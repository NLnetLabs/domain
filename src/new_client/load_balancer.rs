use core::time::Duration;
use std::{boxed::Box, sync::Arc, vec::Vec};

use futures_util::{stream::FuturesUnordered, StreamExt};
use parking_lot::RwLock;
use tokio::time::{timeout_at, Instant};

use crate::new_base::Message;

use super::{BoxClient, Client, ClientError};

#[derive(Clone, Debug)]
pub struct LoadBalancerConfig {
    /// Defer transport errors.
    pub defer_transport_error: bool,

    /// Defer replies that report Refused.
    pub defer_refused: bool,

    /// Defer replies that report ServFail.
    pub defer_servfail: bool,

    /// Cut-off for slow upstreams as a factor of the fastest upstream.
    pub slow_rt_factor: f64,
}

impl Default for LoadBalancerConfig {
    fn default() -> Self {
        Self {
            defer_transport_error: false,
            defer_refused: false,
            defer_servfail: false,
            slow_rt_factor: 5.0,
        }
    }
}

/// Configuration variables for each upstream.
#[derive(Clone, Copy, Debug, Default)]
pub struct SubClientConfig {
    /// Maximum burst of upstream queries.
    max_burst: Option<u64>,

    /// Interval over which the burst is counted.
    burst_interval: Duration,
}

pub struct SubClient {
    config: SubClientConfig,
    client: Box<dyn BoxClient>,
    stats: Mutex<SubClientStats>,
}

pub struct LoadBalancerClient {
    config: LoadBalancerConfig,
    clients: RwLock<Vec<Arc<SubClient>>>,
}

impl<C: BoxClient + 'static> From<C> for SubClient {
    fn from(value: C) -> Self {
        SubClient {
            config: Default::default(),
            client: Box::new(value),
        }
    }
}

impl LoadBalancerClient {
    pub fn new() -> Self {
        Self::with_config(Default::default())
    }

    pub fn with_config(config: LoadBalancerConfig) -> Self {
        Self {
            config,
            clients: Default::default(),
        }
    }

    pub fn add_client(&mut self, client: impl BoxClient) {
        self.add_client_with_config(client, Default::default())
    }

    pub fn add_client_with_config(
        &mut self,
        client: impl BoxClient,
        config: SubClientConfig,
    ) {
        self.clients.push(client.into());
    }

    fn sort_clients(&self) -> Vec<RequestClient> {
        let mut clients: Vec<RequestClient> = self
            .clients
            .read()
            .iter()
            .cloned()
            .map(Into::into)
            .collect();

        todo!()
    }

    /// Determine whether a successful response should be skipped.
    ///
    /// We skip a response if the `RCODE` is `SERVFAIL` or `REFUSED`
    fn skip(&self, msg: &Vec<u8>) -> bool {
        let Ok(msg) = Message::parse_bytes_by_ref(msg) else {
            return false;
        };

        // We match on SERVFAIL and REFUSED. If the normal rcode matches that
        // we have to ensure that the extended rcode is 0.
        match msg.header.flags.rcode() {
            2 /* SERVFAIL */ if self.config.defer_servfail => {
                matches!(find_opt_rcode(msg), Some(0) | None)
            }
            5 /* REFUSED */ if self.config.defer_refused => {
                matches!(find_opt_rcode(msg), Some(0) | None)
            }
            _ => false
        }
    }
}

impl Client for LoadBalancerClient {
    async fn request(
        &self,
        request: &Message,
    ) -> Result<Vec<u8>, ClientError> {
        // This will be our view of the clients for this request.
        // We sort them based on their timeout and iterate over them in that
        // order.
        let clients = self.sort_clients();
        if clients.is_empty() {
            return Err(ClientError::NoTransportAvailable);
        }
        let mut clients = clients.into_iter();

        let mut futs = FuturesUnordered::new();

        // The time at which the next request should be sent out.
        let mut next_request_time = Instant::now();

        // This will hold the result of requests that fail or that we skip,
        // so we can return them later when the subsequent requests also
        // fail.
        let mut deferred_result = None;

        loop {
            match timeout_at(next_request_time, futs.next()).await {
                Ok(Some(res)) => {
                    // got some response, so we decide whether to return it,
                    // store it into the deferred_result or discard it.
                    match res {
                        Ok(msg) if self.skip(&msg) => {
                            if let Some(Err(_)) | None = deferred_result {
                                deferred_result = Some(Ok(msg));
                            }
                        }
                        Err(err) if self.config.defer_transport_error => {
                            if deferred_result.is_none() {
                                deferred_result = Some(Err(err));
                            }
                        }
                        // It's not one of the cases we defer or skip, so we
                        // return it!
                        result => {
                            return result;
                        }
                    }
                }
                // On a timeout or empty set of futures we start a new
                // request.
                //
                // An empty set of futures happens in two cases:
                //  1. We haven't send out any requests yet
                //  2. All sent requests have been resolved, which means
                //     we can send more requests immediately.
                Ok(None) | Err(_) => {
                    if let Some(RequestClient { client, timeout }) =
                        clients.next()
                    {
                        futs.push(client.request(message));
                        next_request_time = Instant::now() + timeout;
                    } else {
                        return deferred_result
                            .unwrap_or(Err(ClientError::Bug));
                    }
                }
            }
        }
    }
}

struct RequestClient {
    client: Arc<SubClient>,
    timeout: Duration,
}

impl RequestClient {
    fn new(client: &Arc<SubClient>) -> Self {
        let timeout = client.stats.lock().timeout;
        RequestClient {
            timeout,
            client: client.clone(),
        }
    }
}

/// Find the extended RCODE in the message.
///
/// Note that the returned `u8` only contains the upper 8 bits of the
/// `RCODE`, i.e. the part stored in the `OPT` record.
///
/// `None` is returned on parse errors.
///
/// We have to write this here because new_base is lacking some proper
/// handling of the (extended) `RCODE`.
fn find_opt_rcode(msg: &Message) -> Option<u8> {
    let counts = msg.header.counts;

    let mut offset = 0;
    for _ in 0..counts.questions.get() {
        let (_, rest) = Question::<&UnparsedName>::split_message_bytes(
            &msg.contents,
            offset,
        )
        .ok()?;
        offset = rest;
    }

    for _ in 0..counts.answers.get() {
        let (_, rest) = Record::<&UnparsedName, &UnparsedRecordData>::split_message_bytes(
                &msg.contents,
                offset,
            ).ok()?;
        offset = rest;
    }

    for _ in 0..counts.authorities.get() {
        let (_, rest) = Record::<&UnparsedName, &UnparsedRecordData>::split_message_bytes(
                &msg.contents,
                offset,
            ).ok()?;
        offset = rest;
    }

    for _ in 0..counts.additional.get() {
        let (r, rest) =
                Record::<&UnparsedName, &UnparsedRecordData>::split_message_bytes(
                    &msg.contents,
                    offset,
                )
                .ok()?;

        if let RType::OPT = r.rtype {
            // The extension of the rcode is specified as the first 8 bits
            // of the TTL field in RFC 6891.
            let ttl_bytes: [u8; 4] = r.ttl.value.get().to_be_bytes();
            return Some(ttl_bytes[0]);
        }

        offset = rest;
    }

    None
}
