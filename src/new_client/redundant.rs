//! Multiplexing requests over redundant transports.
//!
//! This module offers a client-side transport for adding redundancy to a DNS
//! query pipeline.  A [`RedundantClient`] can be created and multiple
//! equivalent transports can be added to it.  Requests routed through the
//! [`RedundantClient`] will first be sent to the fastest transport, then to
//! the second-fastest, etc.  Statistics about the response time for each
//! transport are collected and used to estimate the average and an upper
//! bound; [`RedundantClient`] uses this to decide how long to wait before
//! trying each next transport.

use core::time::Duration;
use std::{boxed::Box, sync::Arc, vec::Vec};

use futures_util::{stream::FuturesUnordered, StreamExt};
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use tokio::time::{timeout_at, Instant};

use crate::new_base::name::UnparsedName;
use crate::new_base::parse::SplitMessageBytes;
use crate::new_base::{Message, Question, RType, Record, UnparsedRecordData};

use super::{BoxClient, Client, ClientError};

#[derive(Clone, Debug, Default)]
pub struct RedundantConfig {
    /// Defer transport errors.
    pub defer_transport_error: bool,

    /// Defer replies that report Refused.
    pub defer_refused: bool,

    /// Defer replies that report ServFail.
    pub defer_servfail: bool,
}

/// A client containing multiple sub-clients it will query.
///
/// The fastest connection will generally be used by this transport.
///
/// The clients to put into this client should generally be long-lived. For
/// example, adding a single TCP client might not be good idea, because that
/// connection might get closed. A multi TCP client is therefore a better
/// fit.
#[derive(Default)]
pub struct RedundantClient {
    config: RedundantConfig,
    clients: RwLock<Vec<Arc<SubClient>>>,
}

impl RedundantClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_config(config: RedundantConfig) -> Self {
        Self {
            config,
            clients: Default::default(),
        }
    }

    pub fn add_client(&self, client: impl BoxClient + 'static) {
        let subclient = Arc::new(SubClient {
            inner: Box::new(client),
            stats: Default::default(),
        });
        self.clients.write().push(subclient)
    }

    fn sort_clients(&self) -> Vec<RequestClient> {
        let mut clients: Vec<RequestClient> =
            self.clients.read().iter().map(RequestClient::new).collect();

        // Occasionally probe a random transport.
        let mut rng = rand::thread_rng();
        if clients.len() > 1 && rng.gen_bool(0.05) {
            let swap_idx = rng.gen_range(0..clients.len());
            clients.swap(0, swap_idx);
            clients[1..].sort_unstable_by_key(|c| c.timeout);
            clients[0].timeout = clients[0].timeout.min(clients[1].timeout);
        } else {
            // Sort the client by lowest timeout; we will query in this order.
            clients.sort_unstable_by_key(|c| c.timeout);
        }

        clients
    }

    /// Determine whether a successful response should be skipped.
    ///
    /// We skip a response if the `RCODE` is `SERVFAIL` or `REFUSED`
    fn skip(&self, msg: &Message) -> bool {
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

impl Client for RedundantClient {
    async fn request(
        &self,
        message: &Message,
    ) -> Result<Box<Message>, ClientError> {
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
                    let res: Result<Box<Message>, _> = res;
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

struct SubClient {
    inner: Box<dyn BoxClient>,
    stats: Mutex<SubClientStats>,
}

impl SubClient {
    async fn request(
        self: Arc<Self>,
        request: &Message,
    ) -> Result<Box<Message>, ClientError> {
        /// A drop guard for collecting statistics.
        struct Guard<'a> {
            /// Whether the request actually finished.
            finished: bool,

            /// When the request started.
            start_time: Instant,

            /// The transport statistics.
            stats: &'a Mutex<SubClientStats>,
        }

        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                let elapsed = self.start_time.elapsed();
                let mut stats = self.stats.lock();

                // Update on completion, or if the request took too long.
                if self.finished || elapsed.as_secs_f64() > stats.mean {
                    stats.account(elapsed);
                }
            }
        }

        // Collect statistics even if the future is canceled.
        let mut guard = Guard {
            finished: false,
            start_time: Instant::now(),
            stats: &self.stats,
        };

        // Perform the actual request.
        let result = self.inner.dyn_request(request).await;

        // Inform the drop guard that the request completed.
        guard.finished = true;

        result
    }
}

/// Statistics about a transport.
#[derive(Clone, Debug)]
struct SubClientStats {
    /// The average response time in the window.
    ///
    /// If this is NaN, the window was empty.
    mean: f64,

    /// The average of the square of the response time in the window.
    ///
    /// If this is NaN, the window was empty.
    mean_sq: f64,

    /// A computed timeout for requests to the transport.
    ///
    /// This value is three standard deviations past the mean.  Assuming the
    /// transport request times follow a normal distribution, there is a 99.7%
    /// chance a random transport request will fit within this timeout.
    timeout: Duration,
}

impl Default for SubClientStats {
    fn default() -> Self {
        Self {
            mean: f64::NAN,
            mean_sq: f64::NAN,
            timeout: Duration::from_millis(300),
        }
    }
}

impl SubClientStats {
    /// Account for the given response time.
    fn account(&mut self, rt: Duration) {
        let rt = rt.as_secs_f64();

        if self.mean.is_nan() {
            // This is the first response time -- overwrite the averages.
            self.mean = rt;
            self.mean_sq = rt * rt;
        } else {
            // Adjust the averages by 1/8th.
            //
            // After 8 iterations of the same response time, the previous
            // average has a weight of about 34%.  After 8 more iterations,
            // its weight is about 12%.
            self.mean = (rt + 7. * self.mean) / 8.;
            self.mean_sq = (rt * rt + 7. * self.mean_sq) / 8.;
        }

        // Compute the variance and standard deviation.
        let variance = self.mean_sq - self.mean * self.mean;
        let std_dev = variance.max(0.).sqrt();

        // Determine the appropriate timeout value.
        self.timeout = Duration::from_secs_f64(self.mean + 3. * std_dev);
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
