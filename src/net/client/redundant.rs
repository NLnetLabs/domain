//! Multiplexing requests over redundant transports.
//!
//! This module offers a client-side transport for adding redundancy to a DNS
//! query pipeline.  A [`Connection`] can be created and multiple equivalent
//! transports can be added to it.  Requests routed through the [`Connection`]
//! will first be sent to the fastest transport, then to the second-fastest,
//! etc.  Statistics about the response time for each transport are collected
//! and used to estimate the average and an upper bound; [`Connection`] uses
//! this to decide how long to wait before trying each next transport.

use bytes::Bytes;

use futures_util::stream;
use futures_util::{FutureExt, StreamExt};

use octseq::Octets;

use rand::seq::SliceRandom;
use rand::Rng;

use core::future::ready;
use core::mem;
use core::{fmt, pin::pin};
use std::boxed::Box;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;

use parking_lot::{Mutex, RwLock};

use tokio::time::{Duration, Instant};

use crate::base::iana::OptRcode;
use crate::base::Message;
use crate::net::client::request::{Error, GetResponse, SendRequest};

// NOTE:
//
// The implementation estimates the mean and variance of the response time of
// each transport.  For each request, transports are tried from fastest to
// slowest.  Each transport is assigned a timeout; if a response does not
// arrive before the timeout, the next transport in the list is attempted.
// However, the previous request is not canceled; both run concurrently.
//
// The timeout is set to 3 standard deviations greater than the mean.  If the
// response times are normally distributed, this timeout should cover 99.7% of
// cases.
//
// Particularly slow transports may get sidelined, preventing new information
// about them from being learnt.  Occasionally, a randomly chosen transport is
// brought to the front of the list, so it can be tested.

//------------ Config ---------------------------------------------------------

/// User configuration variables.
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    /// Defer transport errors.
    defer_transport_error: bool,

    /// Defer replies that report Refused.
    defer_refused: bool,

    /// Defer replies that report ServFail.
    defer_servfail: bool,
}

impl Config {
    /// Return the value of the defer_transport_error configuration variable.
    pub fn defer_transport_error(&self) -> bool {
        self.defer_transport_error
    }

    /// Set the value of the defer_transport_error configuration variable.
    pub fn set_defer_transport_error(&mut self, value: bool) {
        self.defer_transport_error = value
    }

    /// Return the value of the defer_refused configuration variable.
    pub fn defer_refused(&self) -> bool {
        self.defer_refused
    }

    /// Set the value of the defer_refused configuration variable.
    pub fn set_defer_refused(&mut self, value: bool) {
        self.defer_refused = value
    }

    /// Return the value of the defer_servfail configuration variable.
    pub fn defer_servfail(&self) -> bool {
        self.defer_servfail
    }

    /// Set the value of the defer_servfail configuration variable.
    pub fn set_defer_servfail(&mut self, value: bool) {
        self.defer_servfail = value
    }
}

//------------ Connection ----------------------------------------------------

/// A request multiplexer over redundant transports.
pub struct Connection<Conn> {
    /// Configuration for the transport.
    config: Config,

    /// A set of known transports.
    ///
    /// This is an unordered list.  Transports are occasionally added and
    /// removed, but this is a rare occurrence -- we focus on read speed.
    ///
    /// Within each transport, runtime statistics can be modified without
    /// locking the entire list for mutation.
    transports: RwLock<Vec<Arc<Transport<Conn>>>>,
}

impl<Conn> Connection<Conn> {
    /// Construct a new [`Connection`].
    pub fn new() -> Self {
        Self::with_config(Config::default())
    }

    /// Construct a new [`Connection`] with the given configuration.
    pub fn with_config(config: Config) -> Self {
        Self {
            config,
            transports: RwLock::new(Vec::new()),
        }
    }

    /// Add a new transport.
    pub fn add(&self, transport: Conn) {
        // Prepare the new transport.
        let transport = Arc::new(Transport::new(transport));

        // Add the transport, locking for as little time as possible.
        self.transports.write().push(transport);
    }
}

impl<Conn, Req> SendRequest<Req> for Connection<Conn>
where
    Conn: SendRequest<Req> + Send + Sync + 'static,
    Req: Clone + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: Req,
    ) -> Box<dyn GetResponse + Send + Sync> {
        /// A wrapper type for a multiplexed request.
        struct Request(
            Pin<
                Box<
                    dyn Future<Output = Result<Message<Bytes>, Error>>
                        + Send
                        + Sync,
                >,
            >,
        );

        impl GetResponse for Request {
            fn get_response(
                &mut self,
            ) -> Pin<
                Box<
                    dyn Future<Output = Result<Message<Bytes>, Error>>
                        + Send
                        + Sync
                        + '_,
                >,
            > {
                Box::pin(&mut self.0)
            }
        }

        impl fmt::Debug for Request {
            fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
                f.write_str("redundant::Request")
            }
        }

        let config = self.config;
        let transports = self.prep_transports();
        let future = Self::request(config, transports, request_msg);

        Box::new(Request(Box::pin(future)))
    }
}

impl<Conn> Connection<Conn> {
    /// Multiplex a request through known transports.
    ///
    /// The given list of transports will be queried, in order.  If a request
    /// does not finish within the associated timeout (which should be quite
    /// rare), a request for the next transport is started concurrently.
    async fn request<Req>(
        config: Config,
        transports: Vec<RequestTransport<Conn>>,
        request: Req,
    ) -> Result<Message<Bytes>, Error>
    where
        Conn: SendRequest<Req>,
        Req: Clone + Send + Sync + 'static,
    {
        // Ensure at least one transport is available.
        if transports.is_empty() {
            return Err(Error::NoTransportAvailable);
        }

        // A deferred result.
        let mut deferred_result = None;

        // The total number of transports.
        let num_transports = transports.len();

        let result = stream::iter(transports)
            // For each transport, request from it, then wait out its timeout.
            .scan(Duration::ZERO, |timeout, transport| {
                let request = request.clone();
                let timeout = mem::replace(timeout, transport.timeout);
                tokio::time::sleep(timeout)
                    .map(|()| Some(transport.transport.request(request)))
            })
            // Execute all requests concurrently, as they are produced.
            .buffer_unordered(num_transports)
            // Defer unwanted results in case more useful ones arrive.
            .filter_map(|result| match result {
                Ok(msg) if skip(&msg, &config) => {
                    if deferred_result.as_ref().map_or(true, Result::is_err) {
                        deferred_result = Some(Ok(msg));
                    }
                    ready(None)
                }

                Err(err) if config.defer_transport_error => {
                    if deferred_result.is_none() {
                        deferred_result = Some(Err(err));
                    }
                    ready(None)
                }

                // In all other cases, finish immediately.
                result => ready(Some(result)),
            });

        pin!(result)
            .next()
            .await
            .or(deferred_result)
            .expect("at least one transport finished a request")
    }

    /// Prepare a sorted list of transports to query.
    ///
    /// The live set of transports will be snapshotted and sorted by timeout.
    /// Occasionally, a slower transport may be assigned a low timeout so that
    /// information about it can be updated.
    fn prep_transports(&self) -> Vec<RequestTransport<Conn>> {
        // Take a snapshot of the transport list.
        let mut transports = self
            .transports
            .read()
            .iter()
            .cloned()
            .map(RequestTransport::new)
            .collect::<Vec<_>>();

        // Occasionally the probe slow transports.
        let mut rng = rand::thread_rng();
        if transports.len() > 1 && rng.gen_bool(0.05) {
            // Find the fastest transport.
            let (min_pos, min_timeout) = transports
                .iter()
                .map(|transport| transport.timeout)
                .enumerate()
                .min_by_key(|&(_, timeout)| timeout)
                .expect("there are at least two transports");

            // Randomly pick a slower transport and get it probed first.
            let last_pos = transports.len() - 1;
            transports.swap(min_pos, last_pos);
            transports[..last_pos]
                .choose_mut(&mut rng)
                .expect("there are at least two transports")
                .timeout = min_timeout;
        }

        // Sort the transports by lowest timeout; we will query in this order.
        transports.sort_by_key(|t| t.timeout);

        transports
    }
}

impl<Conn> Default for Connection<Conn> {
    fn default() -> Self {
        Self {
            config: Default::default(),
            transports: Default::default(),
        }
    }
}

impl<Conn> fmt::Debug for Connection<Conn> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("config", &self.config)
            .field("transports", &self.transports)
            .finish()
    }
}

//------------ Transport -----------------------------------------------------

/// A transport known to [`Connection`].
struct Transport<Conn> {
    /// Statistics about this transport.
    ///
    /// This is updated after every request-response using this transport.
    stats: Mutex<TransportStats>,

    /// The underlying transport.
    inner: Conn,
}

impl<Conn> Transport<Conn> {
    /// Construct a new [`Transport`].
    pub fn new(inner: Conn) -> Self {
        Self {
            stats: Default::default(),
            inner,
        }
    }

    /// Query this transport.
    async fn request<Req>(
        self: Arc<Self>,
        request: Req,
    ) -> Result<Message<Bytes>, Error>
    where
        Conn: SendRequest<Req>,
        Req: Clone + Send + Sync + 'static,
    {
        /// A drop guard for collecting statistics.
        struct Guard<'a> {
            /// Whether the request actually finished.
            finished: bool,

            /// When the request started.
            start_time: Instant,

            /// The transport statistics.
            stats: &'a Mutex<TransportStats>,
        }

        impl<'a> Drop for Guard<'a> {
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
        let result = self.inner.send_request(request).get_response().await;

        // Inform the drop guard that the request completed.
        guard.finished = true;

        result
    }
}

impl<Conn> fmt::Debug for Transport<Conn> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transport")
            .field("inner", &format_args!("_"))
            .field("stats", &self.stats)
            .finish()
    }
}

//------------ TransportStats ------------------------------------------------

/// Statistics about a transport.
#[derive(Clone, Debug)]
struct TransportStats {
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
    ///
    /// If this is NaN, the window was empty.
    timeout: Duration,
}

impl TransportStats {
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

impl Default for TransportStats {
    fn default() -> Self {
        Self {
            mean: f64::NAN,
            mean_sq: f64::NAN,
            timeout: Duration::from_millis(300),
        }
    }
}

//------------ RequestTransport ----------------------------------------------

/// A transport within the context of a request.
struct RequestTransport<Req> {
    /// The underlying transport.
    transport: Arc<Transport<Req>>,

    /// The expected timeout for the transport.
    timeout: Duration,
}

impl<Req> RequestTransport<Req> {
    /// Construct a new [`RequestTransport`].
    pub fn new(transport: Arc<Transport<Req>>) -> Self {
        let timeout = transport.stats.lock().timeout;
        Self { transport, timeout }
    }
}

//------------ Utility --------------------------------------------------------

/// Return if this reply should be skipped or not.
fn skip<Octs: Octets>(msg: &Message<Octs>, config: &Config) -> bool {
    // Check if we actually need to check.
    if !config.defer_refused && !config.defer_servfail {
        return false;
    }

    let opt_rcode = msg.opt_rcode();
    // OptRcode needs PartialEq
    if let OptRcode::REFUSED = opt_rcode {
        if config.defer_refused {
            return true;
        }
    }
    if let OptRcode::SERVFAIL = opt_rcode {
        if config.defer_servfail {
            return true;
        }
    }

    false
}
