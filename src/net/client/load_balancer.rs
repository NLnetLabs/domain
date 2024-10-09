//! A transport that tries to distribute requests over multiple upstreams.
//!
//! It is assumed that the upstreams have similar performance. use the
//! [super::redundant] transport to forward requests to the best upstream out of
//! upstreams that may have quite different performance.
//!
//! Basic mode of operation
//!
//! Associated with every upstream configured is optionally a burst length
//! and burst interval. Burst length deviced by burst interval gives a
//! queries per second (QPS) value. This be use to limit the rate and
//! especially the bursts that reach upstream servers. Once the burst
//! length has been reach, the upstream receives no new requests until
//! the burst interval has completed.
//!
//! For each upstream the object maintains an estimated response time.
//! with the configuration value slow_rt_factor, the group of upstream
//! that have not exceeded their burst length are divided into a 'fast'
//! and a 'slow' group. The slow group are those upstream that have an
//! estimated response time that is higher than slow_rt_factor times the
//! lowest estimated response time. Slow upstream are considered only when
//! all fast upstream failed to provide a suitable response.
//!
//! Within the group of fast upstreams, the ones with the lower queue
//! length are preferred. This tries to give each of the fast upstreams
//! an equal number of outstanding requests.
//!
//! Within a group of fast upstreams with the same queue length, the
//! one with the lowest estimated response time is preferred.
//!
//! Probing
//!
//! Upstream with high estimated response times may be get any traffic and
//! therefore the estimated response time may remain high. Probing is
//! intended to solve that problem. Using a random number generator,
//! occasionally an upstream is selected for probing. If the selected
//! upstream currently has a non-zero queue then probing is not needed and
//! no probe will happen.
//! Otherwise, the upstream to be probed is selected first with an
//! estimated response time equal to the lowest one. If the probed upstream
//! does not provide a response within that time, the otherwise best upstream
//! also gets the request. If the probes upstream provides a suitable response
//! before the next upstream then its estimated will be updated.

use crate::base::iana::OptRcode;
use crate::base::iana::Rcode;
use crate::base::opt::AllOptData;
use crate::base::Message;
use crate::base::MessageBuilder;
use crate::base::StaticCompressor;
use crate::dep::octseq::OctetsInto;
use crate::net::client::request::ComposeRequest;
use crate::net::client::request::{Error, GetResponse, SendRequest};
use crate::utils::config::DefMinMax;
use bytes::Bytes;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use octseq::Octets;
use rand::random;
use std::boxed::Box;
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::string::String;
use std::string::ToString;
use std::sync::Arc;
use std::vec::Vec;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, Duration, Instant};

/*
Basic algorithm:
- try to distribute requests over all upstreams subject to some limitations.
- limit bursts
  - record the start of a burst interval when a request goes out over an
    upstream
  - record the number of requests since the start of the burst interval
  - in the burst is larger than the maximum configured by the user then the
    upstream is no longer available.
  - start a new burst interval when enough time has passed.
- prefer fast upstreams over slow upstreams
  - maintain a response time estimate for each upstream
  - upstreams with an estimate response time larger than slow_rt_factor
    times the lowest estimated response time are consider slow.
  - 'fast' upstreams are preferred over slow upstream. However slow upstreams
    are considered if during a single request all fast upstreams fail.
- prefer fast upstream with a low queue length
  - maintain a counter with the number of current outstanding requests on an
    upstream.
  - prefer the upstream with the lowest count.
  - preset the upstream with the lowest estimated response time in case
    two or more upstreams have the same count.

Execution:
- set a timer to the expect response time.
- if the timer expires before reply arrives, send the query to the next lowest
  and set a timer
- when a reply arrives update the expected response time for the relevant
  upstream and for the ones that failed.

Probing:
- upstream that currently have outstanding requests do not need to be
  probed.
- for idle upstream, based on a random number generator:
  - pick a different upstream rather then the best
  - but set the timer to the expected response time of the best.
  - maybe we need a configuration parameter for the amound of head start
    given to the probed upstream.
*/

/// Capacity of the channel that transports [ChanReq].
const DEF_CHAN_CAP: usize = 8;

/// Time in milliseconds for the initial response time estimate.
const DEFAULT_RT_MS: u64 = 300;

/// The initial response time estimate for unused connections.
const DEFAULT_RT: Duration = Duration::from_millis(DEFAULT_RT_MS);

/// Maintain a moving average for the measured response time and the
/// square of that. The window is SMOOTH_N.
const SMOOTH_N: f64 = 8.;

/// Chance to probe a worse connection.
const PROBE_P: f64 = 0.05;

//------------ Configuration Constants ----------------------------------------

/// Cut off for slow upstreams.
const DEF_SLOW_RT_FACTOR: f64 = 5.0;
const MIN_SLOW_RT_FACTOR: f64 = 1.0;

/// Interval for limiting upstream query bursts.
const BURST_INTERVAL: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(1),
    Duration::from_millis(1),
    Duration::from_secs(3600),
);

//------------ Config ---------------------------------------------------------

/// User configuration variables.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Defer transport errors.
    defer_transport_error: bool,

    /// Defer replies that report Refused.
    defer_refused: bool,

    /// Defer replies that report ServFail.
    defer_servfail: bool,

    /// Cut-off for slow upstreams as a factor of the fastest upstream.
    slow_rt_factor: f64,
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

    /// Set the value of the slow_rt_factor configuration variable.
    pub fn slow_rt_factor(&self) -> f64 {
        self.slow_rt_factor
    }

    /// Set the value of the slow_rt_factor configuration variable.
    pub fn set_slow_rt_factor(&mut self, mut value: f64) {
        if value < MIN_SLOW_RT_FACTOR {
            value = MIN_SLOW_RT_FACTOR
        };
        self.slow_rt_factor = value;
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            defer_transport_error: Default::default(),
            defer_refused: Default::default(),
            defer_servfail: Default::default(),
            slow_rt_factor: DEF_SLOW_RT_FACTOR,
        }
    }
}

//------------ ConnConfig -----------------------------------------------------

/// Configuration variables for each upstream.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnConfig {
    /// Maximum burst of upstream queries.
    max_burst: Option<u64>,

    /// Interval over which the burst is counted.
    burst_interval: Duration,
}

impl ConnConfig {
    /// Create a new ConnConfig object.
    pub fn new() -> Self {
        Self {
            max_burst: None,
            burst_interval: BURST_INTERVAL.default(),
        }
    }

    /// Return the current configuration value for the maximum burst.
    /// None means that there is no limit.
    pub fn max_burst(&mut self) -> Option<u64> {
        self.max_burst
    }

    /// Set the configuration value for the maximum burst.
    /// The value None means no limit.
    pub fn set_max_burst(&mut self, mut max_burst: Option<u64>) {
        if let Some(burst) = max_burst {
            if burst == 0 {
                max_burst = Some(1);
            }
        }
        self.max_burst = max_burst;
    }

    /// Return the current burst interval.
    pub fn burst_interval(&mut self) -> Duration {
        self.burst_interval
    }

    /// Set a new burst interval.
    /// The interval is silently limited to at least 1 millesecond and
    /// at most 1 hour.
    pub fn set_burst_interval(&mut self, burst_interval: Duration) {
        self.burst_interval = BURST_INTERVAL.limit(burst_interval);
    }
}

//------------ Connection -----------------------------------------------------

/// This type represents a transport connection.
#[derive(Debug)]
pub struct Connection<Req>
where
    Req: Send + Sync,
{
    /// User configuation.
    config: Config,

    /// To send a request to the runner.
    sender: mpsc::Sender<ChanReq<Req>>,
}

impl<Req: Clone + Debug + Send + Sync + 'static> Connection<Req> {
    /// Create a new connection.
    pub fn new() -> (Self, Transport<Req>) {
        Self::with_config(Default::default())
    }

    /// Create a new connection with a given config.
    pub fn with_config(config: Config) -> (Self, Transport<Req>) {
        let (sender, receiver) = mpsc::channel(DEF_CHAN_CAP);
        (Self { config, sender }, Transport::new(receiver))
    }

    /// Add a transport connection.
    pub async fn add(
        &self,
        label: &str,
        config: &ConnConfig,
        conn: Box<dyn SendRequest<Req> + Send + Sync>,
    ) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(ChanReq::Add(AddReq {
                label: label.to_string(),
                max_burst: config.max_burst,
                burst_interval: config.burst_interval,
                conn,
                tx,
            }))
            .await
            .expect("send should not fail");
        rx.await.expect("receive should not fail")
    }

    /// Print statistics.
    pub async fn print_stats(&self) {
        self.sender.send(ChanReq::PrintStats).await.unwrap();
    }

    /// Implementation of the query method.
    async fn request_impl(
        self,
        request_msg: Req,
    ) -> Result<Message<Bytes>, Error>
    where
        Req: ComposeRequest,
    {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(ChanReq::GetRT(RTReq { tx }))
            .await
            .expect("send should not fail");
        let conn_rt = rx.await.expect("receive should not fail")?;
        if conn_rt.is_empty() {
            return serve_fail(&request_msg.to_message().unwrap());
        }
        Query::new(self.config, request_msg, conn_rt, self.sender.clone())
            .get_response()
            .await
    }
}

impl<Req> Clone for Connection<Req>
where
    Req: Send + Sync,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config,
            sender: self.sender.clone(),
        }
    }
}

impl<Req: Clone + ComposeRequest + Debug + Send + Sync + 'static>
    SendRequest<Req> for Connection<Req>
{
    fn send_request(
        &self,
        request_msg: Req,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(Request {
            fut: Box::pin(self.clone().request_impl(request_msg)),
        })
    }
}

//------------ Request -------------------------------------------------------

/// An active request.
struct Request {
    /// The underlying future.
    fut: Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + Sync>,
    >,
}

impl Request {
    /// Async function that waits for the future stored in Query to complete.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        (&mut self.fut).await
    }
}

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
        Box::pin(self.get_response_impl())
    }
}

impl Debug for Request {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("fut", &format_args!("_"))
            .finish()
    }
}

//------------ Query --------------------------------------------------------

/// This type represents an active query request.
#[derive(Debug)]
struct Query<Req>
where
    Req: Send + Sync,
{
    /// User configuration.
    config: Config,

    /// The state of the query
    state: QueryState,

    /// The request message
    request_msg: Req,

    /// List of connections identifiers and estimated response times.
    conn_rt: Vec<ConnRT>,

    /// Channel to send requests to the run function.
    sender: mpsc::Sender<ChanReq<Req>>,

    /// List of futures for outstanding requests.
    fut_list: FuturesUnordered<
        Pin<Box<dyn Future<Output = FutListOutput> + Send + Sync>>,
    >,

    /// Transport error that should be reported if nothing better shows
    /// up.
    deferred_transport_error: Option<Error>,

    /// Reply that should be returned to the user if nothing better shows
    /// up.
    deferred_reply: Option<Message<Bytes>>,

    /// The result from one of the connectons.
    result: Option<Result<Message<Bytes>, Error>>,

    /// Index of the connection that returned a result.
    res_index: usize,
}

/// The various states a query can be in.
#[derive(Debug)]
enum QueryState {
    /// The initial state
    Init,

    /// Start a request on a specific connection.
    Probe(usize),

    /// Report the response time for a specific index in the list.
    Report(usize),

    /// Wait for one of the requests to finish.
    Wait,
}

/// The commands that can be sent to the run function.
enum ChanReq<Req>
where
    Req: Send + Sync,
{
    /// Add a connection
    Add(AddReq<Req>),

    /// Get the list of estimated response times for all connections
    GetRT(RTReq),

    /// Start a query
    Query(RequestReq<Req>),

    /// Report how long it took to get a response
    Report(TimeReport),

    /// Report that a connection failed to provide a timely response
    Failure(TimeReport),

    /// Print statistics.
    PrintStats,
}

impl<Req> Debug for ChanReq<Req>
where
    Req: Send + Sync,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("ChanReq").finish()
    }
}

/// Request to add a new connection
struct AddReq<Req> {
    /// Name of new connection
    label: String,

    /// Maximum length of a burst.
    max_burst: Option<u64>,

    /// Interval over which bursts are counted.
    burst_interval: Duration,

    /// New connection to add
    conn: Box<dyn SendRequest<Req> + Send + Sync>,

    /// Channel to send the reply to
    tx: oneshot::Sender<AddReply>,
}

/// Reply to an Add request
type AddReply = Result<(), Error>;

/// Request to give the estimated response times for all connections
struct RTReq /*<Octs>*/ {
    /// Channel to send the reply to
    tx: oneshot::Sender<RTReply>,
}

/// Reply to a RT request
type RTReply = Result<Vec<ConnRT>, Error>;

/// Request to start a request
struct RequestReq<Req>
where
    Req: Send + Sync,
{
    /// Identifier of connection
    id: u64,

    /// Request message
    request_msg: Req,

    /// Channel to send the reply to
    tx: oneshot::Sender<RequestReply>,
}

impl<Req: Debug> Debug for RequestReq<Req>
where
    Req: Send + Sync,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("RequestReq")
            .field("id", &self.id)
            .field("request_msg", &self.request_msg)
            .finish()
    }
}

/// Reply to a request request.
type RequestReply =
    Result<(Box<dyn GetResponse + Send + Sync>, Arc<()>), Error>;

/// Report the amount of time until success or failure.
#[derive(Debug)]
struct TimeReport {
    /// Identifier of the transport connection.
    id: u64,

    /// Time spend waiting for a reply.
    elapsed: Duration,
}

/// Connection statistics to compute the estimated response time.
struct ConnStats {
    /// Name of the connection.
    label: String,

    /// Aproximation of the windowed average of response times.
    mean: f64,

    /// Aproximation of the windowed average of the square of response times.
    mean_sq: f64,

    /// Maximum upstream query burst.
    max_burst: Option<u64>,

    /// burst length,
    burst_interval: Duration,

    /// Start of the current burst
    burst_start: Instant,

    /// Number of queries since the start of the burst.
    burst: u64,

    /// Use the number of references to an Arc as queue length. The number
    /// of references is one higher than then actual queue length.
    queue_length_plus_one: Arc<()>,
}

/// Data required to schedule requests and report timing results.
#[derive(Clone, Debug)]
struct ConnRT {
    /// Estimated response time.
    est_rt: Duration,

    /// Identifier of the connection.
    id: u64,

    /// Start of a request using this connection.
    start: Option<Instant>,

    /// Use the number of references to an Arc as queue length. The number
    /// of references is one higher than then actual queue length.
    queue_length: usize,
}

/// Result of the futures in fut_list.
type FutListOutput = (usize, Result<Message<Bytes>, Error>);

impl<Req: Clone + Send + Sync + 'static> Query<Req> {
    /// Create a new query object.
    fn new(
        config: Config,
        request_msg: Req,
        mut conn_rt: Vec<ConnRT>,
        sender: mpsc::Sender<ChanReq<Req>>,
    ) -> Self {
        let conn_rt_len = conn_rt.len();
        let min_rt = conn_rt.iter().map(|e| e.est_rt).min().unwrap();
        println!("min_rt = {min_rt:?}");
        let slow_rt = min_rt.as_secs_f64() * config.slow_rt_factor;
        conn_rt.sort_unstable_by(|e1, e2| conn_rt_cmp(e1, e2, slow_rt));

        // Do we want to probe a less performant upstream? We only need to
        // probe upstreams with a queue length of zero. If the queue length
        // is non-zero then the upstream recently got work and does not need
        // to be probed.
        if conn_rt_len > 1 && random::<f64>() < PROBE_P {
            let index: usize = 1 + random::<usize>() % (conn_rt_len - 1);

            println!(
                "probing: index {index}, Arc count {}",
                conn_rt[index].queue_length
            );

            //if Arc::strong_count(&conn_rt[index].queue_length_plus_one) - 1
            if conn_rt[index].queue_length == 0 {
                // Give the probe some head start. We may need a separate
                // configuration parameter. A multiple of min_rt. Just use
                // min_rt for now.
                let mut e = conn_rt.remove(index);
                e.est_rt = min_rt;
                conn_rt.insert(0, e);
            }
        }

        println!("Query::new after sort:");
        for e in &conn_rt {
            println!("{:?}", e);
        }

        Self {
            config,
            request_msg,
            conn_rt,
            sender,
            state: QueryState::Init,
            fut_list: FuturesUnordered::new(),
            deferred_transport_error: None,
            deferred_reply: None,
            result: None,
            res_index: 0,
        }
    }

    /// Implementation of get_response.
    async fn get_response(&mut self) -> Result<Message<Bytes>, Error> {
        loop {
            match self.state {
                QueryState::Init => {
                    if self.conn_rt.is_empty() {
                        return Err(Error::NoTransportAvailable);
                    }
                    self.state = QueryState::Probe(0);
                    continue;
                }
                QueryState::Probe(ind) => {
                    self.conn_rt[ind].start = Some(Instant::now());
                    let fut = start_request(
                        ind,
                        self.conn_rt[ind].id,
                        self.sender.clone(),
                        self.request_msg.clone(),
                    );
                    self.fut_list.push(Box::pin(fut));
                    let timeout = Instant::now() + self.conn_rt[ind].est_rt;
                    loop {
                        tokio::select! {
                            res = self.fut_list.next() => {
                                let res = res.expect("res should not be empty");
                                match res.1 {
                                    Err(ref err) => {
                                        if self.config.defer_transport_error {
                                            if self.deferred_transport_error.is_none() {
                                                self.deferred_transport_error = Some(err.clone());
                                            }
                                            if res.0 == ind {
                                                // The current upstream finished,
                                                // try the next one, if any.
                                                self.state =
                                                if ind+1 < self.conn_rt.len() {
                                                    QueryState::Probe(ind+1)
                                                }
                                                else
                                                {
                                                    QueryState::Wait
                                                };
                                                // Break out of receive loop
                                                break;
                                            }
                                            // Just continue receiving
                                            continue;
                                        }
                                        // Return error to the user.
                                    }
                                    Ok(ref msg) => {
                                        if skip(msg, &self.config) {
                                            if self.deferred_reply.is_none() {
                                                self.deferred_reply = Some(msg.clone());
                                            }
                                            if res.0 == ind {
                                                // The current upstream finished,
                                                // try the next one, if any.
                                                self.state =
                                                    if ind+1 < self.conn_rt.len() {
                                                        QueryState::Probe(ind+1)
                                                    }
                                                    else
                                                    {
                                                        QueryState::Wait
                                                    };
                                                // Break out of receive loop
                                                break;
                                            }
                                            // Just continue receiving
                                            continue;
                                        }
                                        // Now we have a reply that can be
                                        // returned to the user.
                                    }
                                }
                                self.result = Some(res.1);
                                self.res_index= res.0;

                                self.state = QueryState::Report(0);
                                // Break out of receive loop
                                break;
                            }
                            _ = sleep_until(timeout) => {
                                // Move to the next Probe state if there
                                // are more upstreams to try, otherwise
                                // move to the Wait state.
                                self.state =
                                if ind+1 < self.conn_rt.len() {
                                    QueryState::Probe(ind+1)
                                }
                                else {
                                    QueryState::Wait
                                };
                                // Break out of receive loop
                                break;
                            }
                        }
                    }
                    // Continue with state machine loop
                    continue;
                }
                QueryState::Report(ind) => {
                    if ind >= self.conn_rt.len()
                        || self.conn_rt[ind].start.is_none()
                    {
                        // Nothing more to report. Return result.
                        let res = self
                            .result
                            .take()
                            .expect("result should not be empty");
                        return res;
                    }

                    let start = self.conn_rt[ind]
                        .start
                        .expect("start time should not be empty");
                    let elapsed = start.elapsed();
                    let time_report = TimeReport {
                        id: self.conn_rt[ind].id,
                        elapsed,
                    };
                    let report = if ind == self.res_index {
                        // Succesfull entry
                        ChanReq::Report(time_report)
                    } else {
                        // Failed entry
                        ChanReq::Failure(time_report)
                    };

                    // Send could fail but we don't care.
                    let _ = self.sender.send(report).await;

                    self.state = QueryState::Report(ind + 1);
                    continue;
                }
                QueryState::Wait => {
                    loop {
                        if self.fut_list.is_empty() {
                            // We have nothing left. There should be a reply or
                            // an error. Prefer a reply over an error.
                            if self.deferred_reply.is_some() {
                                let msg = self
                                    .deferred_reply
                                    .take()
                                    .expect("just checked for Some");
                                return Ok(msg);
                            }
                            if self.deferred_transport_error.is_some() {
                                let err = self
                                    .deferred_transport_error
                                    .take()
                                    .expect("just checked for Some");
                                return Err(err);
                            }
                            panic!("either deferred_reply or deferred_error should be present");
                        }
                        let res = self.fut_list.next().await;
                        let res = res.expect("res should not be empty");
                        match res.1 {
                            Err(ref err) => {
                                if self.config.defer_transport_error {
                                    if self.deferred_transport_error.is_none()
                                    {
                                        self.deferred_transport_error =
                                            Some(err.clone());
                                    }
                                    // Just continue with the next future, or
                                    // finish if fut_list is empty.
                                    continue;
                                }
                                // Return error to the user.
                            }
                            Ok(ref msg) => {
                                if skip(msg, &self.config) {
                                    if self.deferred_reply.is_none() {
                                        self.deferred_reply =
                                            Some(msg.clone());
                                    }
                                    // Just continue with the next future, or
                                    // finish if fut_list is empty.
                                    continue;
                                }
                                // Return reply to user.
                            }
                        }
                        self.result = Some(res.1);
                        self.res_index = res.0;
                        self.state = QueryState::Report(0);
                        // Break out of loop to continue with the state machine
                        break;
                    }
                    continue;
                }
            }
        }
    }
}

//------------ Transport -----------------------------------------------------

/// Type that actually implements the connection.
#[derive(Debug)]
pub struct Transport<Req>
where
    Req: Send + Sync,
{
    /// Receive side of the channel used by the runner.
    receiver: mpsc::Receiver<ChanReq<Req>>,
}

impl<'a, Req: Clone + Send + Sync + 'static> Transport<Req> {
    /// Implementation of the new method.
    fn new(receiver: mpsc::Receiver<ChanReq<Req>>) -> Self {
        Self { receiver }
    }

    /// Run method.
    pub async fn run(mut self) {
        let mut next_id: u64 = 10;
        let mut conn_stats: Vec<ConnStats> = Vec::new();
        let mut conn_rt: Vec<ConnRT> = Vec::new();
        let mut conns: Vec<Box<dyn SendRequest<Req> + Send + Sync>> =
            Vec::new();

        loop {
            let req = match self.receiver.recv().await {
                Some(req) => req,
                None => break, // All references to connection objects are
                               // dropped. Shutdown.
            };
            match req {
                ChanReq::Add(add_req) => {
                    let id = next_id;
                    next_id += 1;
                    let burst_interval = add_req.burst_interval;
                    println!(
                        "burst {:?} {burst_interval:?}",
                        add_req.burst_interval
                    );
                    conn_stats.push(ConnStats {
                        label: add_req.label,
                        mean: (DEFAULT_RT_MS as f64) / 1000.,
                        mean_sq: 0.,
                        max_burst: add_req.max_burst,
                        burst_interval: add_req.burst_interval,
                        burst_start: Instant::now(),
                        burst: 0,
                        queue_length_plus_one: Arc::new(()),
                    });
                    conn_rt.push(ConnRT {
                        id,
                        est_rt: DEFAULT_RT,
                        start: None,
                        queue_length: 42, // To spot errors.
                    });
                    conns.push(add_req.conn);

                    // Don't care if send fails
                    let _ = add_req.tx.send(Ok(()));
                }
                ChanReq::GetRT(rt_req) => {
                    let mut tmp_conn_rt = conn_rt.clone();

                    // Remove entries that exceed the QPS limit. Loop
                    // backward to efficiently remove them.
                    for i in (0..tmp_conn_rt.len()).rev() {
                        // Fill-in current queue length.
                        tmp_conn_rt[i].queue_length = Arc::strong_count(
                            &conn_stats[i].queue_length_plus_one,
                        ) - 1;
                        if let Some(max_burst) = conn_stats[i].max_burst {
                            if conn_stats[i].burst_start.elapsed()
                                > conn_stats[i].burst_interval
                            {
                                conn_stats[i].burst_start = Instant::now();
                                conn_stats[i].burst = 0;
                            }
                            if conn_stats[i].burst > max_burst {
                                println!("qps exceeded for index {i}");
                                tmp_conn_rt.swap_remove(i);
                            }
                        } else {
                            // No limit.
                        }
                    }
                    // Don't care if send fails
                    let _ = rt_req.tx.send(Ok(tmp_conn_rt));
                }
                ChanReq::Query(request_req) => {
                    let opt_ind =
                        conn_rt.iter().position(|e| e.id == request_req.id);
                    match opt_ind {
                        Some(ind) => {
                            // Leave resetting qps_num to GetRT.
                            conn_stats[ind].burst += 1;
                            let query = conns[ind]
                                .send_request(request_req.request_msg);
                            // Don't care if send fails
                            let _ = request_req.tx.send(Ok((
                                query,
                                conn_stats[ind].queue_length_plus_one.clone(),
                            )));
                        }
                        None => {
                            // Don't care if send fails
                            let _ = request_req
                                .tx
                                .send(Err(Error::RedundantTransportNotFound));
                        }
                    }
                }
                ChanReq::Report(time_report) => {
                    let opt_ind =
                        conn_rt.iter().position(|e| e.id == time_report.id);
                    if let Some(ind) = opt_ind {
                        let elapsed = time_report.elapsed.as_secs_f64();
                        conn_stats[ind].mean +=
                            (elapsed - conn_stats[ind].mean) / SMOOTH_N;
                        let elapsed_sq = elapsed * elapsed;
                        conn_stats[ind].mean_sq +=
                            (elapsed_sq - conn_stats[ind].mean_sq) / SMOOTH_N;
                        let mean = conn_stats[ind].mean;
                        let var = conn_stats[ind].mean_sq - mean * mean;
                        let std_dev =
                            if var < 0. { 0. } else { f64::sqrt(var) };
                        let est_rt = mean + 3. * std_dev;
                        conn_rt[ind].est_rt = Duration::from_secs_f64(est_rt);
                    }
                }
                ChanReq::Failure(time_report) => {
                    let opt_ind =
                        conn_rt.iter().position(|e| e.id == time_report.id);
                    if let Some(ind) = opt_ind {
                        let elapsed = time_report.elapsed.as_secs_f64();
                        if elapsed < conn_stats[ind].mean {
                            // Do not update the mean if a
                            // failure took less time than the
                            // current mean.
                            continue;
                        }
                        conn_stats[ind].mean +=
                            (elapsed - conn_stats[ind].mean) / SMOOTH_N;
                        let elapsed_sq = elapsed * elapsed;
                        conn_stats[ind].mean_sq +=
                            (elapsed_sq - conn_stats[ind].mean_sq) / SMOOTH_N;
                        let mean = conn_stats[ind].mean;
                        let var = conn_stats[ind].mean_sq - mean * mean;
                        let std_dev =
                            if var < 0. { 0. } else { f64::sqrt(var) };
                        let est_rt = mean + 3. * std_dev;
                        conn_rt[ind].est_rt = Duration::from_secs_f64(est_rt);
                    }
                }
                ChanReq::PrintStats => {
                    Self::print_stats(&conn_stats, &conn_rt)
                }
            }
        }
    }

    /// Print statistics.
    fn print_stats(conn_stats: &[ConnStats], conn_rt: &[ConnRT]) {
        for i in 0..conn_rt.len() {
            println!("id {} label {} burst {} max burst {:?} Qlen {} Est. RT {:.3}", conn_rt[i].id, conn_stats[i].label, conn_stats[i].burst, conn_stats[i].max_burst, conn_rt[i].queue_length, conn_rt[i].est_rt.as_secs_f64());
        }
    }
}

//------------ Utility --------------------------------------------------------

/// Async function to send a request and wait for the reply.
///
/// This gives a single future that we can put in a list.
async fn start_request<Req>(
    index: usize,
    id: u64,
    sender: mpsc::Sender<ChanReq<Req>>,
    request_msg: Req,
) -> (usize, Result<Message<Bytes>, Error>)
where
    Req: Send + Sync,
{
    let (tx, rx) = oneshot::channel();
    sender
        .send(ChanReq::Query(RequestReq {
            id,
            request_msg,
            tx,
        }))
        .await
        .expect("send is expected to work");
    let (mut request, qlp1) =
        match rx.await.expect("receive is expected to work") {
            Err(err) => return (index, Err(err)),
            Ok((request, qlp1)) => (request, qlp1),
        };
    let reply = request.get_response().await;

    drop(qlp1);
    (index, reply)
}

/// Compare ConnRT elements based on estimated response time.
fn conn_rt_cmp(e1: &ConnRT, e2: &ConnRT, slow_rt: f64) -> Ordering {
    let e1_slow = e1.est_rt.as_secs_f64() > slow_rt;
    let e2_slow = e2.est_rt.as_secs_f64() > slow_rt;
    /*
    println!(
        "{e1_slow:?} and {e2_slow:?} for {e1:?}, {e2:?} and {slow_rt:?}"
    );
    */
    if e1_slow != e2_slow {
        return if e2_slow {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if !e1_slow && !e2_slow {
        // Normal case. First check queue lengths.
        if e1.queue_length != e2.queue_length {
            return if e1.queue_length < e2.queue_length {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }

        // Equal queue length. Just take est_rt.
        return e1.est_rt.cmp(&e2.est_rt);
    }
    // e1_slow == e2_slow
    e1.est_rt.cmp(&e2.est_rt)
}

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

/// Generate a SERVFAIL reply message.
// This needs to be consolodated with the one in validator and the one in
// MessageBuilder.
fn serve_fail<Octs>(msg: &Message<Octs>) -> Result<Message<Bytes>, Error>
where
    Octs: AsRef<[u8]> + Octets,
{
    let mut target =
        MessageBuilder::from_target(StaticCompressor::new(Vec::new()))
            .expect("Vec is expected to have enough space");

    let source = msg;

    *target.header_mut() = msg.header();
    target.header_mut().set_rcode(Rcode::SERVFAIL);
    target.header_mut().set_ad(false);

    let source = source.question();
    let mut target = target.question();
    for rr in source {
        target.push(rr?).expect("should not fail");
    }
    let mut target = target.additional();

    if let Some(opt) = msg.opt() {
        target
            .opt(|ob| {
                ob.set_dnssec_ok(opt.dnssec_ok());
                // XXX something is missing ob.set_rcode(opt.rcode());
                ob.set_udp_payload_size(opt.udp_payload_size());
                ob.set_version(opt.version());
                for o in opt.opt().iter() {
                    let x: AllOptData<_, _> = o.expect("should not fail");
                    ob.push(&x).expect("should not fail");
                }
                Ok(())
            })
            .expect("should not fail");
    }

    let result = target.as_builder().clone();
    let msg = Message::<Bytes>::from_octets(
        result.finish().into_target().octets_into(),
    )
    .expect("Message should be able to parse output from MessageBuilder");
    Ok(msg)
}
