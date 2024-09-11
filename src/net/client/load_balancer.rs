//! A transport that tries to distribute requests over multiple upstreams.
//! It assumed that the upstreams have similar performance. use the [redundant]
//! transport to forward requests to the best upstream out of upstreams
//! that may have different quite performance.

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
use std::vec::Vec;

use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, Duration, Instant};

use crate::base::iana::OptRcode;
use crate::base::Message;
use crate::net::client::request::{Error, GetResponse, SendRequest};

/*
Basic algorithm:
- keep track of expected response time for every upstream
- start with the upstream with the lowest expected response time
- set a timer to the expect response time.
- if the timer expires before reply arrives, send the query to the next lowest
  and set a timer
- when a reply arrives update the expected response time for the relevant
  upstream and for the ones that failed.

Based on a random number generator:
- pick a different upstream rather then the best but set the timer to the
  expected response time of the best.
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

/// Avoid sending two requests at the same time.
///
/// When a worse connection is probed, give it a slight head start.
const PROBE_RT: Duration = Duration::from_millis(1);

//------------ Config ---------------------------------------------------------

/// User configuration variables.
#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    /// Defer transport errors.
    pub defer_transport_error: bool,

    /// Defer replies that report Refused.
    pub defer_refused: bool,

    /// Defer replies that report ServFail.
    pub defer_servfail: bool,
}

//------------ ConnConfig -----------------------------------------------------

/// Configuration variables for each upstream.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnConfig {
    pub qps: Option<f64>
}

impl ConnConfig {
    pub fn new() -> Self {
	Self { qps: None }
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
	_label: &str,
	_config: ConnConfig,
        conn: Box<dyn SendRequest<Req> + Send + Sync>,
    ) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(ChanReq::Add(AddReq { conn, tx }))
            .await
            .expect("send should not fail");
        rx.await.expect("receive should not fail")
    }

    /// Implementation of the query method.
    async fn request_impl(
        self,
        request_msg: Req,
    ) -> Result<Message<Bytes>, Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(ChanReq::GetRT(RTReq { tx }))
            .await
            .expect("send should not fail");
        let conn_rt = rx.await.expect("receive should not fail")?;
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

impl<Req: Clone + Debug + Send + Sync + 'static> SendRequest<Req>
    for Connection<Req>
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
pub struct Request {
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
pub struct Query<Req>
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
type RequestReply = Result<Box<dyn GetResponse + Send + Sync>, Error>;

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
    /// Aproximation of the windowed average of response times.
    mean: f64,

    /// Aproximation of the windowed average of the square of response times.
    mean_sq: f64,
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
        conn_rt.sort_unstable_by(conn_rt_cmp);

        // Do we want to probe a less performant upstream?
        if conn_rt_len > 1 && random::<f64>() < PROBE_P {
            let index: usize = 1 + random::<usize>() % (conn_rt_len - 1);
            conn_rt[index].est_rt = PROBE_RT;

            // Sort again
            conn_rt.sort_unstable_by(conn_rt_cmp);
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
                    conn_stats.push(ConnStats {
                        mean: (DEFAULT_RT_MS as f64) / 1000.,
                        mean_sq: 0.,
                    });
                    conn_rt.push(ConnRT {
                        id,
                        est_rt: DEFAULT_RT,
                        start: None,
                    });
                    conns.push(add_req.conn);

                    // Don't care if send fails
                    let _ = add_req.tx.send(Ok(()));
                }
                ChanReq::GetRT(rt_req) => {
                    // Don't care if send fails
                    let _ = rt_req.tx.send(Ok(conn_rt.clone()));
                }
                ChanReq::Query(request_req) => {
                    let opt_ind =
                        conn_rt.iter().position(|e| e.id == request_req.id);
                    match opt_ind {
                        Some(ind) => {
                            let query = conns[ind]
                                .send_request(request_req.request_msg);
                            // Don't care if send fails
                            let _ = request_req.tx.send(Ok(query));
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
            }
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
    let mut request = match rx.await.expect("receive is expected to work") {
        Err(err) => return (index, Err(err)),
        Ok(request) => request,
    };
    let reply = request.get_response().await;

    (index, reply)
}

/// Compare ConnRT elements based on estimated response time.
fn conn_rt_cmp(e1: &ConnRT, e2: &ConnRT) -> Ordering {
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
