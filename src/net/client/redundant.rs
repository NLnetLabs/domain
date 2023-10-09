//! A transport that multiplexes requests over multiple redundant transports.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use bytes::Bytes;

use futures::stream::FuturesUnordered;
use futures::StreamExt;

use octseq::OctetsBuilder;

use rand::random;

use std::boxed::Box;
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;

use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{sleep_until, Duration, Instant};

use crate::base::wire::Composer;
use crate::base::Message;
use crate::net::client::error::Error;
use crate::net::client::query::{GetResult, QueryMessage3};

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

/// This type represents a transport connection.
#[derive(Clone)]
pub struct Connection<Octs: Send> {
    /// Reference to the actual implementation of the connection.
    inner: Arc<InnerConnection<Octs>>,
}

impl<'a, Octs: Clone + Composer + Debug + Send + Sync + 'static>
    Connection<Octs>
{
    /// Create a new connection.
    pub fn new() -> io::Result<Connection<Octs>> {
        let connection = InnerConnection::new()?;
        //test_send(connection);
        Ok(Self {
            inner: Arc::new(connection),
        })
    }

    /// Runner function for a connection.
    pub async fn run(&self) {
        self.inner.run().await
    }

    /// Add a transport connection.
    pub async fn add(
        &self,
        conn: Box<dyn QueryMessage3<Octs> + Send + Sync>,
    ) -> Result<(), Error> {
        self.inner.add(conn).await
    }

    /// Implementation of the query function.
    async fn query_impl(
        &self,
        query_msg: &Message<Octs>,
    ) -> Result<Box<dyn GetResult + Send>, Error> {
        let query = self.inner.query(query_msg.clone()).await?;
        Ok(Box::new(query))
    }
}

impl<
        Octs: Clone + Composer + Debug + OctetsBuilder + Send + Sync + 'static,
    > QueryMessage3<Octs> for Connection<Octs>
{
    fn query<'a>(
        &'a self,
        query_msg: &'a Message<Octs>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn GetResult + Send>, Error>>
                + Send
                + '_,
        >,
    > {
        return Box::pin(self.query_impl(query_msg));
    }
}

/// This type represents an active query request.
#[derive(Debug)]
pub struct Query<Octs: AsRef<[u8]> + Send> {
    /// The state of the query
    state: QueryState,

    /// The query message
    query_msg: Message<Octs>,

    /// List of connections identifiers and estimated response times.
    conn_rt: Vec<ConnRT>,

    /// Channel to send requests to the run function.
    sender: mpsc::Sender<ChanReq<Octs>>,

    /// List of futures for outstanding requests.
    fut_list:
        FuturesUnordered<Pin<Box<dyn Future<Output = FutListOutput> + Send>>>,

    /// The result from one of the connectons.
    result: Option<Result<Message<Bytes>, Error>>,

    /// Index of the connection that returned a result.
    res_index: usize,
}

/// Result of the futures in fut_list.
type FutListOutput = Result<(usize, Result<Message<Bytes>, Error>), Error>;

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

impl<Octs: AsRef<[u8]> + Clone + Debug + Send + Sync + 'static> Query<Octs> {
    /// Create a new query object.
    fn new(
        query_msg: Message<Octs>,
        mut conn_rt: Vec<ConnRT>,
        sender: mpsc::Sender<ChanReq<Octs>>,
    ) -> Query<Octs> {
        let conn_rt_len = conn_rt.len();
        println!("before sort:");
        for (i, item) in conn_rt.iter().enumerate().take(conn_rt_len) {
            println!("{}: id {} ert {:?}", i, item.id, item.est_rt);
        }
        conn_rt.sort_unstable_by(conn_rt_cmp);
        println!("after sort:");
        for (i, item) in conn_rt.iter().enumerate().take(conn_rt_len) {
            println!("{}: id {} ert {:?}", i, item.id, item.est_rt);
        }

        // Do we want to probe a less performant upstream?
        if conn_rt_len > 1 && random::<f64>() < PROBE_P {
            let index: usize = 1 + random::<usize>() % (conn_rt_len - 1);
            conn_rt[index].est_rt = PROBE_RT;

            // Sort again
            conn_rt.sort_unstable_by(conn_rt_cmp);
            println!("sort for probe :");
            for (i, item) in conn_rt.iter().enumerate().take(conn_rt_len) {
                println!("{}: id {} ert {:?}", i, item.id, item.est_rt);
            }
        }

        Query {
            query_msg,
            //conns,
            conn_rt,
            sender,
            state: QueryState::Init,
            fut_list: FuturesUnordered::new(),
            result: None,
            res_index: 0,
        }
    }

    /// Implementation of get_result.
    async fn get_result_impl(&mut self) -> Result<Message<Bytes>, Error> {
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
                        self.query_msg.clone(),
                    );
                    self.fut_list.push(Box::pin(fut));
                    println!("timeout {:?}", self.conn_rt[ind].est_rt);
                    let timeout = Instant::now() + self.conn_rt[ind].est_rt;
                    tokio::select! {
                        res = self.fut_list.next() => {
                            println!("got res {:?}", res);
                            let res = res.expect("res should not be empty")?;
                            self.result = Some(res.1);
                            self.res_index= res.0;

                            self.state = QueryState::Report(0);
                            continue;
                        }
                        _ = sleep_until(timeout) => {
                            // Move to the next Probe state if there
                            // are more upstreams to try, otherwise
                            // move to the Wait state.
                            self.state =
                            if ind+1 < self.conn_rt.len() {
                                QueryState::Probe(ind+1)
                            }
                            else
                            {
                                QueryState::Wait
                            };
                            continue;
                        }
                    }
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
                    println!(
                        "expected rt was {:?}",
                        self.conn_rt[ind].est_rt
                    );
                    println!("reporting duration {:?}", elapsed);
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
                    let res = self.fut_list.next().await;
                    println!("got res {:?}", res);
                    let res = res.expect("res should not be empty")?;
                    self.result = Some(res.1);
                    self.res_index = res.0;
                    self.state = QueryState::Report(0);
                    continue;
                }
            }
        }
    }
}

impl<
        Octs: AsMut<[u8]>
            + AsRef<[u8]>
            + Clone
            + Composer
            + Debug
            + OctetsBuilder
            + Send
            + Sync
            + 'static,
    > GetResult for Query<Octs>
{
    fn get_result(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_result_impl())
    }
}

/// Async function to send a request and wait for the reply.
///
/// This gives a single future that we can put in a list.
async fn start_request<Octs: Clone + Debug + Send>(
    index: usize,
    id: u64,
    sender: mpsc::Sender<ChanReq<Octs>>,
    query_msg: Message<Octs>,
) -> Result<(usize, Result<Message<Bytes>, Error>), Error> {
    let (tx, rx) = oneshot::channel();
    sender
        .send(ChanReq::Query(QueryReq {
            id,
            query_msg: query_msg.clone(),
            tx,
        }))
        .await
        .expect("send is expected to work");
    let mut query = rx.await.expect("receive is expected to work")?;
    let reply = query.get_result().await;

    Ok((index, reply))
}

/// The commands that can be sent to the run function.
enum ChanReq<Octs: Send> {
    /// Add a connection
    Add(AddReq<Octs>),

    /// Get the list of estimated response times for all connections
    GetRT(RTReq),

    /// Start a query
    Query(QueryReq<Octs>),

    /// Report how long it took to get a response
    Report(TimeReport),

    /// Report that a connection failed to provide a timely response
    Failure(TimeReport),
}

impl<Octs: Debug + Send> Debug for ChanReq<Octs> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("ChanReq").finish()
    }
}

/// Request to add a new connection
struct AddReq<Octs> {
    /// New connection to add
    conn: Box<dyn QueryMessage3<Octs> + Send + Sync>,

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

/// Request to start a query
struct QueryReq<Octs: Send> {
    /// Identifier of connection
    id: u64,

    /// Request message
    query_msg: Message<Octs>,

    /// Channel to send the reply to
    tx: oneshot::Sender<QueryReply>,
}

impl<Octs: AsRef<[u8]> + Debug + Send> Debug for QueryReq<Octs> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("QueryReq")
            .field("id", &self.id)
            .field("query_msg", &self.query_msg)
            .finish()
    }
}

/// Reply to a query request.
type QueryReply = Result<Box<dyn GetResult + Send>, Error>;

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

/// Compare ConnRT elements based on estimated response time.
fn conn_rt_cmp(e1: &ConnRT, e2: &ConnRT) -> Ordering {
    e1.est_rt.cmp(&e2.est_rt)
}

/// Type that actually implements the connection.
struct InnerConnection<Octs: Send> {
    /// Receive side of the channel used by the runner.
    receiver: Mutex<Option<mpsc::Receiver<ChanReq<Octs>>>>,

    /// To send a request to the runner.
    sender: mpsc::Sender<ChanReq<Octs>>,
}

impl<'a, Octs: AsRef<[u8]> + Clone + Debug + Send + Sync + 'static>
    InnerConnection<Octs>
{
    /// Implementation of the new method.
    fn new() -> io::Result<InnerConnection<Octs>> {
        let (tx, rx) = mpsc::channel(DEF_CHAN_CAP);
        Ok(Self {
            receiver: Mutex::new(Some(rx)),
            sender: tx,
        })
    }

    /// Implementation of the run method.
    async fn run(&self) {
        let mut next_id: u64 = 10;
        let mut conn_stats: Vec<ConnStats> = Vec::new();
        let mut conn_rt: Vec<ConnRT> = Vec::new();
        let mut conns: Vec<Box<dyn QueryMessage3<Octs> + Send + Sync>> =
            Vec::new();

        let mut receiver = self.receiver.lock().await;
        let opt_receiver = receiver.take();
        drop(receiver);
        let mut receiver =
            opt_receiver.expect("receiver should not be empty");
        loop {
            let req =
                receiver.recv().await.expect("receiver should not fail");
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
                ChanReq::Query(query_req) => {
                    println!("QueryReq for id {}", query_req.id);
                    let opt_ind =
                        conn_rt.iter().position(|e| e.id == query_req.id);
                    match opt_ind {
                        Some(ind) => {
                            println!("QueryReq for ind {}", ind);
                            let query =
                                conns[ind].query(&query_req.query_msg).await;
                            // Don't care if send fails
                            let _ = query_req.tx.send(query);
                        }
                        None => {
                            // Don't care if send fails
                            let _ = query_req
                                .tx
                                .send(Err(Error::RedundantTransportNotFound));
                        }
                    }
                }
                ChanReq::Report(time_report) => {
                    println!(
                        "for {} time {:?}",
                        time_report.id, time_report.elapsed
                    );
                    let opt_ind =
                        conn_rt.iter().position(|e| e.id == time_report.id);
                    if let Some(ind) = opt_ind {
                        println!("Report for ind {}", ind);
                        let elapsed = time_report.elapsed.as_secs_f64();
                        conn_stats[ind].mean +=
                            (elapsed - conn_stats[ind].mean) / SMOOTH_N;
                        let elapsed_sq = elapsed * elapsed;
                        conn_stats[ind].mean_sq +=
                            (elapsed_sq - conn_stats[ind].mean_sq) / SMOOTH_N;
                        println!(
                            "new mean {} mean_sq {}",
                            conn_stats[ind].mean, conn_stats[ind].mean_sq
                        );
                        let mean = conn_stats[ind].mean;
                        let var = conn_stats[ind].mean_sq - mean * mean;
                        let std_dev =
                            if var < 0. { 0. } else { f64::sqrt(var) };
                        println!("std dev {}", std_dev);
                        let est_rt = mean + 3. * std_dev;
                        conn_rt[ind].est_rt = Duration::from_secs_f64(est_rt);
                        println!("new est_rt {:?}", conn_rt[ind].est_rt);
                    }
                }
                ChanReq::Failure(time_report) => {
                    println!(
                        "failure for {} time {:?}",
                        time_report.id, time_report.elapsed
                    );
                    let opt_ind =
                        conn_rt.iter().position(|e| e.id == time_report.id);
                    if let Some(ind) = opt_ind {
                        println!("Failure Report for ind {}", ind);
                        let elapsed = time_report.elapsed.as_secs_f64();
                        if elapsed < conn_stats[ind].mean {
                            // Do not update the mean if a
                            // failure took less time than the
                            // current mean.
                            println!("ignoring better time");
                            continue;
                        }
                        conn_stats[ind].mean +=
                            (elapsed - conn_stats[ind].mean) / SMOOTH_N;
                        let elapsed_sq = elapsed * elapsed;
                        conn_stats[ind].mean_sq +=
                            (elapsed_sq - conn_stats[ind].mean_sq) / SMOOTH_N;
                        println!(
                            "new mean {} mean_sq {}",
                            conn_stats[ind].mean, conn_stats[ind].mean_sq
                        );
                        let mean = conn_stats[ind].mean;
                        let var = conn_stats[ind].mean_sq - mean * mean;
                        let std_dev =
                            if var < 0. { 0. } else { f64::sqrt(var) };
                        println!("std dev {}", std_dev);
                        let est_rt = mean + 3. * std_dev;
                        conn_rt[ind].est_rt = Duration::from_secs_f64(est_rt);
                        println!("new est_rt {:?}", conn_rt[ind].est_rt);
                    }
                }
            }
        }
    }

    /// Implementation of the add method.
    async fn add(
        &self,
        conn: Box<dyn QueryMessage3<Octs> + Send + Sync>,
    ) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(ChanReq::Add(AddReq { conn, tx }))
            .await
            .expect("send should not fail");
        rx.await.expect("receive should not fail")
    }

    /// Implementation of the query method.
    async fn query(
        &'a self,
        query_msg: Message<Octs>,
    ) -> Result<Query<Octs>, Error> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(ChanReq::GetRT(RTReq { tx }))
            .await
            .expect("send should not fail");
        let conn_rt = rx.await.expect("receive should not fail")?;
        Ok(Query::new(query_msg, conn_rt, self.sender.clone()))
    }
}

//fn test_send<T: Send>(t: T) -> T { t }
