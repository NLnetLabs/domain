//! A DNS over multiple octet streams transport

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

// To do:
// - too many connection errors

use bytes::Bytes;

use futures::lock::Mutex as Futures_mutex;
use futures::stream::FuturesUnordered;
use futures::StreamExt;

use octseq::Octets;

use rand::random;

use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, Instant};

use crate::base::{Message, MessageBuilder, StaticCompressor, StreamTarget};
use crate::net::client::error::Error;
use crate::net::client::factory::ConnFactory;
use crate::net::client::octet_stream::Connection as SingleConnection;
use crate::net::client::octet_stream::QueryNoCheck as SingleQuery;
use crate::net::client::query::{GetResult, QueryMessage, QueryMessage3};

/// Capacity of the channel that transports [ChanReq].
const DEF_CHAN_CAP: usize = 8;

/// Error reported when the connection is closed and
/// [InnerConnection::run] terminated.
const ERR_CONN_CLOSED: &str = "connection closed";

/// Response to the DNS request sent by [InnerConnection::run] to [Query].
#[derive(Debug)]
struct ChanRespOk<Octs: AsRef<[u8]>> {
    /// id of this connection.
    id: u64,

    /// New octet_stream transport.
    conn: SingleConnection<Octs>,
}

/// The reply to a NewConn request.
type ChanResp<Octs> = Result<ChanRespOk<Octs>, Arc<std::io::Error>>;

/// This is the type of sender in [ReqCmd].
type ReplySender<Octs> = oneshot::Sender<ChanResp<Octs>>;

#[derive(Debug)]
/// Commands that can be requested.
enum ReqCmd<Octs: AsRef<[u8]>> {
    /// Request for a (new) connection.
    ///
    /// The id of the previous connection (if any) is passed as well as a
    /// channel to send the reply.
    NewConn(Option<u64>, ReplySender<Octs>),

    /// Shutdown command.
    Shutdown,
}

#[derive(Debug)]
/// A request to [Connection::run] either for a new octet_stream or to
/// shutdown.
struct ChanReq<Octs: AsRef<[u8]>> {
    /// A requests consists of a command.
    cmd: ReqCmd<Octs>,
}

/// The actual implementation of [Connection].
#[derive(Debug)]
struct InnerConnection<Octs: AsRef<[u8]>> {
    /// [InnerConnection::sender] and [InnerConnection::receiver] are
    /// part of a single channel.
    ///
    /// Used by [Query] to send requests to [InnerConnection::run].
    sender: mpsc::Sender<ChanReq<Octs>>,

    /// receiver part of the channel.
    ///
    /// Protected by a mutex to allow read/write access by
    /// [InnerConnection::run].
    /// The Option is to allow [InnerConnection::run] to signal that the
    /// connection is closed.
    receiver: Futures_mutex<Option<mpsc::Receiver<ChanReq<Octs>>>>,
}

#[derive(Clone, Debug)]
/// A DNS over octect streams transport.
pub struct Connection<Octs: AsRef<[u8]>> {
    /// Reference counted [InnerConnection].
    inner: Arc<InnerConnection<Octs>>,
}

/// Status of a query. Used in [Query].
#[derive(Debug)]
enum QueryState<Octs: AsRef<[u8]>> {
    /// Get a octet_stream transport.
    GetConn(oneshot::Receiver<ChanResp<Octs>>),

    /// Start a query using the transport.
    StartQuery(SingleConnection<Octs>),

    /// Get the result of the query.
    GetResult(SingleQuery),

    /// Wait until trying again.
    ///
    /// The instant represents when the error occured, the duration how
    /// long to wait.
    Delay(Instant, Duration),

    /// The response has been received and the query is done.
    Done,
}

/// State associated with a failed attempt to create a new octet_stream
/// transport.
#[derive(Clone)]
struct ErrorState {
    /// The error we got from the most recent attempt.
    error: Arc<std::io::Error>,

    /// How many times we tried so far.
    retries: u64,

    /// When we got an error.
    timer: Instant,

    /// Time to wait before trying to create a new connection.
    timeout: Duration,
}

/// State of the current underlying octet_stream transport.
enum SingleConnState3<Octs: AsRef<[u8]>> {
    /// No current octet_stream transport.
    None,

    /// Current octet_stream transport.
    Some(SingleConnection<Octs>),

    /// State that deals with an error getting a new octet stream from
    /// a factory.
    Err(ErrorState),
}

/// Internal datastructure of [InnerConnection::run] to keep track of
/// the status of the connection.
// The types Status and ConnState are only used in InnerConnection
struct State3<'a, F, IO, Octs: AsRef<[u8]>> {
    /// Underlying octet_stream connection.
    conn_state: SingleConnState3<Octs>,

    /// Current connection id.
    conn_id: u64,

    /// Factory for new octet streams.
    factory: F,

    /// Collection of futures for the async run function of the underlying
    /// octet_stream.
    runners: FuturesUnordered<
        Pin<Box<dyn Future<Output = Option<()>> + Send + 'a>>,
    >,

    /// Phantom data for type IO
    phantom: PhantomData<&'a IO>,
}

/// This struct represent an active DNS query.
#[derive(Debug)]
pub struct Query<Octs: AsRef<[u8]>> {
    /// Request message.
    ///
    /// The reply message is compared with the request message to see if
    /// it matches the query.
    // query_msg: Message<Vec<u8>>,
    query_msg: Message<Octs>,

    /// Current state of the query.
    state: QueryState<Octs>,

    /// A multi_octet connection object is needed to request new underlying
    /// octet_stream transport connections.
    conn: Connection<Octs>,

    /// id of most recent connection.
    conn_id: u64,

    // /// Number of retries without delay.
    // imm_retry_count: u16,
    /// Number of retries with delay.
    delayed_retry_count: u64,
}

impl<Octs: AsRef<[u8]> + Clone + Octets + Send + 'static>
    InnerConnection<Octs>
{
    /// Constructor for [InnerConnection].
    ///
    /// This is the implementation of [Connection::new].
    pub fn new() -> io::Result<InnerConnection<Octs>> {
        let (tx, rx) = mpsc::channel(DEF_CHAN_CAP);
        Ok(Self {
            sender: tx,
            receiver: Futures_mutex::new(Some(rx)),
        })
    }

    /// Main execution function for [InnerConnection].
    ///
    /// This function Gets called by [Connection::run].
    /// This function is not async cancellation safe
    #[rustfmt::skip]

    pub async fn run<
        'a,
        F: ConnFactory<IO> + Send,
        IO: 'static + AsyncRead + AsyncWrite + Debug + Send + Unpin,
    >(
        &self,
        factory: F,
    ) -> Option<()> {
        let mut receiver = {
            let mut locked_opt_receiver = self.receiver.lock().await;
            let opt_receiver = locked_opt_receiver.take();
            opt_receiver.expect("no receiver present?")
        };
        let mut curr_cmd: Option<ReqCmd<Octs>> = None;

        let mut state = State3::<'a, F, IO, Octs> {
            conn_state: SingleConnState3::None,
            conn_id: 0,
            factory,
            runners: FuturesUnordered::<
                Pin<Box<dyn Future<Output = Option<()>> + Send>>,
            >::new(),
            phantom: PhantomData,
        };

        let mut do_stream = false;
        let mut stream_fut: Pin<
            Box<dyn Future<Output = Result<IO, std::io::Error>> + Send>,
        > = Box::pin(factory_nop());
        let mut opt_chan = None;

        loop {
            if let Some(req) = curr_cmd {
                assert!(!do_stream);
                curr_cmd = None;
                match req {
                    ReqCmd::NewConn(opt_id, chan) => {
                        if let SingleConnState3::Err(error_state) =
                            &state.conn_state
                        {
                            if error_state.timer.elapsed()
                                < error_state.timeout
                            {
                                let resp =
                                    ChanResp::Err(error_state.error.clone());

                                // Ignore errors. We don't care if the receiver
                                // is gone
                                _ = chan.send(resp);
                                continue;
                            }

                            // Try to set up a new connection
                        }

                        // Check if the command has an id greather than the
                        // current id.
                        if let Some(id) = opt_id {
                            if id >= state.conn_id {
                                // We need a new connection. Remove the
                                // current one. This is the best place to
                                // increment conn_id.
                                state.conn_id += 1;
                                state.conn_state = SingleConnState3::None;
                            }
                        }
                        // If we still have a connection then we can reply
                        // immediately.
                        if let SingleConnState3::Some(conn) = &state.conn_state
                        {
                            let resp = ChanResp::Ok(ChanRespOk {
                                id: state.conn_id,
                                conn: conn.clone(),
                            });
                            // Ignore errors. We don't care if the receiver
                            // is gone
                            _ = chan.send(resp);
                        } else {
                            opt_chan = Some(chan);
                            stream_fut = Box::pin(state.factory.next());
                            do_stream = true;
                        }
                    }
                    ReqCmd::Shutdown => break,
                }
            }

            if do_stream {
                let runners_empty = state.runners.is_empty();

                loop {
                    tokio::select! {
                        res_conn = stream_fut.as_mut() => {
                            do_stream = false;
                            stream_fut = Box::pin(factory_nop());

                            if let Err(error) = res_conn {
                                let error = Arc::new(error);
                                match state.conn_state {
                                    SingleConnState3::None =>
                                        state.conn_state =
                                        SingleConnState3::Err(ErrorState {
                                            error: error.clone(),
                                            retries: 0,
                                            timer: Instant::now(),
                                            timeout: retry_time(0),
                                        }),
                                    SingleConnState3::Some(_) =>
                                        panic!("Illegal Some state"),
                                    SingleConnState3::Err(error_state) => {
                                        state.conn_state =
                                        SingleConnState3::Err(ErrorState {
                                            error: error_state.error.clone(),
                                            retries: error_state.retries+1,
                                            timer: Instant::now(),
                                            timeout: retry_time(
                                            error_state.retries+1),
                                        });
                                    }
                                }

                                let resp = ChanResp::Err(error);
                                let loc_opt_chan = opt_chan.take();

                                // Ignore errors. We don't care if the receiver
                                // is gone
                                _ = loc_opt_chan.expect("weird, no channel?")
                                    .send(resp);
                                break;
                            }

                            let stream = res_conn
                                .expect("error case is checked before");
                            let conn = SingleConnection::new()
                                .expect(
                                "the connect implementation cannot fail");
                            let conn_run = conn.clone();

                            let clo = || async move {
                                conn_run.run(stream).await
                            };
                            let fut = clo();
                            state.runners.push(Box::pin(fut));

                            let resp = ChanResp::Ok(ChanRespOk {
                                id: state.conn_id,
                                conn: conn.clone(),
                            });
                            state.conn_state = SingleConnState3::Some(conn);

                            let loc_opt_chan = opt_chan.take();

                            // Ignore errors. We don't care if the receiver
                            // is gone
                            _ = loc_opt_chan.expect("weird, no channel?")
                                .send(resp);
                            break;
                        }
                        _ = state.runners.next(), if !runners_empty => {
                            }
                    }
                }
                continue;
            }

            assert!(curr_cmd.is_none());
            let recv_fut = receiver.recv();
            let runners_empty = state.runners.is_empty();
            tokio::select! {
                msg = recv_fut => {
                    if msg.is_none() {
                        panic!("recv failed");
                    }
                    curr_cmd = Some(msg.expect("None is checked before").cmd);
                }
                _ = state.runners.next(), if !runners_empty => {
                    }
            }
        }

        // Avoid new queries
        drop(receiver);

        // Wait for existing octet_stream runners to terminate
        while !state.runners.is_empty() {
            state.runners.next().await;
        }

        // Done
        Some(())
    }

    /// Request a new connection.
    async fn new_conn(
        &self,
        opt_id: Option<u64>,
        sender: oneshot::Sender<ChanResp<Octs>>,
    ) -> Result<(), Error> {
        let req = ChanReq {
            cmd: ReqCmd::NewConn(opt_id, sender),
        };
        match self.sender.send(req).await {
            Err(_) =>
            // Send error. The receiver is gone, this means that the
            // connection is closed.
            {
                Err(Error::ConnectionClosed)
            }
            Ok(_) => Ok(()),
        }
    }

    /// Request a shutdown.
    async fn shutdown(&self) -> Result<(), &'static str> {
        let req = ChanReq {
            cmd: ReqCmd::Shutdown,
        };
        match self.sender.send(req).await {
            Err(_) =>
            // Send error. The receiver is gone, this means that the
            // connection is closed.
            {
                Err(ERR_CONN_CLOSED)
            }
            Ok(_) => Ok(()),
        }
    }
}

impl<Octs: AsRef<[u8]> + Clone + Debug + Octets + Send + Sync + 'static>
    Connection<Octs>
{
    /// Constructor for [Connection].
    ///
    /// Returns a [Connection] wrapped in a [Result](io::Result).
    pub fn new() -> io::Result<Connection<Octs>> {
        let connection = InnerConnection::new()?;
        Ok(Self {
            inner: Arc::new(connection),
        })
    }

    /// Main execution function for [Connection].
    ///
    /// This function has to run in the background or together with
    /// any calls to [query](Self::query) or [Query::get_result].
    pub async fn run<
        F: ConnFactory<IO> + Send,
        IO: 'static + AsyncRead + AsyncWrite + Debug + Send + Unpin,
    >(
        &self,
        factory: F,
    ) -> Option<()> {
        self.inner.run(factory).await
    }

    /// Start a DNS request.
    ///
    /// This function takes a precomposed message as a parameter and
    /// returns a [Query] object wrapped in a [Result].
    pub async fn query_impl3(
        &self,
        query_msg: &Message<Octs>,
    ) -> Result<Box<dyn GetResult + Send>, Error> {
        let (tx, rx) = oneshot::channel();
        self.inner.new_conn(None, tx).await?;
        let gr = Query::new(self.clone(), query_msg, rx);
        Ok(Box::new(gr))
    }

    /// Shutdown this transport.
    pub async fn shutdown(&self) -> Result<(), &'static str> {
        self.inner.shutdown().await
    }

    /// Request a new connection.
    async fn new_conn(
        &self,
        id: u64,
        tx: oneshot::Sender<ChanResp<Octs>>,
    ) -> Result<(), Error> {
        self.inner.new_conn(Some(id), tx).await
    }
}

impl<Octs: Clone + Debug + Octets + Send + Sync + 'static>
    QueryMessage<Query<Octs>, Octs> for Connection<Octs>
{
    fn query<'a>(
        &'a self,
        _query_msg: &'a mut MessageBuilder<
            StaticCompressor<StreamTarget<Octs>>,
        >,
    ) -> Pin<Box<dyn Future<Output = Result<Query<Octs>, Error>> + Send + '_>>
    {
        todo!();
        /*
                return Box::pin(self.query_impl3(query_msg));
        */
    }
}

impl<Octs: AsRef<[u8]> + Clone + Debug + Octets + Send + Sync + 'static>
    QueryMessage3<Octs> for Connection<Octs>
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
        return Box::pin(self.query_impl3(query_msg));
    }
}

impl<Octs: AsRef<[u8]> + Clone + Debug + Octets + Send + Sync + 'static>
    Query<Octs>
{
    /// Constructor for [Query], takes a DNS query and a receiver for the
    /// reply.
    fn new(
        conn: Connection<Octs>,
        query_msg: &Message<Octs>,
        receiver: oneshot::Receiver<ChanResp<Octs>>,
    ) -> Query<Octs> {
        Self {
            conn,
            query_msg: query_msg.clone(),
            state: QueryState::GetConn(receiver),
            conn_id: 0,
            //imm_retry_count: 0,
            delayed_retry_count: 0,
        }
    }

    /// Get the result of a DNS query.
    ///
    /// This function returns the reply to a DNS query wrapped in a
    /// [Result].
    pub async fn get_result_impl(&mut self) -> Result<Message<Bytes>, Error> {
        loop {
            match self.state {
                QueryState::GetConn(ref mut receiver) => {
                    let res = receiver.await;
                    if res.is_err() {
                        // Assume receive error
                        self.state = QueryState::Done;
                        return Err(Error::StreamReceiveError);
                    }
                    let res = res.expect("error is checked before");

                    // Another Result. This time from executing the request
                    match res {
                        Err(_) => {
                            self.delayed_retry_count += 1;
                            let retry_time =
                                retry_time(self.delayed_retry_count);
                            self.state =
                                QueryState::Delay(Instant::now(), retry_time);
                            continue;
                        }
                        Ok(ok_res) => {
                            let id = ok_res.id;
                            let conn = ok_res.conn;

                            self.conn_id = id;
                            self.state = QueryState::StartQuery(conn);
                            continue;
                        }
                    }
                }
                QueryState::StartQuery(ref mut conn) => {
                    let mut msg = self.query_msg.clone();
                    let query_res = conn.query_no_check(&mut msg).await;
                    match query_res {
                        Err(err) => {
                            if let Error::ConnectionClosed = err {
                                let (tx, rx) = oneshot::channel();
                                let res = self
                                    .conn
                                    .new_conn(self.conn_id, tx)
                                    .await;
                                if let Err(err) = res {
                                    self.state = QueryState::Done;
                                    return Err(err);
                                }
                                self.state = QueryState::GetConn(rx);
                                continue;
                            }
                            return Err(err);
                        }
                        Ok(query) => {
                            self.state = QueryState::GetResult(query);
                            continue;
                        }
                    }
                }
                QueryState::GetResult(ref mut query) => {
                    let reply = query.get_result().await;

                    if reply.is_err() {
                        self.delayed_retry_count += 1;
                        let retry_time = retry_time(self.delayed_retry_count);
                        self.state =
                            QueryState::Delay(Instant::now(), retry_time);
                        continue;
                    }

                    let msg = reply.expect("error is checked before");
                    let query_msg_ref: &[u8] = self.query_msg.as_ref();
                    let query_msg_vec = query_msg_ref.to_vec();
                    let query_msg = Message::from_octets(query_msg_vec)
                        .expect("how to go from MessageBuild to Message?");

                    if !is_answer_ignore_id(&msg, &query_msg) {
                        return Err(Error::WrongReplyForQuery);
                    }
                    return Ok(msg);
                }
                QueryState::Delay(instant, duration) => {
                    sleep_until(instant + duration).await;
                    let (tx, rx) = oneshot::channel();
                    let res = self.conn.new_conn(self.conn_id, tx).await;
                    if let Err(err) = res {
                        self.state = QueryState::Done;
                        return Err(err);
                    }
                    self.state = QueryState::GetConn(rx);
                    continue;
                }
                QueryState::Done => {
                    panic!("Already done");
                }
            }
        }
    }
}

impl<Octs: AsRef<[u8]> + Clone + Debug + Octets + Send + Sync + 'static>
    GetResult for Query<Octs>
{
    fn get_result(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_result_impl())
    }
}

/// Compute the retry timeout based on the number of retries so far.
///
/// The computation is a random value (in microseconds) between zero and
/// two to the power of the number of retries.
fn retry_time(retries: u64) -> Duration {
    let to_secs = if retries > 6 { 60 } else { 1 << retries };
    let to_usecs = to_secs * 1000000;
    let rnd: f64 = random();
    let to_usecs = to_usecs as f64 * rnd;
    Duration::from_micros(to_usecs as u64)
}

/// Check if a message is the reply to a query.
///
/// Avoid checking the id field because the id has been changed in the
/// query that was actually issued.
fn is_answer_ignore_id<
    Octs1: Octets + AsRef<[u8]>,
    Octs2: Octets + AsRef<[u8]>,
>(
    reply: &Message<Octs1>,
    query: &Message<Octs2>,
) -> bool {
    if !reply.header().qr()
        || reply.header_counts().qdcount() != query.header_counts().qdcount()
    {
        false
    } else {
        reply.question() == query.question()
    }
}

/// Helper function to create an empty future that is compatible with the
/// future return by a factory.
async fn factory_nop<IO>() -> Result<IO, std::io::Error> {
    Err(io::Error::new(io::ErrorKind::Other, "nop"))
}
