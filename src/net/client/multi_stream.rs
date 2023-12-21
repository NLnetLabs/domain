//! A DNS over multiple octet streams transport

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

// To do:
// - too many connection errors

use bytes::Bytes;

use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;

use octseq::Octets;

use rand::random;

use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, Instant};

use crate::base::iana::Rcode;
use crate::base::Message;
use crate::net::client::octet_stream;
use crate::net::client::protocol::AsyncConnect;
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};

/// Capacity of the channel that transports [ChanReq].
const DEF_CHAN_CAP: usize = 8;

/// Error reported when the connection is closed and
/// [InnerConnection::run] terminated.
const ERR_CONN_CLOSED: &str = "connection closed";

//------------ Config ---------------------------------------------------------

/// Configuration for an octet_stream transport connection.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Response timeout.
    pub octet_stream: Option<octet_stream::Config>,
}

//------------ Connection -----------------------------------------------------

#[derive(Clone, Debug)]
/// A DNS over octect streams transport.
pub struct Connection<CR> {
    /// Reference counted [InnerConnection].
    inner: Arc<InnerConnection<CR>>,
}

impl<CR: ComposeRequest + Clone + 'static> Connection<CR> {
    /// Constructor for [Connection].
    ///
    /// Returns a [Connection] wrapped in a [Result](io::Result).
    pub fn new(config: Option<Config>) -> Result<Self, Error> {
        let config = match config {
            Some(config) => {
                check_config(&config)?;
                config
            }
            None => Default::default(),
        };
        let connection = InnerConnection::new(config)?;
        Ok(Self {
            inner: Arc::new(connection),
        })
    }

    /// Main execution function for [Connection].
    ///
    /// This function has to run in the background or together with
    /// any calls to [query](Self::query) or [ReqResp::get_response].
    pub fn run<
        S: AsyncConnect<Connection = C> + Send + 'static,
        C: 'static + AsyncRead + AsyncWrite + Debug + Send + Sync + Unpin,
    >(
        &self,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>> {
        self.inner.run(stream)
    }

    /// Start a DNS request.
    ///
    /// This function takes a precomposed message as a parameter and
    /// returns a [ReqResp] object wrapped in a [Result].
    async fn query_impl(
        &self,
        query_msg: &CR,
    ) -> Result<Box<dyn GetResponse + Send>, Error> {
        let (tx, rx) = oneshot::channel();
        self.inner.new_conn(None, tx).await?;
        let gr = ReqResp::<CR>::new(self.clone(), query_msg, rx);
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
        tx: oneshot::Sender<ChanResp<CR>>,
    ) -> Result<(), Error> {
        self.inner.new_conn(Some(id), tx).await
    }
}

impl<CR: ComposeRequest + Clone + 'static> SendRequest<CR>
    for Connection<CR>
{
    fn send_request<'a>(
        &'a self,
        request_msg: &'a CR,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn GetResponse + Send>, Error>>
                + Send
                + '_,
        >,
    > {
        return Box::pin(self.query_impl(request_msg));
    }
}

//------------ ReqResp --------------------------------------------------------

/// This struct represent an active DNS request.
#[derive(Debug)]
pub struct ReqResp<CR: ComposeRequest> {
    /// Request message.
    ///
    /// The reply message is compared with the request message to see if
    /// it matches the query.
    // query_msg: Message<Vec<u8>>,
    request_msg: CR,

    /// Current state of the query.
    state: QueryState<CR>,

    /// A multi_octet connection object is needed to request new underlying
    /// octet_stream transport connections.
    conn: Connection<CR>,

    /// id of most recent connection.
    conn_id: u64,

    // /// Number of retries without delay.
    // imm_retry_count: u16,
    /// Number of retries with delay.
    delayed_retry_count: u64,
}

/// Status of a query. Used in [Query].
#[derive(Debug)]
enum QueryState<CR> {
    /// Get a octet_stream transport.
    GetConn(oneshot::Receiver<ChanResp<CR>>),

    /// Start a query using the transport.
    StartQuery(octet_stream::Connection<CR>),

    /// Get the result of the query.
    GetResult(octet_stream::QueryNoCheck),

    /// Wait until trying again.
    ///
    /// The instant represents when the error occured, the duration how
    /// long to wait.
    Delay(Instant, Duration),

    /// The response has been received and the query is done.
    Done,
}

/// The reply to a NewConn request.
type ChanResp<CR> = Result<ChanRespOk<CR>, Arc<std::io::Error>>;

/// Response to the DNS request sent by [InnerConnection::run] to [Query].
#[derive(Debug)]
struct ChanRespOk<CR> {
    /// id of this connection.
    id: u64,

    /// New octet_stream transport.
    conn: octet_stream::Connection<CR>,
}

impl<CR: ComposeRequest + Clone + 'static> ReqResp<CR> {
    /// Constructor for [ReqResp], takes a DNS request and a receiver for the
    /// reply.
    fn new(
        conn: Connection<CR>,
        request_msg: &CR,
        receiver: oneshot::Receiver<ChanResp<CR>>,
    ) -> ReqResp<CR> {
        Self {
            conn,
            request_msg: request_msg.clone(),
            state: QueryState::GetConn(receiver),
            conn_id: 0,
            delayed_retry_count: 0,
        }
    }

    /// Get the result of a DNS request.
    ///
    /// This function returns the reply to a DNS request wrapped in a
    /// [Result].
    pub async fn get_response_impl(
        &mut self,
    ) -> Result<Message<Bytes>, Error> {
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
                    let msg = self.request_msg.clone();
                    let query_res = conn.query_no_check(&msg).await;
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
                    let request_msg = self.request_msg.to_message();

                    if !is_answer_ignore_id(&msg, &request_msg) {
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

impl<CR: ComposeRequest + Clone + 'static> GetResponse for ReqResp<CR> {
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_response_impl())
    }
}

//------------ InnerConnection ------------------------------------------------

/// The actual implementation of [Connection].
#[derive(Debug)]
struct InnerConnection<CR> {
    /// User configuration values.
    config: Config,

    /// [InnerConnection::sender] and [InnerConnection::receiver] are
    /// part of a single channel.
    ///
    /// Used by [ReqResp] to send requests to [InnerConnection::run].
    sender: mpsc::Sender<ChanReq<CR>>,

    /// receiver part of the channel.
    ///
    /// Protected by a mutex to allow read/write access by
    /// [InnerConnection::run].
    /// The Option is to allow [InnerConnection::run] to signal that the
    /// connection is closed.
    receiver: Mutex<Option<mpsc::Receiver<ChanReq<CR>>>>,
}

#[derive(Debug)]
/// A request to [Connection::run] either for a new octet_stream or to
/// shutdown.
struct ChanReq<CR> {
    /// A requests consists of a command.
    cmd: ReqCmd<CR>,
}

#[derive(Debug)]
/// Commands that can be requested.
enum ReqCmd<CR> {
    /// Request for a (new) connection.
    ///
    /// The id of the previous connection (if any) is passed as well as a
    /// channel to send the reply.
    NewConn(Option<u64>, ReplySender<CR>),

    /// Shutdown command.
    Shutdown,
}

/// This is the type of sender in [ReqCmd].
type ReplySender<CR> = oneshot::Sender<ChanResp<CR>>;

/// Internal datastructure of [InnerConnection::run] to keep track of
/// the status of the connection.
// The types Status and ConnState are only used in InnerConnection
struct State3<'a, S, IO, CR> {
    /// Underlying octet_stream connection.
    conn_state: SingleConnState3<CR>,

    /// Current connection id.
    conn_id: u64,

    /// Connection stream for new octet streams.
    stream: S,

    /// Collection of futures for the async run function of the underlying
    /// octet_stream.
    runners: FuturesUnordered<
        Pin<Box<dyn Future<Output = Option<()>> + Send + 'a>>,
    >,

    /// Phantom data for type IO
    phantom: PhantomData<&'a IO>,
}

/// State of the current underlying octet_stream transport.
enum SingleConnState3<CR> {
    /// No current octet_stream transport.
    None,

    /// Current octet_stream transport.
    Some(octet_stream::Connection<CR>),

    /// State that deals with an error getting a new octet stream from
    /// a connection stream.
    Err(ErrorState),
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

impl<CR: ComposeRequest + Clone + 'static> InnerConnection<CR> {
    /// Constructor for [InnerConnection].
    ///
    /// This is the implementation of [Connection::new].
    pub fn new(config: Config) -> Result<Self, Error> {
        let (tx, rx) = mpsc::channel(DEF_CHAN_CAP);
        Ok(Self {
            config,
            sender: tx,
            receiver: Mutex::new(Some(rx)),
        })
    }

    /// Main execution function for [InnerConnection].
    ///
    /// This function Gets called by [Connection::run].
    /// This function is not async cancellation safe.
    /// Make sure the resulting future does not contain a reference to self.
    pub fn run<
        S: AsyncConnect<Connection = C> + Send + 'static,
        C: 'static + AsyncRead + AsyncWrite + Debug + Send + Sync + Unpin,
    >(
        &self,
        stream: S,
    ) -> Pin<Box<dyn Future<Output = Result<(), Error>> + Send>> {
        let mut receiver = self.receiver.lock().unwrap();
        let opt_receiver = receiver.take();
        drop(receiver);

        Box::pin(Self::run_impl(self.config.clone(), stream, opt_receiver))
    }

    /// Implementation of the run method. This function does not have
    /// a reference to self.
    #[rustfmt::skip]
    async fn run_impl<
        'a,
        S: AsyncConnect<Connection = C> + Send,
        C: 'static + AsyncRead + AsyncWrite + Debug + Send + Unpin,
    >(
	config: Config,
        stream: S,
	opt_receiver: Option<mpsc::Receiver<ChanReq<CR>>>
    ) -> Result<(), Error> {
        let mut receiver = {
            opt_receiver.expect("no receiver present?")
        };
        let mut curr_cmd: Option<ReqCmd<CR>> = None;

        let mut state = State3::<'a, S, C, CR> {
            conn_state: SingleConnState3::None,
            conn_id: 0,
            stream,
            runners: FuturesUnordered::<
                Pin<Box<dyn Future<Output = Option<()>> + Send>>,
            >::new(),
            phantom: PhantomData,
        };

        let mut do_stream = false;
        let mut stream_fut: Pin<
            Box<dyn Future<Output = Result<C, std::io::Error>> + Send>,
        > = Box::pin(stream_nop());
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
                            stream_fut = Box::pin(state.stream.connect());
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
                            stream_fut = Box::pin(stream_nop());

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
                            let conn = octet_stream::Connection::new(config.octet_stream.clone())?;
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
			// All references to the connection object have been
			// dropped. Shutdown.
                        break;
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
        Ok(())
    }

    /// Request a new connection.
    async fn new_conn(
        &self,
        opt_id: Option<u64>,
        sender: oneshot::Sender<ChanResp<CR>>,
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

//------------ Utility --------------------------------------------------------

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
    let reply_header = reply.header();
    let reply_hcounts = reply.header_counts();

    // First check qr is set
    if !reply_header.qr() {
        return false;
    }

    // If the result is an error, then the question
    // section can be empty. In that case we require all other sections
    // to be empty as well.
    if reply_header.rcode() != Rcode::NoError
        && reply_hcounts.qdcount() == 0
        && reply_hcounts.ancount() == 0
        && reply_hcounts.nscount() == 0
        && reply_hcounts.arcount() == 0
    {
        // We can accept this as a valid reply.
        return true;
    }

    // Remaining checks. The question section in the reply has to be the
    // same as in the query.
    if reply_hcounts.qdcount() != query.header_counts().qdcount() {
        false
    } else {
        reply.question() == query.question()
    }
}

/// Helper function to create an empty future that is compatible with the
/// future returned by a connection stream.
async fn stream_nop<IO>() -> Result<IO, std::io::Error> {
    Err(io::Error::new(io::ErrorKind::Other, "nop"))
}

/// Check if config is valid.
fn check_config(_config: &Config) -> Result<(), Error> {
    // Nothing to check at the moment.
    Ok(())
}
