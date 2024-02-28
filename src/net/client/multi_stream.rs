//! A DNS over multiple octet streams transport

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

// To do:
// - too many connection errors

use crate::base::Message;
use crate::net::client::protocol::AsyncConnect;
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};
use crate::net::client::stream;
use bytes::Bytes;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use rand::random;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, Instant};

//------------ Constants -----------------------------------------------------

/// Capacity of the channel that transports `ChanReq`.
const DEF_CHAN_CAP: usize = 8;

/// Error messafe when the connection is closed.
const ERR_CONN_CLOSED: &str = "connection closed";

//------------ Config ---------------------------------------------------------

/// Configuration for an multi-stream transport.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// Configuration of the underlying stream transport.
    stream: stream::Config,
}

impl Config {
    /// Returns the underlying stream config.
    pub fn stream(&self) -> &stream::Config {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream config.
    pub fn stream_mut(&mut self) -> &mut stream::Config {
        &mut self.stream
    }
}

impl From<stream::Config> for Config {
    fn from(stream: stream::Config) -> Self {
        Self { stream }
    }
}

//------------ Connection -----------------------------------------------------

/// A connection to a multi-stream transport.
#[derive(Debug)]
pub struct Connection<Req> {
    /// The sender half of the connection request channel.
    sender: mpsc::Sender<ChanReq<Req>>,
}

impl<Req> Connection<Req> {
    /// Creates a new connection and transport.
    ///
    /// This is the same as calling [`with_config()`][`Self::with_config()`]
    /// with [`Config::default()`].
    pub fn new<Remote>(remote: Remote) -> (Self, Transport<Remote, Req>) {
        Self::with_config(remote, Default::default())
    }

    /// Creates a new connection and transport with the given configuration.
    ///
    /// Returns a [`Connection`] and a [`Transport`]. Use [`Transport::run()`]
    /// to start the transport running then use [`Connection::send_request()`]
    /// to send a request and receive a response via the transport.
    pub fn with_config<Remote>(
        remote: Remote,
        config: Config,
    ) -> (Self, Transport<Remote, Req>) {
        let (sender, transport) = Transport::new(remote, config);
        (Self { sender }, transport)
    }

    /// Runs a new transport returning a connection to it.
    ///
    /// This is the same as calling
    /// [`run_with_config()`][`Self::run_with_config()`] with
    /// [`Config::default()`].
    pub fn run<Remote>(remote: Remote) -> Self
    where
        Remote: AsyncConnect + Send + 'static,
        Remote::Connection: AsyncRead + AsyncWrite + Send,
        Req: ComposeRequest + 'static,
    {
        Self::run_with_config(remote, Default::default())
    }

    /// Runs a new transport with the given configuration, returning a
    /// connection to it.
    ///
    /// Creates a [`Connection`] and [`Transport`], spawning the future that
    /// drives the transport onto a new Tokio task and returns the
    /// [`Connection`] ready for sending requests.
    pub fn run_with_config<Remote>(remote: Remote, config: Config) -> Self
    where
        Remote: AsyncConnect + Send + 'static,
        Remote::Connection: AsyncRead + AsyncWrite + Send,
        Req: ComposeRequest + 'static,
    {
        let (connection, transport) = Self::with_config(remote, config);
        let _join_handle = tokio::spawn(async move {
            transport.run().await;
        });
        connection
    }
}

impl<Req: ComposeRequest + Clone + 'static> Connection<Req> {
    /// Sends a request and receives a response.
    pub async fn request(
        &self,
        request: Req,
    ) -> Result<Message<Bytes>, Error> {
        Request::new(self.clone(), request).get_response().await
    }

    /// Starts a request.
    ///
    /// This is the future that is returned by the `SendRequest` impl.
    async fn _send_request(
        &self,
        request: &Req,
    ) -> Result<Box<dyn GetResponse + Send>, Error>
    where
        Req: 'static,
    {
        let gr = Request::new(self.clone(), request.clone());
        Ok(Box::new(gr))
    }

    /// Request a new connection.
    async fn new_conn(
        &self,
        opt_id: Option<u64>,
    ) -> Result<oneshot::Receiver<ChanResp<Req>>, Error> {
        let (sender, receiver) = oneshot::channel();
        let req = ChanReq {
            cmd: ReqCmd::NewConn(opt_id, sender),
        };
        self.sender
            .send(req)
            .await
            .map_err(|_| Error::ConnectionClosed)?;
        Ok(receiver)
    }

    /// Request a shutdown.
    pub async fn shutdown(&self) -> Result<(), &'static str> {
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

//--- Clone

impl<Req> Clone for Connection<Req> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

//--- SendRequest

impl<Req> SendRequest<Req> for Connection<Req>
where
    Req: ComposeRequest + Clone + 'static,
{
    fn send_request(
        &self,
        request: Req,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(Request::new(self.clone(), request))
    }
}

//------------ Request --------------------------------------------------------

/// The connection side of an active request.
#[derive(Debug)]
struct Request<Req> {
    /// The request message.
    ///
    /// It is kept so we can compare a response with it.
    request_msg: Req,

    /// Current state of the query.
    state: QueryState<Req>,

    /// The underlying transport.
    conn: Connection<Req>,

    /// The id of the most recent connection, if any.
    conn_id: Option<u64>,

    /// Number of retries with delay.
    delayed_retry_count: u64,
}

/// The states of the query state machine.
#[derive(Debug)]
enum QueryState<Req> {
    /// Request a new connection.
    RequestConn,

    /// Receive a new connection from the receiver.
    ReceiveConn(oneshot::Receiver<ChanResp<Req>>),

    /// Start a query using the given stream transport.
    StartQuery(Arc<stream::Connection<Req>>),

    /// Get the result of the query.
    GetResult(stream::Request),

    /// Wait until trying again.
    ///
    /// The instant represents when the error occurred, the duration how
    /// long to wait.
    Delay(Instant, Duration),

    /// A response has been received and the query is done.
    Done,
}

/// The response to a connection request.
type ChanResp<Req> = Result<ChanRespOk<Req>, Arc<std::io::Error>>;

/// The successful response to a connection request.
#[derive(Debug)]
struct ChanRespOk<Req> {
    /// The id of this connection.
    id: u64,

    /// The new stream transport to use for sending a request.
    conn: Arc<stream::Connection<Req>>,
}

impl<Req> Request<Req> {
    /// Creates a new query.
    fn new(conn: Connection<Req>, request_msg: Req) -> Self {
        Self {
            conn,
            request_msg,
            state: QueryState::RequestConn,
            conn_id: None,
            delayed_retry_count: 0,
        }
    }
}

impl<Req: ComposeRequest + Clone + 'static> Request<Req> {
    /// Get the result of a DNS request.
    ///
    /// This function is cancellation safe. If its future is dropped before
    /// it is resolved, you can call it again to get a new future.
    pub async fn get_response(&mut self) -> Result<Message<Bytes>, Error> {
        loop {
            match self.state {
                QueryState::RequestConn => {
                    let rx = match self.conn.new_conn(self.conn_id).await {
                        Ok(rx) => rx,
                        Err(err) => {
                            self.state = QueryState::Done;
                            return Err(err);
                        }
                    };
                    self.state = QueryState::ReceiveConn(rx);
                }
                QueryState::ReceiveConn(ref mut receiver) => {
                    let res = match receiver.await {
                        Ok(res) => res,
                        Err(_) => {
                            // Assume receive error
                            self.state = QueryState::Done;
                            return Err(Error::StreamReceiveError);
                        }
                    };

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

                            self.conn_id = Some(id);
                            self.state = QueryState::StartQuery(conn);
                            continue;
                        }
                    }
                }
                QueryState::StartQuery(ref mut conn) => {
                    self.state = QueryState::GetResult(
                        conn.get_request(self.request_msg.clone()),
                    );
                    continue;
                }
                QueryState::GetResult(ref mut query) => {
                    match query.get_response().await {
                        Ok(reply) => return Ok(reply),
                        // XXX This replicates the previous behavior. But
                        //     maybe we should have a whole category of
                        //     fatal errors where retrying doesn’t make any
                        //     sense?
                        Err(Error::WrongReplyForQuery) => {
                            return Err(Error::WrongReplyForQuery)
                        }
                        Err(_) => {
                            self.delayed_retry_count += 1;
                            let retry_time =
                                retry_time(self.delayed_retry_count);
                            self.state =
                                QueryState::Delay(Instant::now(), retry_time);
                            continue;
                        }
                    }
                }
                QueryState::Delay(instant, duration) => {
                    sleep_until(instant + duration).await;
                    self.state = QueryState::RequestConn;
                }
                QueryState::Done => {
                    panic!("Already done");
                }
            }
        }
    }
}

impl<Req: ComposeRequest + Clone + 'static> GetResponse for Request<Req> {
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
        Box::pin(Self::get_response(self))
    }
}

//------------ Transport ------------------------------------------------

/// The actual implementation of [Connection].
#[derive(Debug)]
pub struct Transport<Remote, Req> {
    /// User configuration values.
    config: Config,

    /// The remote destination.
    stream: Remote,

    /// Underlying stream connection.
    conn_state: SingleConnState3<Req>,

    /// Current connection id.
    conn_id: u64,

    /// Receiver part of the channel.
    receiver: mpsc::Receiver<ChanReq<Req>>,
}

#[derive(Debug)]
/// A request to [Connection::run] either for a new stream or to
/// shutdown.
struct ChanReq<Req> {
    /// A requests consists of a command.
    cmd: ReqCmd<Req>,
}

#[derive(Debug)]
/// Commands that can be requested.
enum ReqCmd<Req> {
    /// Request for a (new) connection.
    ///
    /// The id of the previous connection (if any) is passed as well as a
    /// channel to send the reply.
    NewConn(Option<u64>, ReplySender<Req>),

    /// Shutdown command.
    Shutdown,
}

/// This is the type of sender in [ReqCmd].
type ReplySender<Req> = oneshot::Sender<ChanResp<Req>>;

/// State of the current underlying stream transport.
#[derive(Debug)]
enum SingleConnState3<Req> {
    /// No current stream transport.
    None,

    /// Current stream transport.
    Some(Arc<stream::Connection<Req>>),

    /// State that deals with an error getting a new octet stream from
    /// a connection stream.
    Err(ErrorState),
}

/// State associated with a failed attempt to create a new stream
/// transport.
#[derive(Clone, Debug)]
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

impl<Remote, Req> Transport<Remote, Req> {
    /// Creates a new transport.
    fn new(
        stream: Remote,
        config: Config,
    ) -> (mpsc::Sender<ChanReq<Req>>, Self) {
        let (sender, receiver) = mpsc::channel(DEF_CHAN_CAP);
        (
            sender,
            Self {
                config,
                stream,
                conn_state: SingleConnState3::None,
                conn_id: 0,
                receiver,
            },
        )
    }
}

impl<Remote, Req: ComposeRequest> Transport<Remote, Req>
where
    Remote: AsyncConnect,
    Remote::Connection: AsyncRead + AsyncWrite,
    Req: ComposeRequest,
{
    /// Run the transport machinery.
    pub async fn run(mut self) {
        let mut curr_cmd: Option<ReqCmd<Req>> = None;
        let mut do_stream = false;
        let mut runners = FuturesUnordered::new();
        let mut stream_fut: Pin<
            Box<
                dyn Future<
                        Output = Result<Remote::Connection, std::io::Error>,
                    > + Send,
            >,
        > = Box::pin(stream_nop());
        let mut opt_chan = None;

        loop {
            if let Some(req) = curr_cmd {
                assert!(!do_stream);
                curr_cmd = None;
                match req {
                    ReqCmd::NewConn(opt_id, chan) => {
                        if let SingleConnState3::Err(error_state) =
                            &self.conn_state
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
                            if id >= self.conn_id {
                                // We need a new connection. Remove the
                                // current one. This is the best place to
                                // increment conn_id.
                                self.conn_id += 1;
                                self.conn_state = SingleConnState3::None;
                            }
                        }
                        // If we still have a connection then we can reply
                        // immediately.
                        if let SingleConnState3::Some(conn) = &self.conn_state
                        {
                            let resp = ChanResp::Ok(ChanRespOk {
                                id: self.conn_id,
                                conn: conn.clone(),
                            });
                            // Ignore errors. We don't care if the receiver
                            // is gone
                            _ = chan.send(resp);
                        } else {
                            opt_chan = Some(chan);
                            stream_fut = Box::pin(self.stream.connect());
                            do_stream = true;
                        }
                    }
                    ReqCmd::Shutdown => break,
                }
            }

            if do_stream {
                let runners_empty = runners.is_empty();

                loop {
                    tokio::select! {
                        res_conn = stream_fut.as_mut() => {
                            do_stream = false;
                            stream_fut = Box::pin(stream_nop());

                            let stream = match res_conn {
                                Ok(stream) => stream,
                                Err(error) => {
                                    let error = Arc::new(error);
                                    match self.conn_state {
                                        SingleConnState3::None =>
                                            self.conn_state =
                                            SingleConnState3::Err(ErrorState {
                                                error: error.clone(),
                                                retries: 0,
                                                timer: Instant::now(),
                                                timeout: retry_time(0),
                                            }),
                                        SingleConnState3::Some(_) =>
                                            panic!("Illegal Some state"),
                                        SingleConnState3::Err(error_state) => {
                                            self.conn_state =
                                            SingleConnState3::Err(ErrorState {
                                                error:
                                                    error_state.error.clone(),
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
                            };
                            let (conn, tran) = stream::Connection::with_config(
                                stream, self.config.stream.clone()
                            );
                            let conn = Arc::new(conn);
                            runners.push(Box::pin(tran.run()));

                            let resp = ChanResp::Ok(ChanRespOk {
                                id: self.conn_id,
                                conn: conn.clone(),
                            });
                            self.conn_state = SingleConnState3::Some(conn);

                            let loc_opt_chan = opt_chan.take();

                            // Ignore errors. We don't care if the receiver
                            // is gone
                            _ = loc_opt_chan.expect("weird, no channel?")
                                .send(resp);
                            break;
                        }
                        _ = runners.next(), if !runners_empty => {
                            }
                    }
                }
                continue;
            }

            assert!(curr_cmd.is_none());
            let recv_fut = self.receiver.recv();
            let runners_empty = runners.is_empty();
            tokio::select! {
                msg = recv_fut => {
                    if msg.is_none() {
            // All references to the connection object have been
            // dropped. Shutdown.
                        break;
                    }
                    curr_cmd = Some(msg.expect("None is checked before").cmd);
                }
                _ = runners.next(), if !runners_empty => {
                    }
            }
        }

        // Avoid new queries
        drop(self.receiver);

        // Wait for existing stream runners to terminate
        while !runners.is_empty() {
            runners.next().await;
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

/// Helper function to create an empty future that is compatible with the
/// future returned by a connection stream.
async fn stream_nop<IO>() -> Result<IO, std::io::Error> {
    Err(io::Error::new(io::ErrorKind::Other, "nop"))
}
