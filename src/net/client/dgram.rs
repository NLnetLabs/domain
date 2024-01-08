//! A client over datagram protocols.
//!
//! This module implements a DNS client for use with datagram protocols, i.e.,
//! message-oriented, connection-less, unreliable network protocols. In
//! practice, this is pretty much exclusively UDP.

#![warn(missing_docs)]

// To do:
// - cookies

use crate::base::Message;
use crate::net::client::protocol::{
    AsyncConnect, AsyncDgramRecv, AsyncDgramRecvEx, AsyncDgramSend,
    AsyncDgramSendEx,
};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, HandleRequest, SendRequest,
};
use bytes::Bytes;
use core::{cmp, fmt};
use futures_util::FutureExt;
use octseq::OctetsInto;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::{error, io};
use tokio::sync::{Semaphore, TryAcquireError};
use tokio::time::{timeout_at, Duration, Instant};

//------------ Configuration Constants ----------------------------------------

/// Configuration limits for the maximum number of parallel requests.
const MAX_PARALLEL: DefMinMax<usize> = DefMinMax::new(100, 1, 1000);

/// Configuration limits for the read timeout.
const READ_TIMEOUT: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(5),
    Duration::from_millis(1),
    Duration::from_secs(60),
);

/// Configuration limits for the maximum number of retries.
const MAX_RETRIES: DefMinMax<u8> = DefMinMax::new(5, 1, 100);

/// Default UDP payload size.
const DEF_UDP_PAYLOAD_SIZE: u16 = 1232;

/// The default receive buffer size.
const DEF_RECV_SIZE: usize = 2000;

//------------ Config ---------------------------------------------------------

/// Configuration of a datagram transport.
#[derive(Clone, Debug)]
pub struct Config {
    /// Maximum number of parallel requests for a transport connection.
    max_parallel: usize,

    /// Read timeout.
    read_timeout: Duration,

    /// Maximum number of retries.
    max_retries: u8,

    /// EDNS UDP payload size.
    ///
    /// If this is `None`, no OPT record will be included at all.
    udp_payload_size: Option<u16>,

    /// Receive buffer size.
    recv_size: usize,
}

impl Config {
    /// Creates a new config with default values.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the maximum number of parallel requests.
    ///
    /// Once this many number of requests are currently outstanding,
    /// additional requests will wait.
    ///
    /// If this value is too small or too large, it will be caped.
    pub fn set_max_parallel(&mut self, value: usize) {
        self.max_parallel = MAX_PARALLEL.limit(value)
    }

    /// Returns the maximum number of parallel requests.
    pub fn max_parallel(&self) -> usize {
        self.max_parallel
    }

    /// Sets the read timeout.
    ///
    /// The read timeout is the maximum amount of time to wait for any
    /// response after a request was sent.
    ///
    /// If this value is too small or too large, it will be caped.
    pub fn set_read_timeout(&mut self, value: Duration) {
        self.read_timeout = READ_TIMEOUT.limit(value)
    }

    /// Returns the read timeout.
    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// Sets the maximum number a request is retried before giving up.
    ///
    /// If this value is too small or too large, it will be caped.
    pub fn set_max_retries(&mut self, value: u8) {
        self.max_retries = MAX_RETRIES.limit(value)
    }

    /// Returns the maximum number of request retries.
    pub fn max_retries(&self) -> u8 {
        self.max_retries
    }

    /// Sets the requested UDP payload size.
    ///
    /// This value indicates to the server the maximum size of a UDP packet.
    /// For UDP on public networks, this value should be left at the default
    /// of 1232 to avoid issues rising from packet fragmentation. See
    /// [draft-ietf-dnsop-avoid-fragmentation] for a discussion on these
    /// issues and recommendations.
    ///
    /// On private networks or protocols other than UDP, other values can be
    /// used.
    ///
    /// Setting the UDP payload size to `None` currently results in messages
    /// that will not include an OPT record.
    ///
    /// [draft-ietf-dnsop-avoid-fragmentation]: https://datatracker.ietf.org/doc/draft-ietf-dnsop-avoid-fragmentation/
    pub fn set_udp_payload_size(&mut self, value: Option<u16>) {
        self.udp_payload_size = value;
    }

    /// Returns the UDP payload size.
    pub fn udp_payload_size(&self) -> Option<u16> {
        self.udp_payload_size
    }

    /// Sets the receive buffer size.
    ///
    /// This is the amount of memory that is allocated for receiving a
    /// response.
    pub fn set_recv_size(&mut self, size: usize) {
        self.recv_size = size
    }

    /// Returns the receive buffer size.
    pub fn recv_size(&self) -> usize {
        self.recv_size
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_parallel: MAX_PARALLEL.default(),
            read_timeout: READ_TIMEOUT.default(),
            max_retries: MAX_RETRIES.default(),
            udp_payload_size: Some(DEF_UDP_PAYLOAD_SIZE),
            recv_size: DEF_RECV_SIZE,
        }
    }
}

//------------ Connection -----------------------------------------------------

/// A datagram protocol connection.
///
/// Because it owns the connection’s resources, this type is not `Clone`.
/// However, it is entirely safe to share it by sticking it into e.g. an arc.
#[derive(Debug)]
pub struct Connection<S> {
    /// User configuration variables.
    config: Config,

    /// Connections to datagram sockets.
    connect: S,

    /// Semaphore to limit access to UDP sockets.
    semaphore: Semaphore,
}

impl<S> Connection<S> {
    /// Create a new datagram transport with default configuration.
    pub fn new(connect: S) -> Connection<S> {
        Self::with_config(connect, Default::default())
    }

    /// Create a new datagram transport with a given configuration.
    pub fn with_config(connect: S, config: Config) -> Connection<S> {
        Self {
            semaphore: Semaphore::new(config.max_parallel),
            config,
            connect,
        }
    }
}

impl<S> Connection<S>
where
    S: AsyncConnect,
    S::Connection: AsyncDgramRecv + AsyncDgramSend + Unpin,
{
    /// Performs a query.
    ///
    /// Sends the provided and returns either a response or an error. If there
    /// are currently too many active queries, the future will wait until the
    /// number has dropped below the limit.
    pub async fn query<Req: ComposeRequest>(
        &self,
        request: Req,
    ) -> Result<Message<Bytes>, QueryError> {
        let _ = self.semaphore.acquire().await.expect("semaphore closed");
        self.query_unchecked(request).await
    }

    /// Tries to perform a query.
    ///
    /// This is essentially the same as [`request`][Self::query] but returns
    /// an error immediately if there are currently too many active queries.
    pub async fn try_query<Req: ComposeRequest>(
        &self,
        request: Req,
    ) -> Result<Message<Bytes>, TryQueryError<Req>> {
        let _ = match self.semaphore.try_acquire() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                return Err(TryQueryError::TooManyQueries(request))
            }
            Err(TryAcquireError::Closed) => panic!("semaphore closed"),
        };
        self.query_unchecked(request)
            .await
            .map_err(TryQueryError::Query)
    }

    /// Performs a query without acquiring the semaphore.
    async fn query_unchecked<Req: ComposeRequest>(
        &self,
        mut request: Req,
    ) -> Result<Message<Bytes>, QueryError> {
        // A place to store the receive buffer for reuse.
        let mut reuse_buf = None;

        // Transmit loop.
        for _ in 0..self.config.max_retries {
            let mut sock =
                self.connect.connect().await.map_err(QueryError::connect)?;

            // Set random ID in header
            request.header_mut().set_random_id();

            // Set UDP payload size if necessary.
            if let Some(size) = self.config.udp_payload_size {
                request.set_udp_payload_size(size)
            }

            // Create the message and send it out.
            let request_msg = request.to_message();
            let dgram = request_msg.as_slice();
            let sent = sock.send(dgram).await.map_err(QueryError::send)?;
            if sent != dgram.len() {
                return Err(QueryError::short_send());
            }

            // Receive loop. It may at most take read_timeout time.
            let deadline = Instant::now() + self.config.read_timeout;
            while deadline > Instant::now() {
                let mut buf = reuse_buf.take().unwrap_or_else(|| {
                    // XXX use uninit'ed mem here.
                    vec![0; self.config.recv_size]
                });
                let len =
                    match timeout_at(deadline, sock.recv(&mut buf)).await {
                        Ok(Ok(len)) => len,
                        Ok(Err(err)) => {
                            // Receiving failed.
                            return Err(QueryError::receive(err));
                        }
                        Err(_) => {
                            // Timeout.
                            break;
                        }
                    };
                buf.truncate(len);

                // We ignore garbage since there is a timer on this whole
                // thing.
                let answer = match Message::try_from_octets(buf) {
                    Ok(answer) => answer,
                    Err(buf) => {
                        // Just go back to receiving.
                        reuse_buf = Some(buf);
                        continue;
                    }
                };

                if !request.is_answer(answer.for_slice()) {
                    // Wrong answer, go back to receiving
                    reuse_buf = Some(answer.into_octets());
                    continue;
                }
                return Ok(answer.octets_into());
            }
        }
        Err(QueryError::timeout())
    }
}

impl<S> Connection<S>
where
    S: AsyncConnect + Clone + Send + Sync + 'static,
    S::Connection:
        AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
{
    /// Start a new DNS request.
    async fn request_impl<
        CR: ComposeRequest + Clone + Send + Sync + 'static,
    >(
        self: Arc<Self>,
        request_msg: CR,
    ) -> Result<Box<dyn GetResponse + Send>, Error> {
        Ok(Box::new(Query {
            get_response_fut: async move {
                self.query(request_msg).await.map_err(Into::into)
            }
            .boxed(),
        }))
    }
}

//--- SendRequest and HandleRequest

impl<S, Req> SendRequest<Req> for Arc<Connection<S>>
where
    S: AsyncConnect + Clone + Send + Sync + 'static,
    S::Connection:
        AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
    Req: ComposeRequest + Clone + Send + Sync + 'static,
{
    fn send_request<'a>(
        &'a self,
        request_msg: &'a Req,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn GetResponse + Send>, Error>>
                + Send
                + '_,
        >,
    > {
        let this = self.clone();
        Box::pin(this.request_impl(request_msg.clone()))
    }
}

impl<S, Req> HandleRequest<Req> for Connection<S>
where
    S: AsyncConnect + Clone + Send + Sync + 'static,
    S::Connection:
        AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
    Req: ComposeRequest + Clone + Send + Sync + 'static,
{
    type Response = Message<Bytes>;
    type Error = Error;
    type Fut<'s> = Pin<Box<
        dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 's
    >> where Self: 's;

    fn handle_request(&self, request: Req) -> Self::Fut<'_> {
        async { self.query(request).await.map_err(Into::into) }.boxed()
    }
}

//------------ Query --------------------------------------------------------

/// The state of a DNS request.
pub struct Query {
    /// Future that does the actual work of GetResponse.
    get_response_fut:
        Pin<Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send>>,
}

impl Query {
    /// Async function that waits for the future stored in Query to complete.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        (&mut self.get_response_fut).await
    }
}

impl fmt::Debug for Query {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        todo!()
    }
}

impl GetResponse for Query {
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_response_impl())
    }
}

//------------ DefMinMax -----------------------------------------------------

/// The default, minimum, and maximum values for a config variable.
#[derive(Clone, Copy)]
struct DefMinMax<T> {
    /// The default value,
    def: T,

    /// The minimum value,
    min: T,

    /// The maximum value,
    max: T,
}

impl<T> DefMinMax<T> {
    /// Creates a new value.
    const fn new(def: T, min: T, max: T) -> Self {
        Self { def, min, max }
    }

    /// Returns the default value.
    fn default(self) -> T {
        self.def
    }

    /// Trims the given value to fit into the minimum/maximum range.
    fn limit(self, value: T) -> T
    where
        T: Ord,
    {
        cmp::max(self.min, cmp::min(self.max, value))
    }
}

//============ Errors ========================================================

//------------ QueryError ----------------------------------------------------

/// A query failed.
#[derive(Debug)]
pub struct QueryError {
    /// Which step failed?
    kind: QueryErrorKind,

    /// The underlying IO error.
    io: std::io::Error,
}

impl QueryError {
    fn new(kind: QueryErrorKind, io: io::Error) -> Self {
        Self { kind, io }
    }

    fn connect(io: io::Error) -> Self {
        Self::new(QueryErrorKind::Connect, io)
    }

    fn send(io: io::Error) -> Self {
        Self::new(QueryErrorKind::Send, io)
    }

    fn short_send() -> Self {
        Self::new(
            QueryErrorKind::Send,
            io::Error::new(io::ErrorKind::Other, "short request sent"),
        )
    }

    fn timeout() -> Self {
        Self::new(
            QueryErrorKind::Timeout,
            io::Error::new(io::ErrorKind::TimedOut, "timeout expired"),
        )
    }

    fn receive(io: io::Error) -> Self {
        Self::new(QueryErrorKind::Receive, io)
    }
}

impl QueryError {
    /// Returns information about when the query has failed.
    pub fn kind(&self) -> QueryErrorKind {
        self.kind
    }

    /// Converts the query error into the underlying IO error.
    pub fn io_error(self) -> std::io::Error {
        self.io
    }
}

impl From<QueryError> for std::io::Error {
    fn from(err: QueryError) -> std::io::Error {
        err.io
    }
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}: {}", self.kind.error_str(), self.io)
    }
}

impl error::Error for QueryError {}

//------------ QueryErrorKind ------------------------------------------------

/// Which part of processing the query failed?
#[derive(Copy, Clone, Debug)]
pub enum QueryErrorKind {
    /// Failed to connect to the remote.
    Connect,

    /// Failed to send the request.
    Send,

    /// The request has timed out.
    Timeout,

    /// Failed to read the response.
    Receive,
}

impl QueryErrorKind {
    /// Returns the string to be used when displaying a query error.
    fn error_str(self) -> &'static str {
        match self {
            Self::Connect => "connecting failed",
            Self::Send => "sending request failed",
            Self::Timeout | Self::Receive => "reading response failed",
        }
    }
}

impl fmt::Display for QueryErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Connect => "connecting failed",
            Self::Send => "sending request failed",
            Self::Timeout => "request timeout",
            Self::Receive => "reading response failed",
        })
    }
}

//------------ TryQueryError -------------------------------------------------

/// An attempted query failed
///
/// This error is returned by [`Connection::try_query`].
pub enum TryQueryError<Req> {
    /// The query has failed with the given error.
    Query(QueryError),

    /// There were too many active queries.
    ///
    /// This variant contains the original request unchanged.
    TooManyQueries(Req),
}

impl<Req> fmt::Debug for TryQueryError<Req> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Query(err) => {
                f.debug_tuple("TryQueryError::Query").field(err).finish()
            }
            Self::TooManyQueries(_) => f
                .debug_tuple("TryQueryError::Req")
                .field(&format_args!("_"))
                .finish(),
        }
    }
}

impl<Req> fmt::Display for TryQueryError<Req> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Query(error) => error.fmt(f),
            Self::TooManyQueries(_) => {
                f.write_str("too many active requests")
            }
        }
    }
}

impl<Req> error::Error for TryQueryError<Req> {}
