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
    ComposeRequest, Error, GetResponse, SendRequest,
};
use crate::utils::config::DefMinMax;
use bytes::Bytes;
use core::fmt;
use octseq::OctetsInto;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;
use std::{error, io};
use tokio::sync::Semaphore;
use tokio::time::{timeout_at, Duration, Instant};
use tracing::trace;

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
const MAX_RETRIES: DefMinMax<u8> = DefMinMax::new(5, 0, 100);

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
    /// If this value is too small or too large, it will be capped.
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
    /// If this value is too small or too large, it will be capped.
    pub fn set_read_timeout(&mut self, value: Duration) {
        self.read_timeout = READ_TIMEOUT.limit(value)
    }

    /// Returns the read timeout.
    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// Sets the maximum number of times a request is retried before giving
    /// up.
    ///
    /// If this value is too small or too large, it will be capped.
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
#[derive(Clone, Debug)]
pub struct Connection<S> {
    /// Actual state of the connection.
    state: Arc<ConnectionState<S>>,
}

/// Because it owns the connection’s resources, this type is not [`Clone`].
/// However, it is entirely safe to share it by sticking it into e.g. an arc.
#[derive(Debug)]
struct ConnectionState<S> {
    /// User configuration variables.
    config: Config,

    /// Connections to datagram sockets.
    connect: S,

    /// Semaphore to limit access to UDP sockets.
    semaphore: Semaphore,
}

impl<S> Connection<S> {
    /// Create a new datagram transport with default configuration.
    pub fn new(connect: S) -> Self {
        Self::with_config(connect, Default::default())
    }

    /// Create a new datagram transport with a given configuration.
    pub fn with_config(connect: S, config: Config) -> Self {
        Self {
            state: Arc::new(ConnectionState {
                semaphore: Semaphore::new(config.max_parallel),
                config,
                connect,
            }),
        }
    }
}

impl<S> Connection<S>
where
    S: AsyncConnect,
    S::Connection: AsyncDgramRecv + AsyncDgramSend + Unpin,
{
    /// Performs a request.
    ///
    /// Sends the provided and returns either a response or an error. If there
    /// are currently too many active queries, the future will wait until the
    /// number has dropped below the limit.
    async fn handle_request_impl<Req: ComposeRequest>(
        self,
        mut request: Req,
    ) -> Result<Message<Bytes>, Error> {
        // Acquire the semaphore or wait for it.
        let _permit = self
            .state
            .semaphore
            .acquire()
            .await
            .expect("semaphore closed");

        // The buffer we will reuse on subsequent requests
        let mut buf = Vec::new();

        // Transmit loop.
        for _ in 0..1 + self.state.config.max_retries {
            let mut sock = self
                .state
                .connect
                .connect()
                .await
                .map_err(QueryError::connect)?;

            // Set random ID in header
            request.header_mut().set_random_id();

            // Set UDP payload size if necessary.
            if let Some(size) = self.state.config.udp_payload_size {
                request.set_udp_payload_size(size)
            }

            // Create the message and send it out.
            let request_msg = request.to_message()?;
            let dgram = request_msg.as_slice();
            let sent = sock.send(dgram).await.map_err(QueryError::send)?;
            if sent != dgram.len() {
                return Err(QueryError::short_send().into());
            }

            // Receive loop. It may at most take read_timeout time.
            let deadline = Instant::now() + self.state.config.read_timeout;
            while deadline > Instant::now() {
                // The buffer might have been truncated in a previous
                // iteration.
                buf.resize(self.state.config.recv_size, 0);

                let len =
                    match timeout_at(deadline, sock.recv(&mut buf)).await {
                        Ok(Ok(len)) => len,
                        Ok(Err(err)) => {
                            // Receiving failed.
                            return Err(QueryError::receive(err).into());
                        }
                        Err(_) => {
                            // Timeout.
                            trace!("Receive timed out");
                            break;
                        }
                    };

                trace!("Received {len} bytes of message");
                buf.truncate(len);

                // We ignore garbage since there is a timer on this whole
                // thing.
                let answer = match Message::try_from_octets(buf) {
                    Ok(answer) => answer,
                    Err(old_buf) => {
                        // Just go back to receiving.
                        trace!("Received bytes were garbage, reading more");
                        buf = old_buf;
                        continue;
                    }
                };

                if !request.is_answer(answer.for_slice()) {
                    // Wrong answer, go back to receiving
                    trace!("Received message is not the answer we were waiting for, reading more");
                    buf = answer.into_octets();
                    continue;
                }

                trace!("Received message is accepted");
                return Ok(answer.octets_into());
            }
        }
        Err(QueryError::timeout().into())
    }
}

//--- SendRequest

impl<S, Req> SendRequest<Req> for Connection<S>
where
    S: AsyncConnect + Clone + Send + Sync + 'static,
    S::Connection:
        AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
    Req: ComposeRequest + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: Req,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(Request {
            fut: Box::pin(self.clone().handle_request_impl(request_msg)),
        })
    }
}

//------------ Request ------------------------------------------------------

/// The state of a DNS request.
pub struct Request {
    /// Future that does the actual work of GetResponse.
    fut: Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + Sync>,
    >,
}

impl Request {
    /// Async function that waits for the future stored in Request to complete.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        (&mut self.fut).await
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        todo!()
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
    /// Create a new `QueryError`.
    fn new(kind: QueryErrorKind, io: io::Error) -> Self {
        Self { kind, io }
    }

    /// Create a new connect error.
    fn connect(io: io::Error) -> Self {
        Self::new(QueryErrorKind::Connect, io)
    }

    /// Create a new send error.
    fn send(io: io::Error) -> Self {
        Self::new(QueryErrorKind::Send, io)
    }

    /// Create a new short send error.
    fn short_send() -> Self {
        Self::new(
            QueryErrorKind::Send,
            io::Error::other("short request sent"),
        )
    }

    /// Create a new timeout error.
    fn timeout() -> Self {
        Self::new(
            QueryErrorKind::Timeout,
            io::Error::new(io::ErrorKind::TimedOut, "timeout expired"),
        )
    }

    /// Create a new receive error.
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Connect => "connecting failed",
            Self::Send => "sending request failed",
            Self::Timeout => "request timeout",
            Self::Receive => "reading response failed",
        })
    }
}
