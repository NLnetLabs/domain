//! A DNS over datagram transport

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

// To do:
// - cookies

use crate::base::iana::Rcode;
use crate::base::Message;
use crate::net::client::protocol::{
    AsyncConnect, AsyncDgramRecv, AsyncDgramRecvEx, AsyncDgramSend,
    AsyncDgramSendEx,
};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};
use bytes::Bytes;
use core::cmp;
use octseq::Octets;
use std::boxed::Box;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Duration, Instant};

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

//------------ Config ---------------------------------------------------------

/// Configuration for a datagram transport connection.
#[derive(Clone, Debug)]
pub struct Config {
    /// Maximum number of parallel requests for a transport connection.
    max_parallel: usize,

    /// Read timeout.
    read_timeout: Duration,

    /// Maimum number of retries.
    max_retries: u8,

    /// EDNS(0) UDP payload size. Set this value to None to be able to create
    /// a DNS request without ENDS(0) option.
    udp_payload_size: Option<u16>,
}

impl Config {
    /// Creates a new config with default values.
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns the maximum number of parallel requests.
    ///
    /// Once this many number of requests are currently outstanding,
    /// additional requests will wait.
    pub fn max_parallel(&self) -> usize {
        self.max_parallel
    }

    /// Sets the maximum number of parallel requests.
    ///
    /// If this value is too small or too large, it will be caped.
    pub fn set_max_parallel(&mut self, value: usize) {
        self.max_parallel = MAX_PARALLEL.limit(value)
    }

    /// Returns the read timeout.
    ///
    /// The read timeout is the maximum amount of time to wait for any
    /// response after a request was sent.
    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// Sets the read timeout.
    ///
    /// If this value is too small or too large, it will be caped.
    pub fn set_read_timeout(&mut self, value: Duration) {
        self.read_timeout = READ_TIMEOUT.limit(value)
    }

    /// Returns the maximum number a request is retried before giving up.
    pub fn max_retries(&self) -> u8 {
        self.max_retries
    }

    /// Sets the maximum number of request retries.
    ///
    /// If this value is too small or too large, it will be caped.
    pub fn set_max_retries(&mut self, value: u8) {
        self.max_retries = MAX_RETRIES.limit(value)
    }

    /// Returns the UDP payload size.
    ///
    /// See draft-ietf-dnsop-avoid-fragmentation-15 for a discussion.
    pub fn udp_payload_size(&self) -> Option<u16> {
        self.udp_payload_size
    }

    /// Sets the UDP payload size.
    pub fn set_udp_payload_size(&mut self, value: Option<u16>) {
        self.udp_payload_size = value;
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_parallel: MAX_PARALLEL.default(),
            read_timeout: READ_TIMEOUT.default(),
            max_retries: MAX_RETRIES.default(),
            udp_payload_size: Some(DEF_UDP_PAYLOAD_SIZE),
        }
    }
}

//------------ Connection -----------------------------------------------------

/// A datagram transport connection.
#[derive(Clone, Debug)]
pub struct Connection<S> {
    /// Reference to the actual connection object.
    inner: Arc<InnerConnection<S>>,
}

impl<
        S: AsyncConnect<Connection = C> + Clone + Send + Sync + 'static,
        C: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
    > Connection<S>
{
    /// Create a new datagram transport connection.
    pub fn new(config: Option<Config>, connect: S) -> Connection<S> {
        let connection =
            InnerConnection::new(config.unwrap_or_default(), connect);
        Self {
            inner: Arc::new(connection),
        }
    }

    /// Start a new DNS request.
    async fn request_impl<
        CR: ComposeRequest + Clone + Send + Sync + 'static,
    >(
        &self,
        request_msg: &CR,
    ) -> Result<Box<dyn GetResponse + Send>, Error> {
        let gr = self.inner.request(request_msg, self.clone()).await?;
        Ok(Box::new(gr))
    }

    /// Get a permit from the semaphore to start using a socket.
    async fn get_permit(&self) -> OwnedSemaphorePermit {
        self.inner.get_permit().await
    }
}

impl<
        S: AsyncConnect<Connection = C> + Clone + Send + Sync + 'static,
        C: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
        CR: ComposeRequest + Clone + Send + Sync + 'static,
    > SendRequest<CR> for Connection<S>
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
        return Box::pin(self.request_impl(request_msg));
    }
}

//------------ ReqResp --------------------------------------------------------

/// The state of a DNS request.
pub struct ReqResp {
    /// Future that does the actual work of GetResponse.
    get_response_fut:
        Pin<Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send>>,
}

impl ReqResp {
    /// Create new ReqResp object.
    fn new<
        S: AsyncConnect<Connection = C> + Clone + Send + Sync + 'static,
        C: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
        CR: ComposeRequest + Clone + Send + Sync + 'static,
    >(
        config: Config,
        request_msg: &CR,
        conn: Connection<S>,
        udp_payload_size: Option<u16>,
        connect: S,
    ) -> Self {
        Self {
            get_response_fut: Box::pin(Self::get_response_impl2(
                config,
                request_msg.clone(),
                conn,
                udp_payload_size,
                connect,
            )),
        }
    }

    /// Async function that waits for the future stored in Query to complete.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        (&mut self.get_response_fut).await
    }

    /// Get the response of a DNS request.
    ///
    /// This function is not cancel safe.
    async fn get_response_impl2<
        S: AsyncConnect<Connection = C> + Clone + Send + Sync + 'static,
        C: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
        CR: ComposeRequest,
    >(
        config: Config,
        mut request_bmb: CR,
        conn: Connection<S>,
        udp_payload_size: Option<u16>,
        connect: S,
    ) -> Result<Message<Bytes>, Error> {
        let recv_size = 2000; // Should be configurable.

        let mut retries: u8 = 0;

        // We need to get past the semaphore that limits the
        // number of concurrent sockets we can use.
        let _permit = conn.get_permit().await;

        loop {
            let mut sock = connect
                .connect()
                .await
                .map_err(|e| Error::UdpConnect(Arc::new(e)))?;

            // Set random ID in header
            let header = request_bmb.header_mut();
            header.set_random_id();
            // Set UDP payload size
            if let Some(size) = udp_payload_size {
                request_bmb.set_udp_payload_size(size)
            }
            let request_msg = request_bmb.to_message();
            let dgram = request_msg.as_slice();

            let sent = sock
                .send(dgram)
                .await
                .map_err(|e| Error::UdpSend(Arc::new(e)))?;
            if sent != dgram.len() {
                return Err(Error::UdpShortSend);
            }

            let start = Instant::now();

            loop {
                let elapsed = start.elapsed();
                if elapsed > config.read_timeout {
                    // Break out of the receive loop and continue in the
                    // transmit loop.
                    break;
                }
                let remain = config.read_timeout - elapsed;

                let mut buf = vec![0; recv_size]; // XXX use uninit'ed mem here.
                let timeout_res = timeout(remain, sock.recv(&mut buf)).await;
                if timeout_res.is_err() {
                    retries += 1;
                    if retries < config.max_retries {
                        // Break out of the receive loop and continue in the
                        // transmit loop.
                        break;
                    }
                    return Err(Error::UdpTimeoutNoResponse);
                }
                let len = timeout_res
                    .expect("errror case is checked above")
                    .map_err(|e| Error::UdpReceive(Arc::new(e)))?;
                buf.truncate(len);

                // We ignore garbage since there is a timer on this whole
                // thing.
                let answer = match Message::from_octets(buf.into()) {
                    // Just go back to receiving.
                    Ok(answer) => answer,
                    Err(_) => continue,
                };

                if !is_answer(&answer, &request_msg) {
                    // Wrong answer, go back to receiving
                    continue;
                }
                return Ok(answer);
            }
            retries += 1;
            if retries < config.max_retries {
                continue;
            }
            break;
        }
        Err(Error::UdpTimeoutNoResponse)
    }
}

impl Debug for ReqResp {
    fn fmt(&self, _: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        todo!()
    }
}

impl GetResponse for ReqResp {
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_response_impl())
    }
}

//------------ InnerConnection ------------------------------------------------

/// Actual implementation of the datagram transport connection.
#[derive(Debug)]
struct InnerConnection<S> {
    /// User configuration variables.
    config: Config,

    /// Connections to datagram sockets.
    connect: S,

    /// Semaphore to limit access to UDP sockets.
    semaphore: Arc<Semaphore>,
}

impl<
        S: AsyncConnect<Connection = C> + Clone + Send + Sync + 'static,
        C: AsyncDgramRecv + AsyncDgramSend + Send + Sync + Unpin + 'static,
    > InnerConnection<S>
{
    /// Create new InnerConnection object.
    fn new(config: Config, connect: S) -> InnerConnection<S> {
        let max_parallel = config.max_parallel;
        Self {
            config,
            connect,
            semaphore: Arc::new(Semaphore::new(max_parallel)),
        }
    }

    /// Return a Query object that contains the query state.
    async fn request<CR: ComposeRequest + Clone + Send + Sync + 'static>(
        &self,
        request_msg: &CR,
        conn: Connection<S>,
    ) -> Result<ReqResp, Error> {
        Ok(ReqResp::new(
            self.config.clone(),
            request_msg,
            conn,
            self.config.udp_payload_size,
            self.connect.clone(),
        ))
    }

    /// Return a permit for a our semaphore.
    async fn get_permit(&self) -> OwnedSemaphorePermit {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore has not been closed")
    }
}

//------------ Utility --------------------------------------------------------

/// Check if a message is a valid reply for a query. Allow the question section
/// to be empty if there is an error or if the reply is truncated.
fn is_answer<
    QueryOcts: AsRef<[u8]> + Octets,
    ReplyOcts: AsRef<[u8]> + Octets,
>(
    reply: &Message<ReplyOcts>,
    query: &Message<QueryOcts>,
) -> bool {
    let reply_header = reply.header();
    let reply_hcounts = reply.header_counts();

    // First check qr and id
    if !reply_header.qr() || reply_header.id() != query.header().id() {
        return false;
    }

    // If either tc is set or the result is an error, then the question
    // section can be empty. In that case we require all other sections
    // to be empty as well.
    if (reply_header.tc() || reply_header.rcode() != Rcode::NoError)
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

//------------ DefMinMax -----------------------------------------------------

#[derive(Clone, Copy)]
struct DefMinMax<T> {
    def: T,
    min: T,
    max: T,
}

impl<T> DefMinMax<T> {
    const fn new(def: T, min: T, max: T) -> Self {
        Self { def, min, max }
    }

    fn default(self) -> T {
        self.def
    }

    fn limit(self, value: T) -> T
    where
        T: Ord,
    {
        cmp::max(self.min, cmp::min(self.max, value))
    }
}
