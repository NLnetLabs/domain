//! A DNS over datagram transport

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

// To do:
// - cookies

use bytes::Bytes;
use octseq::Octets;
use std::boxed::Box;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Duration, Instant};

use crate::base::iana::Rcode;
use crate::base::Message;
use crate::net::client::protocol::{
    AsyncConnect, AsyncDgramRecv, AsyncDgramSend,
};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};

/// Default configuration value for the maximum number of parallel DNS query
/// over a single datagram transport connection.
const DEF_MAX_PARALLEL: usize = 100;

/// Minimum configuration value for max_parallel.
const MIN_MAX_PARALLEL: usize = 1;

/// Maximum configuration value for max_parallel.
const MAX_MAX_PARALLEL: usize = 1000;

/// Default configuration value for the maximum amount of time to wait for a
/// reply.
const DEF_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum configuration value for read_timeout.
const MIN_READ_TIMEOUT: Duration = Duration::from_millis(1);

/// Maximum configuration value for read_timeout.
const MAX_READ_TIMEOUT: Duration = Duration::from_secs(60);

/// Default configuration value for maximum number of retries after timeouts.
const DEF_MAX_RETRIES: u8 = 5;

/// Minimum allowed configuration value for max_retries.
const MIN_MAX_RETRIES: u8 = 1;

/// Maximum allowed configuration value for max_retries.
const MAX_MAX_RETRIES: u8 = 100;

/// Default UDP payload size. See draft-ietf-dnsop-avoid-fragmentation-15
/// for discussion.
const DEF_UDP_PAYLOAD_SIZE: u16 = 1232;

//------------ Config ---------------------------------------------------------

/// Configuration for a datagram transport connection.
#[derive(Clone, Debug)]
pub struct Config {
    /// Maximum number of parallel requests for a transport connection.
    pub max_parallel: usize,

    /// Read timeout.
    pub read_timeout: Duration,

    /// Maimum number of retries.
    pub max_retries: u8,

    /// EDNS(0) UDP payload size. Set this value to None to be able to create
    /// a DNS request without ENDS(0) option.
    pub udp_payload_size: Option<u16>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_parallel: DEF_MAX_PARALLEL,
            read_timeout: DEF_READ_TIMEOUT,
            max_retries: DEF_MAX_RETRIES,
            udp_payload_size: Some(DEF_UDP_PAYLOAD_SIZE),
        }
    }
}

//------------ Connection -----------------------------------------------------

/// A datagram transport connection.
#[derive(Clone, Debug)]
pub struct Connection<S: AsyncConnect + Clone + Sync> {
    /// Reference to the actual connection object.
    inner: Arc<InnerConnection<S>>,
}

impl<
        S: AsyncConnect<Connection = C> + Clone + Send + Sync + 'static,
        C: AsyncDgramRecv + AsyncDgramSend + Send + Sync + 'static,
    > Connection<S>
{
    /// Create a new datagram transport connection.
    pub fn new(
        config: Option<Config>,
        connect: S,
    ) -> Result<Connection<S>, Error> {
        let config = match config {
            Some(config) => {
                check_config(&config)?;
                config
            }
            None => Default::default(),
        };
        let connection = InnerConnection::new(config, connect)?;
        Ok(Self {
            inner: Arc::new(connection),
        })
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
        C: AsyncDgramRecv + AsyncDgramSend + Send + Sync + 'static,
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
        C: AsyncDgramRecv + AsyncDgramSend + Send + Sync + 'static,
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
        C: AsyncDgramRecv + AsyncDgramSend + Send + Sync + 'static,
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
            let sock = connect
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

                let buf = vec![0; recv_size]; // XXX use uninit'ed mem here.
                let timeout_res = timeout(remain, sock.recv(buf)).await;
                if timeout_res.is_err() {
                    retries += 1;
                    if retries < config.max_retries {
                        // Break out of the receive loop and continue in the
                        // transmit loop.
                        break;
                    }
                    return Err(Error::UdpTimeoutNoResponse);
                }
                let buf = timeout_res
                    .expect("errror case is checked above")
                    .map_err(|e| Error::UdpReceive(Arc::new(e)))?;

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
struct InnerConnection<S: AsyncConnect> {
    /// User configuration variables.
    config: Config,

    /// Connections to datagram sockets.
    connect: S,

    /// Semaphore to limit access to UDP sockets.
    semaphore: Arc<Semaphore>,
}

impl<
        S: AsyncConnect<Connection = C> + Clone + Send + Sync + 'static,
        C: AsyncDgramRecv + AsyncDgramSend + Send + Sync + 'static,
    > InnerConnection<S>
{
    /// Create new InnerConnection object.
    fn new(config: Config, connect: S) -> Result<InnerConnection<S>, Error> {
        let max_parallel = config.max_parallel;
        Ok(Self {
            config,
            connect,
            semaphore: Arc::new(Semaphore::new(max_parallel)),
        })
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

/// Check if config is valid.
fn check_config(config: &Config) -> Result<(), Error> {
    if config.max_parallel < MIN_MAX_PARALLEL
        || config.max_parallel > MAX_MAX_PARALLEL
    {
        return Err(Error::UdpConfigError(Arc::new(std::io::Error::new(
            ErrorKind::Other,
            "max_parallel",
        ))));
    }

    if config.read_timeout < MIN_READ_TIMEOUT
        || config.read_timeout > MAX_READ_TIMEOUT
    {
        return Err(Error::UdpConfigError(Arc::new(std::io::Error::new(
            ErrorKind::Other,
            "read_timeout",
        ))));
    }

    if config.max_retries < MIN_MAX_RETRIES
        || config.max_retries > MAX_MAX_RETRIES
    {
        return Err(Error::UdpConfigError(Arc::new(std::io::Error::new(
            ErrorKind::Other,
            "max_retries",
        ))));
    }
    Ok(())
}

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
