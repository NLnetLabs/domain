//! A DNS over UDP transport

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

// To do:
// - cookies
// - random port

use bytes::Bytes;
use octseq::Octets;
use std::boxed::Box;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Duration, Instant};

use crate::base::iana::Rcode;
use crate::base::Message;
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, Request,
};

/// How many times do we try a new random port if we get ‘address in use.’
const RETRY_RANDOM_PORT: usize = 10;

/// Default configuration value for the maximum number of parallel DNS query
/// over a single UDP transport connection.
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

/// Configuration for a UDP transport connection.
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

/// A UDP transport connection.
#[derive(Clone, Debug)]
pub struct Connection {
    /// Reference to the actual connection object.
    inner: Arc<InnerConnection>,
}

impl Connection {
    /// Create a new UDP transport connection.
    pub fn new(
        config: Option<Config>,
        remote_addr: SocketAddr,
    ) -> Result<Connection, Error> {
        let config = match config {
            Some(config) => {
                check_config(&config)?;
                config
            }
            None => Default::default(),
        };
        let connection = InnerConnection::new(config, remote_addr)?;
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

impl<CR: ComposeRequest + Clone + Send + Sync + 'static> Request<CR>
    for Connection
{
    fn request<'a>(
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

//------------ Query ----------------------------------------------------------

/*

/// State of the DNS query.
#[derive(Debug)]
enum QueryState {
    /// Get a semaphore permit.
    GetPermit(Connection),

    /// Get a UDP socket.
    GetSocket,

    /// Connect the socket.
    Connect,

    /// Send the request.
    Send,

    /// Receive the reply.
    Receive(Instant),
}
*/

/*

/// The state of a DNS query.
#[derive(Debug)]
pub struct Query {
    /// Address of remote server to connect to.
    remote_addr: SocketAddr,

    /// DNS request message.
    query_msg: Message<BytesMut>,

    /// Semaphore permit that allow use of socket.
    _permit: Option<OwnedSemaphorePermit>,

    /// UDP socket for communication.
    sock: Option<UdpSocket>,

    /// Current number of retries.
    retries: u8,

    /// State of query.
    state: QueryState,
}

impl Query {
    /// Create new Query object.
    fn new(
        query_msg: Message<BytesMut>,
        remote_addr: SocketAddr,
        conn: Connection,
    ) -> Query {
        Query {
            query_msg,
            remote_addr,
            _permit: None,
            sock: None,
            retries: 0,
            state: QueryState::GetPermit(conn),
        }
    }

    /// Get the result of a DNS Query.
    ///
    /// This function is cancel safe.
    async fn get_result_impl(&mut self) -> Result<Message<Bytes>, Error> {
        let recv_size = 2000; // Should be configurable.

        loop {
            match &self.state {
                QueryState::GetPermit(conn) => {
                    // We need to get past the semaphore that limits the
                    // number of concurrent sockets we can use.
                    let permit = conn.get_permit().await;
                    self._permit = Some(permit);
                    self.state = QueryState::GetSocket;
                    continue;
                }
                QueryState::GetSocket => {
                    self.sock = Some(
                        Self::udp_bind(self.remote_addr.is_ipv4()).await?,
                    );
                    self.state = QueryState::Connect;
                    continue;
                }
                QueryState::Connect => {
                    self.sock
                        .as_ref()
                        .expect("socket should be present")
                        .connect(self.remote_addr)
                        .await
                        .map_err(|e| Error::UdpConnect(Arc::new(e)))?;
                    self.state = QueryState::Send;
                    continue;
                }
                QueryState::Send => {
                    // Set random ID in header
                    let header = self.query_msg.header_mut();
                    header.set_random_id();
                    let dgram = self.query_msg.as_slice();

                    let sent = self
                        .sock
                        .as_ref()
                        .expect("socket should be present")
                        .send(dgram)
                        .await
                        .map_err(|e| Error::UdpSend(Arc::new(e)))?;
                    if sent != self.query_msg.as_slice().len() {
                        return Err(Error::UdpShortSend);
                    }
                    self.state = QueryState::Receive(Instant::now());
                    continue;
                }
                QueryState::Receive(start) => {
                    let elapsed = start.elapsed();
                    if elapsed > READ_TIMEOUT {
                        todo!();
                    }
                    let remain = READ_TIMEOUT - elapsed;

                    let mut buf = vec![0; recv_size]; // XXX use uninit'ed mem here.
                    let timeout_res = timeout(
                        remain,
                        self.sock
                            .as_ref()
                            .expect("socket should be present")
                            .recv(&mut buf),
                    )
                    .await;
                    if timeout_res.is_err() {
                        self.retries += 1;
                        if self.retries < MAX_RETRIES {
                            self.sock = None;
                            self.state = QueryState::GetSocket;
                            continue;
                        }
                        return Err(Error::UdpTimeoutNoResponse);
                    }
                    let len = timeout_res
                        .expect("errror case is checked above")
                        .map_err(|e| Error::UdpReceive(Arc::new(e)))?;
                    buf.truncate(len);

                    // We ignore garbage since there is a timer on this whole thing.
                    let answer = match Message::from_octets(buf.into()) {
                        Ok(answer) => answer,
                        Err(_) => continue,
                    };

                    // Unfortunately we cannot pass query_msg to is_answer
                    // because is_answer requires Octets, which is not
                    // implemented by BytesMut. Make a copy.
                    let query_msg = Message::from_octets(
                        self.query_msg.as_slice(),
                    )
                    .expect(
                        "Message failed to parse contents of another Message",
                    );
                    if !is_answer(answer, &query_msg) {
                        continue;
                    }
                    self.sock = None;
                    self._permit = None;
                    return Ok(answer);
                }
            }
        }
    }

    /// Bind to a local UDP port.
    ///
    /// This should explicitly pick a random number in a suitable range of
    /// ports.
    async fn udp_bind(v4: bool) -> Result<UdpSocket, Error> {
        let mut i = 0;
        loop {
            let local: SocketAddr = if v4 {
                ([0u8; 4], 0).into()
            } else {
                ([0u16; 8], 0).into()
            };
            match UdpSocket::bind(&local).await {
                Ok(sock) => return Ok(sock),
                Err(err) => {
                    if i == RETRY_RANDOM_PORT {
                        return Err(Error::UdpBind(Arc::new(err)));
                    } else {
                        i += 1
                    }
                }
            }
        }
    }
}

impl GetResult for Query {
    fn get_result(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_result_impl())
    }
}

*/

//------------ ReqResp --------------------------------------------------------

/// The state of a DNS request.
pub struct ReqResp {
    /// Future that does the actual work of GetResponse.
    get_response_fut:
        Pin<Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send>>,
}

impl ReqResp {
    /// Create new ReqResp object.
    fn new<CR: ComposeRequest + Clone + Send + Sync + 'static>(
        config: Config,
        request_msg: &CR,
        remote_addr: SocketAddr,
        conn: Connection,
        udp_payload_size: Option<u16>,
    ) -> Self {
        Self {
            get_response_fut: Box::pin(Self::get_response_impl2(
                config,
                request_msg.clone(),
                remote_addr,
                conn,
                udp_payload_size,
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
    async fn get_response_impl2<CR: ComposeRequest>(
        config: Config,
        mut request_bmb: CR,
        remote_addr: SocketAddr,
        conn: Connection,
        udp_payload_size: Option<u16>,
    ) -> Result<Message<Bytes>, Error> {
        let recv_size = 2000; // Should be configurable.

        let mut retries: u8 = 0;

        // We need to get past the semaphore that limits the
        // number of concurrent sockets we can use.
        let _permit = conn.get_permit().await;

        loop {
            let sock = Some(Self::udp_bind(remote_addr.is_ipv4()).await?);

            sock.as_ref()
                .expect("socket should be present")
                .connect(remote_addr)
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
                .as_ref()
                .expect("socket should be present")
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
                let timeout_res = timeout(
                    remain,
                    sock.as_ref()
                        .expect("socket should be present")
                        .recv(&mut buf),
                )
                .await;
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

    /// Bind to a local UDP port.
    ///
    /// This should explicitly pick a random number in a suitable range of
    /// ports.
    async fn udp_bind(v4: bool) -> Result<UdpSocket, Error> {
        let mut i = 0;
        loop {
            let local: SocketAddr = if v4 {
                ([0u8; 4], 0).into()
            } else {
                ([0u16; 8], 0).into()
            };
            match UdpSocket::bind(&local).await {
                Ok(sock) => return Ok(sock),
                Err(err) => {
                    if i == RETRY_RANDOM_PORT {
                        return Err(Error::UdpBind(Arc::new(err)));
                    } else {
                        i += 1
                    }
                }
            }
        }
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

/// Actual implementation of the UDP transport connection.
#[derive(Debug)]
struct InnerConnection {
    /// User configuration variables.
    config: Config,

    /// Address of the remote server.
    remote_addr: SocketAddr,

    /// Semaphore to limit access to UDP sockets.
    semaphore: Arc<Semaphore>,
}

impl InnerConnection {
    /// Create new InnerConnection object.
    fn new(
        config: Config,
        remote_addr: SocketAddr,
    ) -> Result<InnerConnection, Error> {
        let max_parallel = config.max_parallel;
        Ok(Self {
            config,
            remote_addr,
            semaphore: Arc::new(Semaphore::new(max_parallel)),
        })
    }

    /// Return a Query object that contains the query state.
    async fn request<CR: ComposeRequest + Clone + Send + Sync + 'static>(
        &self,
        request_msg: &CR,
        conn: Connection,
    ) -> Result<ReqResp, Error> {
        Ok(ReqResp::new(
            self.config.clone(),
            request_msg,
            self.remote_addr,
            conn,
            self.config.udp_payload_size,
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
