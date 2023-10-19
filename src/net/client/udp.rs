//! A DNS over UDP transport

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

// To do:
// - cookies
// - random port

use bytes::Bytes;
use std::boxed::Box;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Duration, Instant};

use crate::base::{Message, MessageBuilder, StaticCompressor, StreamTarget};
use crate::net::client::error::Error;
use crate::net::client::query::{GetResult, QueryMessage};

/// How many times do we try a new random port if we get ‘address in use.’
const RETRY_RANDOM_PORT: usize = 10;

/// Maximum number of parallel DNS query over a single UDP transport
/// connection.
const MAX_PARALLEL: usize = 100;

/// Maximum amount of time to wait for a reply.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum number of retries after timeouts.
const MAX_RETRIES: u8 = 5;

/// A UDP transport connection.
#[derive(Clone)]
pub struct Connection {
    /// Reference to the actual connection object.
    inner: Arc<InnerConnection>,
}

impl Connection {
    /// Create a new UDP transport connection.
    pub fn new(remote_addr: SocketAddr) -> io::Result<Connection> {
        let connection = InnerConnection::new(remote_addr)?;
        Ok(Self {
            inner: Arc::new(connection),
        })
    }

    /// Start a new DNS query.
    async fn query_impl<Octs: AsRef<[u8]> + Clone>(
        &self,
        query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,
    ) -> Result<Query<Octs>, Error> {
        self.inner.query(query_msg, self.clone()).await
    }

    /// Get a permit from the semaphore to start using a socket.
    async fn get_permit(&self) -> OwnedSemaphorePermit {
        self.inner.get_permit().await
    }
}

impl<Octs: AsRef<[u8]> + Clone> QueryMessage<Query<Octs>, Octs>
    for Connection
{
    fn query<'a>(
        &'a self,
        query_msg: &'a mut MessageBuilder<
            StaticCompressor<StreamTarget<Octs>>,
        >,
    ) -> Pin<Box<dyn Future<Output = Result<Query<Octs>, Error>> + '_>> {
        return Box::pin(self.query_impl(query_msg));
    }
}

/// State of the DNS query.
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

/// The state of a DNS query.
pub struct Query<Octs> {
    /// Address of remote server to connect to.
    remote_addr: SocketAddr,

    /// DNS request message.
    query_msg: MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,

    /// Semaphore permit that allow use of socket.
    _permit: Option<OwnedSemaphorePermit>,

    /// UDP socket for communication.
    sock: Option<UdpSocket>,

    /// Current number of retries.
    retries: u8,

    /// State of query.
    state: QueryState,
}

impl<Octs: AsRef<[u8]> + Clone> Query<Octs> {
    /// Create new Query object.
    fn new(
        query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,
        remote_addr: SocketAddr,
        conn: Connection,
    ) -> Query<Octs> {
        Query {
            query_msg: query_msg.clone(),
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
                    let sent = self
                        .sock
                        .as_ref()
                        .expect("socket should be present")
                        .send(
                            self.query_msg
                                .as_target()
                                .as_target()
                                .as_dgram_slice(),
                        )
                        .await
                        .map_err(|e| Error::UdpSend(Arc::new(e)))?;
                    if sent
                        != self
                            .query_msg
                            .as_target()
                            .as_target()
                            .as_dgram_slice()
                            .len()
                    {
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
                    if !answer.is_answer(&self.query_msg.as_message()) {
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

impl<Octs: AsRef<[u8]> + Clone> GetResult for Query<Octs> {
    fn get_result(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Message<Bytes>, Error>> + '_>>
    {
        Box::pin(self.get_result_impl())
    }
}

/// Actual implementation of the UDP transport connection.
struct InnerConnection {
    /// Address of the remote server.
    remote_addr: SocketAddr,

    /// Semaphore to limit access to UDP sockets.
    semaphore: Arc<Semaphore>,
}

impl InnerConnection {
    /// Create new InnerConnection object.
    fn new(remote_addr: SocketAddr) -> io::Result<InnerConnection> {
        Ok(Self {
            remote_addr,
            semaphore: Arc::new(Semaphore::new(MAX_PARALLEL)),
        })
    }

    /// Return a Query object that contains the query state.
    async fn query<Octs: AsRef<[u8]> + Clone>(
        &self,
        query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,
        conn: Connection,
    ) -> Result<Query<Octs>, Error> {
        Ok(Query::new(query_msg, self.remote_addr, conn))
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
