//! Underlying transport protocols.

use core::future::Future;
use core::pin::Pin;
use std::boxed::Box;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::vec::Vec;
use tokio::net::{TcpStream, ToSocketAddrs, UdpSocket};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, ServerName};
use tokio_rustls::TlsConnector;

/// How many times do we try a new random port if we get ‘address in use.’
const RETRY_RANDOM_PORT: usize = 10;

//------------ AsyncConnect --------------------------------------------------

/// Establish a connection asynchronously.
///
///
pub trait AsyncConnect {
    /// The type of an established connection.
    type Connection;

    /// The future establishing the connection.
    type Fut: Future<Output = Result<Self::Connection, io::Error>> + Send;

    /// Returns a future that establishing a connection.
    fn connect(&self) -> Self::Fut;
}

//------------ TcpConnect --------------------------------------------------

/// Create new TCP connections.
#[derive(Clone, Copy, Debug)]
pub struct TcpConnect<Addr> {
    /// Remote address to connect to.
    addr: Addr,
}

impl<Addr> TcpConnect<Addr> {
    /// Create new TCP connections.
    ///
    /// addr is the destination address to connect to.
    pub fn new(addr: Addr) -> Self {
        Self { addr }
    }
}

impl<Addr> AsyncConnect for TcpConnect<Addr>
where
    Addr: ToSocketAddrs + Clone + Send + 'static,
{
    type Connection = TcpStream;
    type Fut = Pin<
        Box<
            dyn Future<Output = Result<Self::Connection, std::io::Error>>
                + Send,
        >,
    >;

    fn connect(&self) -> Self::Fut {
        Box::pin(TcpStream::connect(self.addr.clone()))
    }
}

//------------ TlsConnect -----------------------------------------------------

/// Create new TLS connections
#[derive(Clone, Debug)]
pub struct TlsConnect<Addr> {
    /// Configuration for setting up a TLS connection.
    client_config: Arc<ClientConfig>,

    /// Server name for certificate verification.
    server_name: ServerName,

    /// Remote address to connect to.
    addr: Addr,
}

impl<Addr> TlsConnect<Addr> {
    /// Function to create a new TLS connection stream
    pub fn new(
        client_config: impl Into<Arc<ClientConfig>>,
        server_name: ServerName,
        addr: Addr,
    ) -> Self {
        Self {
            client_config: client_config.into(),
            server_name,
            addr,
        }
    }
}

impl<Addr> AsyncConnect for TlsConnect<Addr>
where
    Addr: ToSocketAddrs + Clone + Send + 'static,
{
    type Connection = TlsStream<TcpStream>;
    type Fut = Pin<
        Box<
            dyn Future<Output = Result<Self::Connection, std::io::Error>>
                + Send,
        >,
    >;

    fn connect(&self) -> Self::Fut {
        let tls_connection = TlsConnector::from(self.client_config.clone());
        let server_name = self.server_name.clone();
        let addr = self.addr.clone();
        Box::pin(async {
            let box_connection = Box::new(tls_connection);
            let tcp = TcpStream::connect(addr).await?;
            box_connection.connect(server_name, tcp).await
        })
    }
}

//------------ AsyncDgramRecv -------------------------------------------------

/// Receive a datagram packet asynchronously.
///
///
pub trait AsyncDgramRecv {
    /// The future performing the receive operation.
    type Fut: Future<Output = Result<Vec<u8>, io::Error>> + Send;

    /// Returns a future that performs the receive operation.
    fn recv(&self, buf: Vec<u8>) -> Self::Fut;
}

//------------ AsyncDgramSend -------------------------------------------------

/// Send a datagram packet asynchronously.
///
///
pub trait AsyncDgramSend {
    /// The future performing the send operation.
    type Fut: Future<Output = Result<usize, io::Error>> + Send;

    /// Returns a future that performs the send operation.
    fn send(&self, buf: &[u8]) -> Self::Fut;
}

//------------ UdpConnect --------------------------------------------------

/// Create new TCP connections.
#[derive(Clone, Copy, Debug)]
pub struct UdpConnect {
    /// Remote address to connect to.
    addr: SocketAddr,
}

impl UdpConnect {
    /// Create new UDP connections.
    ///
    /// addr is the destination address to connect to.
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

impl AsyncConnect for UdpConnect {
    type Connection = UdpDgram;
    type Fut = Pin<
        Box<
            dyn Future<Output = Result<Self::Connection, std::io::Error>>
                + Send,
        >,
    >;

    fn connect(&self) -> Self::Fut {
        Box::pin(UdpDgram::new(self.addr))
    }
}

/// A single UDP 'connection'
pub struct UdpDgram {
    /// Underlying UDP socket
    sock: Arc<UdpSocket>,
}

impl UdpDgram {
    /// Create a new UdpDgram object.
    async fn new(addr: SocketAddr) -> Result<Self, io::Error> {
        let sock = Self::udp_bind(addr.is_ipv4()).await?;
        sock.connect(addr).await?;
        Ok(Self {
            sock: Arc::new(sock),
        })
    }
    /// Bind to a local UDP port.
    ///
    /// This should explicitly pick a random number in a suitable range of
    /// ports.
    async fn udp_bind(v4: bool) -> Result<UdpSocket, io::Error> {
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
                        return Err(err);
                    } else {
                        i += 1
                    }
                }
            }
        }
    }
}

impl AsyncDgramRecv for UdpDgram {
    type Fut =
        Pin<Box<dyn Future<Output = Result<Vec<u8>, io::Error>> + Send>>;
    fn recv(&self, mut buf: Vec<u8>) -> Self::Fut {
        let sock = self.sock.clone();
        Box::pin(async move {
            let len = sock.recv(&mut buf).await?;
            buf.truncate(len);
            Ok(buf)
        })
    }
}

impl AsyncDgramSend for UdpDgram {
    type Fut = Pin<Box<dyn Future<Output = Result<usize, io::Error>> + Send>>;
    fn send(&self, buf: &[u8]) -> Self::Fut {
        let sock = self.sock.clone();
        let buf = buf.to_vec();
        Box::pin(async move { sock.send(&buf).await })
    }
}

/*
struct Sender {
    sock: Arc<UdpSocket>,
    buf: Vec<u8>
}

impl Sender {
    fn new() -> Self { Self }
}

impl Future for Sender {
    type Output = Result<usize, io::Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) ->
    Poll<Self::Output> {
        self.sock.poll_send(cx, &self.buf)
    }
}
*/
