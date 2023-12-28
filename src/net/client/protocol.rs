//! Underlying transport protocols.

use core::future::Future;
use core::pin::Pin;
use pin_project_lite::pin_project;
use std::boxed::Box;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
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

/// Receive a datagram packets asynchronously.
///
///
pub trait AsyncDgramRecv {
    /// Polled receive.
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>>;
}

/// Convenvience trait to turn poll_recv into an asynchronous function.
pub trait AsyncDgramRecvEx: AsyncDgramRecv {
    /// Asynchronous receive function.
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> DgramRecv<'a, Self>
    where
        Self: Unpin,
    {
        recv(self, buf)
    }
}

impl<R: AsyncDgramRecv> AsyncDgramRecvEx for R {}

pin_project! {
    /// Return value of recv. This captures the future for recv.
    pub struct DgramRecv<'a, R: ?Sized> {
        receiver: &'a mut R,
        buf: &'a mut [u8],
    }
}

impl<R: AsyncDgramRecv + Unpin> Future for DgramRecv<'_, R> {
    type Output = io::Result<usize>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let me = self.project();
        let mut buf = ReadBuf::new(me.buf);
        match Pin::new(me.receiver).poll_recv(cx, &mut buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(res) => {
                if let Err(err) = res {
                    return Poll::Ready(Err(err));
                }
            }
        }
        Poll::Ready(Ok(buf.filled().len()))
    }
}

/// Helper function for the recv method.
fn recv<'a, R: ?Sized>(
    receiver: &'a mut R,
    buf: &'a mut [u8],
) -> DgramRecv<'a, R> {
    DgramRecv { receiver, buf }
}

//------------ AsyncDgramSend -------------------------------------------------

/// Send a datagram packet asynchronously.
///
///
pub trait AsyncDgramSend {
    /// Polled send function.
    fn poll_send(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>>;
}

/// Convenience trait that turns poll_send into an asynchronous function.
pub trait AsyncDgramSendEx: AsyncDgramSend {
    /// Asynchronous function to send a packet.
    fn send<'a>(&'a self, buf: &'a [u8]) -> DgramSend<'a, Self>
    where
        Self: Unpin,
    {
        send(self, buf)
    }
}

impl<S: AsyncDgramSend> AsyncDgramSendEx for S {}

/// This is the return value of send. It captures the future for send.
pub struct DgramSend<'a, S: ?Sized> {
    /// The datagram send object.
    sender: &'a S,

    /// The buffer that needs to be sent.
    buf: &'a [u8],
}

impl<S: AsyncDgramSend + Unpin> Future for DgramSend<'_, S> {
    type Output = io::Result<usize>;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        Pin::new(self.sender).poll_send(cx, self.buf)
    }
}

/// Send helper function to implement the send method of AsyncDgramSendEx.
fn send<'a, S: ?Sized>(sender: &'a S, buf: &'a [u8]) -> DgramSend<'a, S> {
    DgramSend { sender, buf }
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
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        self.sock.poll_recv(cx, buf)
    }
}

impl AsyncDgramSend for UdpDgram {
    fn poll_send(
        self: Pin<&Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        self.sock.poll_send(cx, buf)
    }
}
