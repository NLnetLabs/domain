//! Underlying transport protocols.

use core::future::Future;
use core::pin::Pin;
use std::boxed::Box;
use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::{TcpStream, UdpSocket};

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
    type Fut: Future<Output = Result<Self::Connection, io::Error>>
        + Send
        + Sync;

    /// Returns a future that establishing a connection.
    fn connect(&self) -> Self::Fut;
}

//------------ TcpConnect --------------------------------------------------

/// Create new TCP connections.
#[derive(Clone, Copy, Debug)]
pub struct TcpConnect {
    /// Remote address to connect to.
    addr: SocketAddr,
}

impl TcpConnect {
    /// Create new TCP connections.
    ///
    /// addr is the destination address to connect to.
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }
}

impl AsyncConnect for TcpConnect {
    type Connection = TcpStream;
    type Fut = Pin<
        Box<
            dyn Future<Output = Result<Self::Connection, std::io::Error>>
                + Send
                + Sync,
        >,
    >;

    fn connect(&self) -> Self::Fut {
        Box::pin(TcpStream::connect(self.addr))
    }
}

//------------ TlsConnect -----------------------------------------------------

/// Create new TLS connections
#[cfg(feature = "tokio-rustls")]
#[derive(Clone, Debug)]
pub struct TlsConnect {
    /// Configuration for setting up a TLS connection.
    client_config: std::sync::Arc<tokio_rustls::rustls::ClientConfig>,

    /// Server name for certificate verification.
    server_name: tokio_rustls::rustls::pki_types::ServerName<'static>,

    /// Remote address to connect to.
    addr: SocketAddr,
}

#[cfg(feature = "tokio-rustls")]
impl TlsConnect {
    /// Function to create a new TLS connection stream
    pub fn new<Conf>(
        client_config: Conf,
        server_name: tokio_rustls::rustls::pki_types::ServerName<'static>,
        addr: SocketAddr,
    ) -> Self
    where
        Conf: Into<std::sync::Arc<tokio_rustls::rustls::ClientConfig>>,
    {
        Self {
            client_config: client_config.into(),
            server_name,
            addr,
        }
    }
}

#[cfg(feature = "tokio-rustls")]
impl AsyncConnect for TlsConnect {
    type Connection = tokio_rustls::client::TlsStream<TcpStream>;
    type Fut = Pin<
        Box<
            dyn Future<Output = Result<Self::Connection, std::io::Error>>
                + Send
                + Sync,
        >,
    >;

    fn connect(&self) -> Self::Fut {
        let tls_connection =
            tokio_rustls::TlsConnector::from(self.client_config.clone());
        let server_name = self.server_name.clone();
        let addr = self.addr;
        Box::pin(async move {
            let box_connection = Box::new(tls_connection);
            let tcp = TcpStream::connect(addr).await?;
            box_connection.connect(server_name, tcp).await
        })
    }
}

//------------ UdpConnect --------------------------------------------------

/// Create new UDP connections.
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

    /// Bind to a random local UDP port.
    async fn bind_and_connect(self) -> Result<UdpSocket, io::Error> {
        let mut i = 0;
        let sock = loop {
            let local: SocketAddr = if self.addr.is_ipv4() {
                ([0u8; 4], 0).into()
            } else {
                ([0u16; 8], 0).into()
            };
            match UdpSocket::bind(&local).await {
                Ok(sock) => break sock,
                Err(err) => {
                    if i == RETRY_RANDOM_PORT {
                        return Err(err);
                    } else {
                        i += 1
                    }
                }
            }
        };
        sock.connect(self.addr).await?;
        Ok(sock)
    }
}

impl AsyncConnect for UdpConnect {
    type Connection = UdpSocket;
    type Fut = Pin<
        Box<
            dyn Future<Output = Result<Self::Connection, std::io::Error>>
                + Send
                + Sync,
        >,
    >;

    fn connect(&self) -> Self::Fut {
        Box::pin(self.bind_and_connect())
    }
}

//------------ AsyncDgramRecv -------------------------------------------------

/// Receive a datagram packets asynchronously.
pub trait AsyncDgramRecv {
    /// Polled receive.
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>>;
}

impl AsyncDgramRecv for UdpSocket {
    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        UdpSocket::poll_recv(self, cx, buf)
    }
}

//------------ AsyncDgramRecvEx -----------------------------------------------

/// Convenvience trait to turn poll_recv into an asynchronous function.
pub trait AsyncDgramRecvEx: AsyncDgramRecv {
    /// Asynchronous receive function.
    fn recv<'a>(&'a mut self, buf: &'a mut [u8]) -> DgramRecv<'a, Self>
    where
        Self: Unpin,
    {
        DgramRecv {
            receiver: self,
            buf,
        }
    }
}

impl<R: AsyncDgramRecv> AsyncDgramRecvEx for R {}

//------------ DgramRecv -----------------------------------------------------

/// Return value of recv. This captures the future for recv.
pub struct DgramRecv<'a, R: ?Sized> {
    receiver: &'a R,
    buf: &'a mut [u8],
}

impl<R: AsyncDgramRecv + Unpin> Future for DgramRecv<'_, R> {
    type Output = io::Result<usize>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        let receiver = self.receiver;
        let mut buf = ReadBuf::new(self.buf);
        match Pin::new(receiver).poll_recv(cx, &mut buf) {
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

//------------ AsyncDgramSend -------------------------------------------------

/// Send a datagram packet asynchronously.
///
///
pub trait AsyncDgramSend {
    /// Polled send function.
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>>;
}

impl AsyncDgramSend for UdpSocket {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        UdpSocket::poll_send(self, cx, buf)
    }
}

//------------ AsyncDgramSendEx ----------------------------------------------

/// Convenience trait that turns poll_send into an asynchronous function.
pub trait AsyncDgramSendEx: AsyncDgramSend {
    /// Asynchronous function to send a packet.
    fn send<'a>(&'a self, buf: &'a [u8]) -> DgramSend<'a, Self>
    where
        Self: Unpin,
    {
        DgramSend { sender: self, buf }
    }
}

impl<S: AsyncDgramSend> AsyncDgramSendEx for S {}

//------------ DgramSend -----------------------------------------------------

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
