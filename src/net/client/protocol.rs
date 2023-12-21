//! Underlying transport protocols.

use core::future::Future;
use core::pin::Pin;
use std::boxed::Box;
use std::io;
use std::sync::Arc;
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, ServerName};
use tokio_rustls::TlsConnector;

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
