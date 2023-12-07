//! Create new TLS connections

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use core::ops::DerefMut;
use futures::Future;
use std::boxed::Box;
use std::pin::Pin;
use std::string::String;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::{ClientConfig, ServerName};
use tokio_rustls::TlsConnector;

use crate::net::client::async_connect::AsyncConnect;

//------------ TlsConnect -----------------------------------------------------

/// Create new TLS connections
pub struct TlsConnect<A: ToSocketAddrs> {
    /// Configuration for setting up a TLS connection.
    client_config: Arc<ClientConfig>,

    /// Server name for certificate verification.
    server_name: String,

    /// Remote address to connect to.
    addr: A,
}

impl<A: ToSocketAddrs> TlsConnect<A> {
    /// Function to create a new TLS connection stream
    pub fn new(
        client_config: Arc<ClientConfig>,
        server_name: &str,
        addr: A,
    ) -> Self {
        Self {
            client_config,
            server_name: String::from(server_name),
            addr,
        }
    }
}

impl<A: ToSocketAddrs + Clone + Send + Sync + 'static>
    AsyncConnect<TlsStream<TcpStream>> for TlsConnect<A>
{
    type F = Pin<
        Box<
            dyn Future<Output = Result<TlsStream<TcpStream>, std::io::Error>>
                + Send,
        >,
    >;

    fn connect(&self) -> Self::F {
        let tls_connection = TlsConnector::from(self.client_config.clone());
        let server_name =
            match ServerName::try_from(self.server_name.as_str()) {
                Err(_) => {
                    return Box::pin(error_helper(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "invalid DNS name",
                    )));
                }
                Ok(res) => res,
            };
        let addr = self.addr.clone();
        Box::pin(Next {
            future: Box::pin(async {
                let box_connection = Box::new(tls_connection);
                let tcp = TcpStream::connect(addr).await?;
                box_connection.connect(server_name, tcp).await
            }),
        })
    }
}

//------------ Next -----------------------------------------------------------

/// Internal structure that contains the future for creating a new
/// TLS connection.
pub struct Next {
    /// Future for creating a new TLS connection.
    future: Pin<
        Box<
            dyn Future<Output = Result<TlsStream<TcpStream>, std::io::Error>>
                + Send,
        >,
    >,
}

impl Future for Next {
    type Output = Result<TlsStream<TcpStream>, std::io::Error>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<TlsStream<TcpStream>, std::io::Error>> {
        let me = self.deref_mut();
        let io = ready!(me.future.as_mut().poll(cx))?;
        Poll::Ready(Ok(io))
    }
}

//------------ Utility --------------------------------------------------------

/// Helper to return an error as an async function.
async fn error_helper(
    err: std::io::Error,
) -> Result<TlsStream<TcpStream>, std::io::Error> {
    Err(err)
}
