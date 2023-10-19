//! A factory for TLS connections

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

use crate::net::client::factory::ConnFactory;

/// Factory object for TLS connections
pub struct TlsConnFactory<A: ToSocketAddrs> {
    /// Configuration for setting up a TLS connection.
    client_config: Arc<ClientConfig>,

    /// Server name for certificate verification.
    server_name: String,

    /// Remote address to connect to.
    addr: A,
}

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

impl<A: ToSocketAddrs> TlsConnFactory<A> {
    /// Function to create a new TLS connection factory
    pub fn new(
        client_config: Arc<ClientConfig>,
        server_name: &str,
        addr: A,
    ) -> TlsConnFactory<A> {
        Self {
            client_config,
            server_name: String::from(server_name),
            addr,
        }
    }
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

impl<A: ToSocketAddrs + Clone + Send + Sync + 'static>
    ConnFactory<TlsStream<TcpStream>> for TlsConnFactory<A>
{
    fn next(
        &self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<TlsStream<TcpStream>, std::io::Error>>
                + Send
                + '_,
        >,
    > {
        let tls_connection = TlsConnector::from(self.client_config.clone());
        let server_name =
            ServerName::try_from(self.server_name.as_str()).unwrap();
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
