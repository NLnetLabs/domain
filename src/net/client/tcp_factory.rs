//! A factory for TCP connections

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use core::ops::DerefMut;
use futures::Future;
use std::boxed::Box;
use std::fmt::Debug;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::net::{TcpStream, ToSocketAddrs};

use crate::net::client::factory::ConnFactory;

//------------ TcpConnFactory -------------------------------------------------

/// This a connection factory that produces TCP connections.
pub struct TcpConnFactory<A: ToSocketAddrs> {
    /// Remote address to connect to.
    addr: A,
}

impl<A: ToSocketAddrs + Clone + Debug + Send + 'static> TcpConnFactory<A> {
    /// Create a new factory.
    ///
    /// addr is the destination address to connect to.
    pub fn new(addr: A) -> TcpConnFactory<A> {
        Self { addr }
    }
}

impl<A: ToSocketAddrs + Clone + Send + 'static> ConnFactory<TcpStream>
    for TcpConnFactory<A>
{
    type F = Pin<
        Box<dyn Future<Output = Result<TcpStream, std::io::Error>> + Send>,
    >;

    fn next(&self) -> Self::F {
        Box::pin(Next {
            future: Box::pin(TcpStream::connect(self.addr.clone())),
        })
    }
}

//------------ Next -----------------------------------------------------------

/// This is an internal structure that provides the future for a new
/// connection.
pub struct Next {
    /// Future for creating a new TCP connection.
    future: Pin<
        Box<dyn Future<Output = Result<TcpStream, std::io::Error>> + Send>,
    >,
}

impl Future for Next {
    type Output = Result<TcpStream, std::io::Error>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<TcpStream, std::io::Error>> {
        let me = self.deref_mut();
        let io = ready!(me.future.as_mut().poll(cx))?;
        Poll::Ready(Ok(io))
    }
}
