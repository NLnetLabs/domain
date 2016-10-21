//! Sending and receiving via TCP.

use std::io;
use std::net::SocketAddr;
use futures::{Async, Future};
use futures::stream::Stream;
use tokio_core::net::{Incoming, TcpListener, TcpStream, TcpStreamNew};
use tokio_core::reactor::Handle;
use ::bits::{ComposeMode, MessageBuf};
use super::Flow;
use super::stream::{StreamRecv, StreamSend};

//------------ TcpServer -----------------------------------------------------

/// A server for a tcp transport endpoint.
///
/// This type correlates to a TCP listener. It listens on a port and produces
/// [`TcpFlow`] values for incoming connections.
///
/// [`TcpFlow`]: struct.TcpFlow.html
pub struct TcpServer {
    inner: Incoming,
}


impl TcpServer {
    fn new(listener: TcpListener) -> Self {
        TcpServer{inner: listener.incoming()}
    }

    /// Creates a new TCP server.
    ///
    /// The server will listen for incoming connections on the given address.
    /// It will be associated with the given event loop.
    pub fn bind(addr: &SocketAddr, handle: &Handle) -> io::Result<Self> {
        TcpListener::bind(addr, handle).map(TcpServer::new)
    }
}


//--- Stream

impl Stream for TcpServer {
    type Item = TcpFlow;
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<Option<TcpFlow>>> {
        self.inner.poll().map(|res| res.map(|async| async.map(TcpFlow::from))) 
    }
}


//------------ TcpFlow -------------------------------------------------------

/// A flow between two TCP network endpoints.
///
/// This type wraps a TCP connection.
pub struct TcpFlow {
    /// The actual socket.
    sock: TcpStream,

    send: StreamSend,
    recv: StreamRecv,
}

impl TcpFlow {
    fn new(sock: TcpStream) -> Self {
        TcpFlow {
            sock: sock,
            send: StreamSend::new(),
            recv: StreamRecv::new(),
        }
    }

    pub fn connect(addr: &SocketAddr, handle: &Handle) -> TcpFlowNew {
        TcpFlowNew{inner: TcpStream::connect(addr, handle)}
    }
}

impl Flow for TcpFlow {
    fn compose_mode(&self) -> ComposeMode {
        ComposeMode::Stream
    }

    fn send(&mut self, msg: Vec<u8>) -> io::Result<()> {
        self.send.send(msg)
    }

    fn flush(&mut self) -> io::Result<Async<()>> {
        self.send.flush(&mut self.sock)
    }

    fn recv(&mut self) -> io::Result<Async<Option<MessageBuf>>> {
        self.recv.recv(&mut self.sock)
    }
}

impl From<(TcpStream, SocketAddr)> for TcpFlow {
    fn from(pair: (TcpStream, SocketAddr)) -> Self {
        Self::new(pair.0)
    }
}


//------------ TcpFlowNew ----------------------------------------------------

pub struct TcpFlowNew {
    inner: TcpStreamNew
}

impl Future for TcpFlowNew {
    type Item = TcpFlow;
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<TcpFlow>> {
        self.inner.poll().map(|res| res.map(TcpFlow::new))
    }
}

