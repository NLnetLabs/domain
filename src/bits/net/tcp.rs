//! Sending and receiving via TCP.

use std::io;
use std::net::SocketAddr;
use futures::Async;
use futures::stream::Stream;
use tokio_core::net::{Incoming, TcpListener, TcpStream};
use tokio_core::reactor::Handle;
use ::bits::{ComposeMode, MessageBuf};
use super::Flow;
use super::stream::{StreamRecv, StreamSend};


pub struct TcpIncoming {
    inner: Incoming,
}

impl TcpIncoming {
    pub fn new(listener: TcpListener) -> Self {
        TcpIncoming{inner: listener.incoming()}
    }

    pub fn bind(addr: &SocketAddr, handle: &Handle) -> io::Result<Self> {
        TcpListener::bind(addr, handle).map(TcpIncoming::new)
    }
}

impl Stream for TcpIncoming {
    type Item = TcpFlow;
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<Option<TcpFlow>>> {
        self.inner.poll().map(|res| res.map(|async| async.map(TcpFlow::from))) 
    }
}


pub struct TcpFlow {
    sock: TcpStream,
    addr: SocketAddr,
    send: StreamSend,
    recv: StreamRecv,
}

impl TcpFlow {
    fn new(sock: TcpStream, addr: SocketAddr) -> Self {
        TcpFlow {
            sock: sock,
            addr: addr,
            send: StreamSend::new(),
            recv: StreamRecv::new(),
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.addr
    }
}

impl Flow for TcpFlow {
    fn compose_mode(&self) -> ComposeMode {
        ComposeMode::Stream
    }

    fn send(&mut self, msg: Vec<u8>) -> io::Result<Async<()>> {
        self.send.send(&mut self.sock, msg)
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
        Self::new(pair.0, pair.1)
    }
}
