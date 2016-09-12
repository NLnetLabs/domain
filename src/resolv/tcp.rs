//! TCP message service.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio_core::net::{TcpStream, TcpStreamNew};
use tokio_core::reactor;
use super::stream::{StreamFactory, StreamService};
use super::resolver::ServiceHandle;


pub struct TcpFactory {
    addr: SocketAddr,
}

impl TcpFactory {
    pub fn new(addr: SocketAddr) -> Self {
        TcpFactory{addr: addr}
    }
}

impl StreamFactory for TcpFactory {
    type Stream = TcpStream;
    type Future = TcpStreamNew;

    fn connect(&self, reactor: &reactor::Handle) -> Self::Future {
        TcpStream::connect(&self.addr, reactor)
    }
}

pub fn tcp_service(reactor: reactor::Handle, addr: SocketAddr,
                   keep_alive: Duration, request_timeout: Duration)
                   -> io::Result<ServiceHandle> {
    StreamService::new(reactor, TcpFactory::new(addr), keep_alive,
                       request_timeout)
}
