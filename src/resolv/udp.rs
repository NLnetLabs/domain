//! UDP message service.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use futures::{Async, IntoFuture};
use tokio_core::net::UdpSocket;
use tokio_core::reactor;
use super::dgram::{DgramFactory, DgramService, DgramTransport};
use super::resolver::ServiceHandle;


//------------ udp_service ---------------------------------------------------

/// Create a new DNS service using UDP as the transport.
pub fn udp_service(reactor: reactor::Handle, local: SocketAddr,
                   peer: SocketAddr, request_timeout: Duration,
                   msg_size: usize) -> io::Result<ServiceHandle> {
    DgramService::new(UdpFactory::new(local), peer, reactor, request_timeout,
                      msg_size)
}


//------------ UdpSocket -----------------------------------------------------

//--- DgramTransport

impl DgramTransport for UdpSocket {
    fn send_to(&self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        self.send_to(buf, target)
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf)
    }

    fn poll_read(&self) -> Async<()> {
        self.poll_read()
    }
}


//------------ UdpFactory ----------------------------------------------------

pub struct UdpFactory {
    addr: SocketAddr,
}

impl UdpFactory {
    pub fn new(addr: SocketAddr) -> Self {
        UdpFactory{addr: addr}
    }
}


//--- DgramFactory

impl DgramFactory for UdpFactory {
    type Transport = UdpSocket;
    type Future = <io::Result<UdpSocket> as IntoFuture>::Future;

    fn bind(&self, reactor: &reactor::Handle) -> Self::Future {
        UdpSocket::bind(&self.addr, &reactor).into_future()
    }
}

