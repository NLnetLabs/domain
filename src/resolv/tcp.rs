//! TCP message service.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use futures::{Future, Poll};
use tokio_core::io::{Io, ReadHalf, WriteHalf};
use tokio_core::net::{TcpStream, TcpStreamNew};
use tokio_core::reactor;
use super::conf::ServerConf;
use super::request::ServiceHandle;
use super::service::{Service, ServiceMode};
use super::transport::{Transport, StreamWriter, StreamReader};


//------------ tcp_service ---------------------------------------------------

/// Creates a new DNS service using TCP as the transport.
pub fn tcp_service(reactor: reactor::Handle, conf: &ServerConf)
                   -> io::Result<Option<ServiceHandle>> {
    let mode = match ServiceMode::resolve(conf.tcp, ServiceMode::Sequential) {
        Some(mode) => mode,
        None => return Ok(None)
    };
    let transport = TcpTransport::new(conf.addr);
    Service::spawn(reactor, transport, mode, conf).map(Some)
}


//------------ TcpTransport --------------------------------------------------

pub struct TcpTransport {
    addr: SocketAddr,
}

impl TcpTransport {
    pub fn new(addr: SocketAddr) -> Self {
        TcpTransport{addr: addr}
    }
}


//--- Transport

impl Transport for TcpTransport {
    type Read = StreamReader<ReadHalf<TcpStream>>;
    type Write = StreamWriter<WriteHalf<TcpStream>>;
    type Future = TcpTransportNew;

    fn create(&self, reactor: &reactor::Handle) -> io::Result<Self::Future> {
        Ok(TcpTransportNew(TcpStream::connect(&self.addr, reactor)))
    }
}


//------------ TcpTransportNew -----------------------------------------------

pub struct TcpTransportNew(TcpStreamNew);

impl Future for TcpTransportNew {
    type Item = (StreamReader<ReadHalf<TcpStream>>,
                 StreamWriter<WriteHalf<TcpStream>>);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.0.poll().map(|ready| ready.map(|stream| {
            let (rd, wr) = stream.split();
            (rd.into(), wr.into())
        }))
    }
}

