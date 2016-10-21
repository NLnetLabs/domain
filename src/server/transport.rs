//! The basic server.

use std::io;
use std::net::SocketAddr;
use futures::{Async, Future};
use futures::stream::Stream;
use tokio_core::reactor;
use ::bits::MessageBuf;
use ::bits::net::{Flow, TcpServer, TcpFlow, UdpServer, UdpServerFlow};
use super::service::NameService;

//------------ Transport -----------------------------------------------------

pub struct Transport<F, S, N>
                     where F: Flow,
                           S: Stream<Item=F, Error=io::Error>,
                           N: NameService {
    server: S,
    service: N,
    reactor: reactor::Handle,
}

impl<F, S, N> Transport<F, S, N>
     where F: Flow,
           S: Stream<Item=F, Error=io::Error>,
           N: NameService {
    pub fn new(server: S, reactor: reactor::Handle, service: N) -> Self {
        Transport{server: server, service: service, reactor: reactor}
    }
}

//--- UdpTransport

pub type UdpTransport<N> = Transport<UdpServerFlow, UdpServer, N>;

impl<N: NameService> Transport<UdpServerFlow, UdpServer, N> {
    pub fn bind(addr: &SocketAddr, handle: &reactor::Handle, service: N)
                -> io::Result<Self> {
        UdpServer::bind(addr, handle, 512, 512)
                  .map(|srv| Transport::new(srv, handle.clone(), service))
    }
}

//--- TcpTransport

pub type TcpTransport<N> = Transport<TcpFlow, TcpServer, N>;

impl<N: NameService> Transport<TcpFlow, TcpServer, N> {
    pub fn bind(addr: &SocketAddr, handle: &reactor::Handle, service: N)
                -> io::Result<Self> {
        TcpServer::bind(addr, handle)
                  .map(|srv| Transport::new(srv, handle.clone(), service))
    }
}


//--- Future

impl<F, S, N> Future for Transport<F, S, N>
     where F: Flow + 'static,
           S: Stream<Item=F, Error=io::Error>,
           N: NameService + 'static {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<()>> {
        loop {
            match try_ready!(self.server.poll()) {
                Some(flow) => {
                    let flow = TransportFlow::new(flow, self.service.clone())
                                          .map_err(|_| ());
                    self.reactor.spawn(flow)
                }
                None => return Ok(Async::Ready(()))
            }
        }
    }
}


//------------ TransportFlow -------------------------------------------------

pub struct TransportFlow<F: Flow, N: NameService> {
    flow: F,
    service: N,
    pending: Pending<N>,
    read: Option<MessageBuf>,
}

impl<F: Flow, N: NameService> TransportFlow<F, N> {
    fn new(flow: F, service: N) -> Self {
        TransportFlow {
            flow: flow,
            service: service,
            pending: Pending::new(),
            read: None
        }
    }
}

impl<F: Flow, N: NameService> Future for TransportFlow<F, N> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<()>> {
        if let Async::Ready(()) = try!(self.poll_read()) {
            return Ok(Async::Ready(()))
        }
        self.poll_write()
    }
}

impl<F: Flow, N: NameService> TransportFlow<F, N> {
    fn poll_read(&mut self) -> io::Result<Async<()>> {
        loop {
            if let Some(msg) = self.read.take() {
                if let Async::NotReady = self.service.poll_ready() {
                    return Ok(Async::NotReady)
                }
                let flow = self.service.call(msg, self.flow.compose_mode());
                self.pending.push(flow);
            }
            match try_ready!(self.flow.recv()) {
                Some(msg) => self.read = Some(msg),
                None => return Ok(Async::Ready(()))
            }
        }
    }

    fn poll_write(&mut self) -> io::Result<Async<()>> {
        while let Async::Ready(Some(data)) = try!(self.pending.poll()) {
            try!(self.flow.send(data));
        }
        self.flow.flush()
    }
}



//------------ Pending -------------------------------------------------------

struct Pending<N: NameService> {
    inner: Vec<N::Future>
}

impl<N: NameService> Pending<N> {
    fn new() -> Self {
        Pending{inner: Vec::new()}
    }

    fn push(&mut self, fut: N::Future) {
        self.inner.push(fut)
    }
}

impl<N: NameService> Stream for Pending<N> {
    type Item = Vec<u8>;
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<Option<Vec<u8>>>> {
        if self.inner.is_empty() {
            return Ok(Async::NotReady)
        }
        let mut res = None;
        let mut idx = None;
        for (i, item) in self.inner.iter_mut().enumerate() {
            res = match try!(item.poll()) {
                Async::Ready(res) => Some(res),
                Async::NotReady => continue,
            };
            idx = Some(i);
            break;
        }
        if let Some(idx) = idx {
            self.inner.remove(idx);
            Ok(Async::Ready(Some(res.unwrap())))
        }
        else {
            Ok(Async::NotReady)
        }
    }
}


