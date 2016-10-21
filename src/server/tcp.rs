/// A name server for TCP.

use std::io;
use futures::{Async, Future};
use futures::stream::Stream;
use tokio_core::reactor;
use tokio_core::net::{Incoming, TcpListener, TcpStream};
use super::service::NameService;


//------------ TcpServer -----------------------------------------------------

pub struct TcpServer<N: NameService> {
    sock: Incoming,
    service: N,
    reactor: reactor::Handle,
}

impl<N: NameService> TcpServer<N> {
    pub fn new(sock: TcpListener, reactor: reactor::Handle, service: N)
               -> Self {
        TcpServer {
            sock: sock.incoming(),
            service: service,
            reactor: reactor,
        }
    }
}

impl<N: NameService + 'static> Future for TcpServer<N> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<()>> {
        loop {
            match try_ready!(self.sock.poll()) {
                Some((sock, peer)) => {
                    let conn = TcpConnection::new(sock, self.service.clone());
                    self.reactor.spawn(conn);
                }
                None => return Ok(Async::Ready(()))
            }
        }
    }
}


//------------ TcpConnection -------------------------------------------------

pub struct TcpConnection<N: NameService> {
    sock: TcpStream,
    service: N,
    pending: Pending<N>,
    write: Option<Vec<u8>>,
    read
}

impl<N: NameService> TcpConnection<N> {
    fn new(sock: TcpStream, service: N) -> Self {
        TcpConnection {
            sock: sock,
            service: service
        }
    }
}

impl<N: NameService> Future for TcpConnection<N> {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<()>, ()> {
        unimplemented!()
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

