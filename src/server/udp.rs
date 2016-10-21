/// A name server for UDP.

use std::{io, mem};
use std::net::SocketAddr;
use futures::{Async, Future};
use futures::stream::Stream;
use tokio_core::net::UdpSocket;
use ::bits::MessageBuf;
use super::service::NameService;


//------------ UdpServer -----------------------------------------------------

pub struct UdpServer<N: NameService> {
    sock: UdpSocket,
    service: N,
    pending: Pending<N>,
    write: Option<(SocketAddr, Vec<u8>)>,
    read_buf: Vec<u8>,
    read: Option<(SocketAddr, MessageBuf)>,

    read_size: usize,
}

impl<N: NameService> UdpServer<N> {
    pub fn new(sock: UdpSocket, service: N, read_size: usize) -> Self {
        UdpServer {
            sock: sock,
            service: service,
            pending: Pending::new(),
            write: None,
            read_buf: vec![0u8; read_size],
            read: None,
            read_size: read_size
        }
    }
}

impl<N: NameService> Future for UdpServer<N> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<()>> {
        try!(self.poll_read());
        try!(self.poll_write());
        Ok(Async::NotReady)
    }
}

impl<N: NameService> UdpServer<N> {
    fn poll_write(&mut self) -> io::Result<()> {
        loop {
            if let Async::NotReady = try!(self.send_response()) {
                return Ok(())
            }
            if let Async::NotReady = try!(self.get_response()) {
                return Ok(())
            }
        }
    }

    fn send_response(&mut self) -> io::Result<Async<()>> {
        if let Some((ref peer, ref data)) = self.write {
            // XXX Deal with short send.
            try_nb!(self.sock.send_to(&data, &peer).map(|_| ()));
        }
        self.write = None;
        Ok(Async::Ready(()))
    }

    fn get_response(&mut self) -> io::Result<Async<()>> {
        self.write = Some(try_ready!(self.pending.poll()).unwrap());
        Ok(Async::Ready(()))
    }
}

impl<N: NameService> UdpServer<N> {
    fn poll_read(&mut self) -> io::Result<()> {
        loop {
            if let Async::NotReady = try!(self.dispatch()) {
                return Ok(())
            }
            if let Async::NotReady = try!(self.recv_request()) {
                return Ok(())
            }
        }
    }

    fn dispatch(&mut self) -> io::Result<Async<()>> {
        if self.read.is_none() {
            Ok(Async::Ready(()))
        }
        else if let Async::NotReady = self.service.poll_ready() {
            Ok(Async::NotReady)
        }
        else {
            let (peer, req) = self.read.take().unwrap();
            let fut = self.service.call(req, true);
            self.pending.push(peer, fut);
            Ok(Async::Ready(()))
        }
    }

    fn recv_request(&mut self) -> io::Result<Async<()>> {
        loop {
            let (size, peer) = try_nb!(self.sock.recv_from(
                                                        &mut self.read_buf));
            let new_data = vec![0u8; self.read_size];
            let mut data = mem::replace(&mut self.read_buf, new_data);
            data.truncate(size);
            match MessageBuf::from_vec(data) {
                Ok(msg) => {
                    self.read = Some((peer, msg));
                    return Ok(Async::Ready(()));
                }
                Err(_) => { }
            }
        }
    }
}


//------------ Pending -------------------------------------------------------

struct Pending<N: NameService> {
    inner: Vec<Response<N>>
}

impl<N: NameService> Pending<N> {
    fn new() -> Self {
        Pending{inner: Vec::new()}
    }

    fn push(&mut self, peer: SocketAddr, fut: N::Future) {
        self.inner.push(Response::new(peer, fut))
    }
}

impl<N: NameService> Stream for Pending<N> {
    type Item = (SocketAddr, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<Option<(SocketAddr, Vec<u8>)>>> {
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


//------------ Response ------------------------------------------------------

pub struct Response<N: NameService> {
    peer: SocketAddr,
    future: N::Future,
}

impl<N: NameService> Response<N> {
    fn new(peer: SocketAddr, future: N::Future) ->  Self {
        Response{peer: peer, future: future}
    }
}

impl<N: NameService> Future for Response<N> {
    type Item = (SocketAddr, Vec<u8>);
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<(SocketAddr, Vec<u8>)>> {
        self.future.poll().map(|ok| ok.map(|data| (self.peer, data)))
    }
}

