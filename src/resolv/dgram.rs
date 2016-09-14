//! Service for datagram transport.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::time::Duration;
use futures::{Async, Future, Poll};
use futures::stream::Stream;
use tokio_core::channel::{Receiver, channel};
use tokio_core::reactor;
use ::bits::{ComposeResult, MessageBuf, MessageBuilder, Question};
use super::error::Error;
use super::pending::PendingRequests;
use super::request::Request;
use super::resolver::ServiceHandle;


//------------ DgramTransport ------------------------------------------------

/// A trait for datagram transports.
///
/// This is all the methods from `UdpSocket` that `DgramService` needs.
pub trait DgramTransport {
    fn send_to(&self, buf: &[u8], target: &SocketAddr) -> io::Result<usize>;
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn poll_read(&self) -> Async<()>;
}


//------------ DgramFactory --------------------------------------------------

/// A factory that creates datagram sockets.
pub trait DgramFactory: Send + 'static {
    /// The transport type produced by this factory.
    type Transport: DgramTransport;

    /// The type of the future that will eventually produce a transport.
    type Future: Future<Item=Self::Transport, Error=io::Error>;

    /// Creates a future that will resolve into a socket on the given reactor.
    fn bind(&self, reactor: &reactor::Handle) -> Self::Future;
}


//------------ DgramService --------------------------------------------------

/// A DNS service using a datagram transport.
///
/// Each datagram service communicates with exactly one remote server.
pub struct DgramService<T: DgramTransport> {
    /// The receiving end of a channel of incoming requests.
    recv: Option<Receiver<Request>>,

    /// The datagram socket.
    sock: T,

    /// The remote address to communicate with.
    peer: SocketAddr,

    /// The current outgoing request if there is one.
    write: Option<DgramRequest>,

    /// The map of outstanding requests.
    pending: PendingRequests<DgramRequest>,

    /// The maximum message size of our socket.
    msg_size: usize,
}

impl<T: DgramTransport + 'static> DgramService<T> {
    /// Creates a new datagram service and returns its service handle.
    ///
    /// What this actually does is create a convoluted future that will
    /// listen on the receiving side of the service handle’s channel until
    /// the first request arrives and only then actually create the service
    /// which will then be alive until the channel is disconnected or the
    /// datagram socket is closed.
    pub fn new<F>(factory: F, peer: SocketAddr, reactor: reactor::Handle,
                  request_timeout: Duration, msg_size: usize)
                  -> io::Result<ServiceHandle>
               where F: DgramFactory<Transport=T> {
        let (tx, rx) = try!(channel(&reactor));
        let idle = rx.into_future().map_err(|(_, _)| ());
        let received = idle.and_then(|(item, recv)| {
            match item {
                Some(request) => Ok((request, recv)),
                None => Err(())
            }
        });
        let bind_handle = reactor.clone();
        let binding = received.and_then(move |(request, recv)| {
            factory.bind(&bind_handle)
                   .map(|sock| (sock, request, recv))
                   .map_err(|_| ())
        });
        let pending_handle = reactor.clone();
        let fut = binding.and_then(move |(sock, request, recv)| {
            let mut pending = PendingRequests::new(pending_handle,
                                                   request_timeout);
            let write = DgramRequest::new(request, &mut pending, msg_size);
            let res = DgramService {
                recv: Some(recv), sock: sock, peer: peer,
                write: write, pending: pending, msg_size: msg_size,
            };
            res.map_err(|_| ())
        });
        reactor.spawn(fut);
        Ok(ServiceHandle::from_sender(tx))
    }
}


/// # Polling Helpers
///
impl<T: DgramTransport> DgramService<T> {
    /// Polls the request receiver.
    ///
    /// Returns ready iff the receiver is gone and there are no more pending
    /// requests.
    fn poll_recv(&mut self) -> Async<()> {
        if let Some(ref mut recv) = self.recv {
            if self.write.is_none() {
                match recv.poll() {
                    Ok(Async::Ready(Some(request))) => {
                        self.write = DgramRequest::new(request,
                                                       &mut self.pending,
                                                       self.msg_size);
                        return Async::NotReady
                    }
                    Ok(Async::NotReady) => return Async::NotReady,
                    Ok(Async::Ready(None)) | Err(_) => { }
                }
            }
            else { return Async::NotReady }
        }
        else {
            if self.pending.is_empty() { return Async::Ready(()) }
            else { return Async::NotReady }
        };
        self.recv = None;
        Async::NotReady
    }

    /// Poll the pending requests.
    ///
    /// That is, times out all expired requests.
    fn poll_pending(&mut self) {
        self.pending.expire(|item| item.timeout())
    }


    fn poll_write(&mut self) -> io::Result<()> {
        loop {
            let success = if let Some(ref mut request) = self.write {
                let written = match self.sock.send_to(request.buf(),
                                                      &self.peer) {
                    Ok(written) => written,
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock
                    => {
                        return Ok(())
                    }
                    Err(err) => return Err(err)
                };
                written == request.buf().len()
            }
            else {
                return Ok(())
            };
            if let Some(request) = mem::replace(&mut self.write, None) {
                if success {
                    self.pending.push(request.id(), request)
                }
                else {
                    request.fail(io::Error::new(io::ErrorKind::Other,
                                                "short write").into());
                }
            }
        }
    }

    fn poll_read(&mut self) -> io::Result<()> {
        while let Async::Ready(()) = self.sock.poll_read() {
            let mut buf = vec![0u8; self.msg_size];
            let (size, addr) = match self.sock.recv_from(&mut buf) {
                Ok(some) => some,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(())
                }
                Err(err) => return Err(err)
            };
            if addr != self.peer {
                return Ok(())
            }
            buf.resize(size, 0);
            let msg = match MessageBuf::from_vec(buf) {
                Ok(msg) => msg,
                Err(_) => return Ok(())
            };
            let id = msg.header().id();
            if let Some(request) = self.pending.pop(id) {
                request.respond(msg)
            }
        }
        Ok(())
    }
}


//--- Future

impl<T: DgramTransport> Future for DgramService<T> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        match self.poll_recv() {
            Async::Ready(()) => return Ok(Async::Ready(())),
            Async::NotReady => { }
        }
        self.poll_pending();
        try!(self.poll_write());
        try!(self.poll_read());
        Ok(Async::NotReady)
    }
}



//------------ DgramRequest --------------------------------------------------

struct DgramRequest {
    request: Request,
    id: u16,
    buf: MessageBuf,
}

impl DgramRequest {
    fn new(request: Request, pending: &mut PendingRequests<Self>,
           msg_size: usize) -> Option<Self> {
        let id = match pending.reserve() {
            Ok(id) => id,
            Err(_) => {
                request.fail(io::Error::new(io::ErrorKind::Other,
                                            "too many pending queries")
                                       .into());
                return None
            }
        };
        let buf = match Self::new_buf(&request, id, msg_size) {
            Ok(buf) => buf,
            Err(err) => {
                request.fail(err.into());
                return None
            }
        };
        Some(DgramRequest{request: request, id: id, buf: buf})
    }

    fn new_buf(request: &Request, id: u16, msg_size: usize)
               -> ComposeResult<MessageBuf> {
        let mut buf = try!(MessageBuilder::new(Some(msg_size), true));
        buf.header_mut().set_id(id);
        buf.header_mut().set_rd(true);
        try!(Question::push(&mut buf, &request.query().name,
                            request.query().rtype, request.query().class));
        Ok(MessageBuf::from_vec(try!(buf.finish()).finish()).unwrap())
    }

    fn buf(&self) -> &[u8] {
        self.buf.as_bytes()
    }

    fn id(&self) -> u16 {
        self.id
    }

    fn respond(self, response: MessageBuf) {
        if response.is_answer(&self.buf) {
            self.request.succeed(response)
        }
        else {
            self.request.fail(io::Error::new(io::ErrorKind::Other,
                                             "server error").into())
        }
    }

    fn fail(self, err: Error) {
        self.request.fail(err)
    }

    fn timeout(self) {
        self.request.fail(Error::Timeout)
    }
}

