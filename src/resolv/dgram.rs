//! Service for datagram transport.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::time::Duration;
use futures::{Async, Future, Poll};
use futures::stream::Stream;
use tokio_core::channel::{Receiver, channel};
use tokio_core::reactor;
use ::bits::{ComposeMode, ComposeResult, MessageBuf, MessageBuilder,
             Question};
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
    ///
    /// If the receiver disconnects, we set this field to `None` and keep
    /// going until `self.pending` is empty.
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
    /// Tries to get a new request from the receiver if we don’t
    /// currently have anything to write. Or, if we don’t have a receiver
    /// anymore and no more pending requests either, we are done.
    ///
    /// Returns some ready if there is something to write, returns
    /// none ready if the receiver is disconnected and everything has
    /// expired, not ready if we are waiting for a new request (which sorta
    /// is also the case if the receiver has disconnected and there is still
    /// pending requests left), and error for an error.
    fn poll_recv(&mut self) -> Async<Option<()>> {
        if let Some(ref mut recv) = self.recv {
            if self.write.is_none() {
                match recv.poll() {
                    Ok(Async::Ready(Some(request))) => {
                        self.write = DgramRequest::new(request,
                                                       &mut self.pending,
                                                       self.msg_size);
                        return Async::Ready(Some(()))
                    }
                    Ok(Async::NotReady) => return Async::NotReady,
                    Ok(Async::Ready(None)) | Err(_) => { }
                }
            }
            else { return Async::NotReady }
        }
        else if self.pending.is_empty() { return Async::Ready(None) }
        else { return Async::NotReady };
        self.recv = None;
        Async::NotReady
    }

    /// Poll for writing.
    ///
    /// Returns ready if it is done writing, not ready if it needs to write
    /// some more but can’t and error if there is an error.
    fn poll_write(&mut self) -> Poll<(), io::Error> {
        let success = match self.write {
            Some(ref mut request) => {
                let written = try_nb!(self.sock.send_to(request.buf(),
                                                        &self.peer));
                written == request.buf().len()
            }
            None => return Ok(Async::Ready(()))
        };
        if let Some(request) = mem::replace(&mut self.write, None) {
            if success {
                self.pending.push(request.id(), request)
            }
            else {
                self.pending.unreserve(request.id());
                request.fail(io::Error::new(io::ErrorKind::Other,
                                            "short write").into());
            }
        }
        Ok(Async::Ready(()))
    }

    /// Polls for reading.
    ///
    /// Tries to read and dispatch messages. Returns `Ok()` if that ends
    /// all well with waiting for more messages or `Err(_)` if reading fails
    /// and this should be it.
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

    /// Poll the pending requests.
    ///
    /// That is, times out all expired requests.
    fn poll_pending(&mut self) {
        self.pending.expire(|item| item.timeout())
    }

}


//--- Future

impl<T: DgramTransport> Future for DgramService<T> {
    type Item = ();
    type Error = io::Error;

    /// Polls all inner futures.
    ///
    /// We need to write as long as we can and either have or can get
    /// something. We need to read as long as we can. And we need to ditch
    /// all expired requests.
    ///
    /// We are done if the receiver is done and there are no more requests
    /// left or if anything goes horribly wrong.
    fn poll(&mut self) -> Poll<(), io::Error> {
        self.poll_pending();
        while let Async::Ready(()) = try!(self.poll_write()) {
            match self.poll_recv() {
                Async::Ready(Some(())) => {
                    // New request, try writing right again.
                }
                Async::Ready(None) => {
                    return Ok(Async::Ready(()))
                }
                Async::NotReady => break
            }
        }
        try!(self.poll_read());
        Ok(Async::NotReady)
    }
}


//------------ DgramRequest --------------------------------------------------

/// A pending request of a datagram service.
struct DgramRequest {
    /// The actual request.
    request: Request,

    /// The message ID we assigned to it.
    ///
    /// Technically, we could fetch it out of `self.buf`, but this is
    /// quicker.
    id: u16,

    /// The outgoing message.
    buf: MessageBuf,
}

impl DgramRequest {
    /// Creates a new request.
    ///
    /// The request will be based on the given request and use an ID
    /// reserved within `pending`.
    ///
    /// Returns `Some(_)` if that all worked or `None` otherwise. If it
    /// fails, takes care of failing `request`, too.
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

    /// Creates the outgoing message.
    fn new_buf(request: &Request, id: u16, msg_size: usize)
               -> ComposeResult<MessageBuf> {
        let mut buf = try!(MessageBuilder::new(ComposeMode::Limited(msg_size),
                                               true));
        buf.header_mut().set_id(id);
        buf.header_mut().set_rd(true);
        try!(Question::push(&mut buf, &request.query().name,
                            request.query().rtype, request.query().class));
        Ok(MessageBuf::from_vec(try!(buf.finish()).finish()).unwrap())
    }

    /// Returns a reference to the bytes of the outgoing message.
    fn buf(&self) -> &[u8] {
        self.buf.as_bytes()
    }

    /// Returns the ID for this request.
    fn id(&self) -> u16 {
        self.id
    }

    /// Responds to the request with `response`.
    fn respond(self, response: MessageBuf) {
        if response.is_answer(&self.buf) {
            self.request.succeed(response)
        }
        else {
            self.request.fail(io::Error::new(io::ErrorKind::Other,
                                             "server error").into())
        }
    }

    /// Fails the request with `err`.
    fn fail(self, err: Error) {
        self.request.fail(err)
    }

    /// Fails the request with a timeout.
    fn timeout(self) {
        self.request.fail(Error::Timeout)
    }
}

