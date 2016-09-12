//! Service for stream transports.
//!
//! This implementation is seemingly too smart for some recursors
//! (particularly whatever runs on FritzBoxen) that seem to expect a
//! strict ping pong of requests and responses.

use std::fmt;
use std::io::{self, Read, Write};
use std::mem;
use std::time::Duration;
use futures::{Async, Future, Poll};
use futures::stream::Stream;
use tokio_core::channel::{Receiver, channel};
use tokio_core::io::IoFuture;
use tokio_core::reactor;
use ::bits::{ComposeBuf, ComposeBytes, ComposeResult, Message, MessageBuf,
             MessageBuilder, Question};
use super::pending::PendingRequests;
use super::request::{Request, RequestError};
use super::resolver::ServiceHandle;


//------------ StreamFactory -------------------------------------------------

pub trait StreamFactory: Send + 'static {
    type Stream: Read + Write + Send + 'static;
    type Future: Future<Item=Self::Stream, Error=io::Error> + Send + 'static;

    fn connect(&self, reactor: &reactor::Handle) -> Self::Future;
}


//------------ StreamService ------------------------------------------------

pub struct StreamService<S: StreamFactory> {
    state: State<S>,
    reactor: reactor::Handle,
    factory: S,
    keep_alive: Duration,
    request_timeout: Duration,
}

enum State<S: StreamFactory> {
    /// There is currently no request to work on and no open connection.
    ///
    /// In this state, we wait on the receiver for a request to come in. The
    /// state either ends with a new request, in which case we go into active,
    /// or the receiver having been closed, in which case we are done.
    Idle(IoFuture<Option<(Request, Receiver<Request>)>>),

    /// There are requests to be worked on and we are connecting.
    ///
    /// We need this separate state here since making `State::Active` a
    /// boxed future and chaining `ActiveStream` onto the connecting future
    /// would require `ActiveStream` to be `Send` which it can’t be because
    /// it contains a `reactor::Handle`. Spelling out the type doesn’t work
    /// either because `futures::AndThen` is generic over the chaining
    /// closure. (Or at least I think that’s what the compiler was trying
    /// to tell me …)
    Connecting(IoFuture<(S::Stream, Request, Receiver<Request>)>),

    /// There are requests to be worked on.
    ///
    /// When entering this state, we connect. Once that is successful, we
    /// send out all requests coming in on the receiver, read responses and
    /// match them to requests and thus complete them. We also keep a
    /// keep-alive timeout that is refreshed on every received request. If
    /// it triggers, we close the connection, fail all pending requests,
    /// and go into idle state.
    ///
    /// If the receiver disconnects, we clean out all cancelled pending
    /// requests, wait for all remaining requests to either be answered or
    /// time out, and then are done.
    Active(ActiveStream<S::Stream>)
}

impl<S: StreamFactory> StreamService<S> {
    pub fn new(reactor: reactor::Handle, factory: S, keep_alive: Duration,
               request_timeout: Duration) -> io::Result<ServiceHandle> {
        let (tx, rx) = try!(channel(&reactor));
        let service = StreamService {
            state: StreamService::<S>::idle(rx),
            reactor: reactor.clone(),
            factory: factory,
            keep_alive: keep_alive,
            request_timeout: request_timeout
        };
        let service = service.map_err(|_| ());
        reactor.spawn(service);
        Ok(ServiceHandle::from_sender(tx))
    }
}


impl<S: StreamFactory> Future for StreamService<S> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        let state = match self.state {
            State::Idle(ref mut fut) => {
                match try_ready!(fut.poll()) {
                    Some((request, recv)) => {
                        let connecting = self.factory.connect(&self.reactor);
                        let fut = connecting.and_then(move |stream| {
                            Ok((stream, request, recv))
                        });
                        State::Connecting(fut.boxed())
                    }
                    None => return Ok(Async::Ready(()))
                }
            }
            State::Connecting(ref mut fut) => {
                let (stream, request, recv) = try_ready!(fut.poll());
                let active = ActiveStream::new(stream, self.reactor.clone(),
                                               self.keep_alive,
                                               self.request_timeout,
                                               request, recv);
                State::Active(active)
            }
            State::Active(ref mut fut) => {
                match try_ready!(fut.poll()) {
                    Some(recv) => Self::idle(recv),
                    None => return Ok(Async::Ready(()))
                }
            }
        };
        self.state = state;
        self.poll()
    }
}

impl<S: StreamFactory> StreamService<S> {
    fn idle(recv: Receiver<Request>) -> State<S> {
        let fut = recv.into_future().then(|res| {
            match res {
                Ok((Some(request), recv)) => Ok(Some((request, recv))),
                Ok((None, _)) => Ok(None),
                Err((err, _)) => Err(err)
            }
        });
        State::Idle(fut.boxed())
    }
}


impl<S: StreamFactory> fmt::Debug for State<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            State::Idle(_) => "idle".fmt(f),
            State::Connecting(_) => "connecting".fmt(f),
            State::Active(_) => "active".fmt(f)
        }
    }
}

//------------ ActiveStream --------------------------------------------------

struct ActiveStream<T: Read + Write> {
    recv: Option<Receiver<Request>>,
    timeout: Option<reactor::Timeout>,
    stream: T,
    write: Option<WriteRequest>,
    read: ReadResponse,
    pending: PendingRequests<StreamRequest>,
    reactor: reactor::Handle,
    keep_alive: Duration,
}

impl<T: Read + Write> ActiveStream<T> {
    fn new(stream: T, reactor: reactor::Handle, keep_alive: Duration,
           request_timeout: Duration, request: Request,
           recv: Receiver<Request>) -> Self {
        let mut pending = PendingRequests::new(reactor.clone(),
                                               request_timeout);
        let write = new_write(request, &mut pending);
        ActiveStream {
            recv: Some(recv),
            timeout: reactor::Timeout::new(keep_alive, &reactor).ok(),
            stream: stream,
            write: write,
            read: ReadResponse::new(),
            pending: pending,
            reactor: reactor,
            keep_alive: keep_alive
        }
    }
}

impl<T: Read + Write> Future for ActiveStream<T> {
    type Item = Option<Receiver<Request>>;
    type Error = io::Error;

    /// Polls all our futures.
    ///
    /// We need to write as long as we can and have something, which may
    /// involve polling the receiver. We need to poll our timeout after that
    /// since the receiver may have changed the timeout and we need to
    /// register a new one with the task by polling it at least once.
    /// Additionally, we need to receive as long as there is something and
    /// remove all expired requests.
    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.poll_pending();
        loop {
            match try!(self.poll_write()) {
                Async::Ready(()) => {
                    match try!(self.poll_recv()) {
                        Async::Ready(Some(())) => {
                            // New request, try again right away.
                        }
                        Async::Ready(None) => {
                            return Ok(Async::Ready(self.recv.take()))
                        }
                        Async::NotReady => break
                    }
                }
                Async::NotReady => break
            }
        }
        if let Async::Ready(()) = try!(self.poll_timeout()) {
            return Ok(Async::Ready(self.recv.take()))
        }
        if let Async::Ready(()) = try!(self.poll_read()) {
            return Ok(Async::Ready(self.recv.take()))
        }
        Ok(Async::NotReady)
    }
}

impl<T: Read + Write> ActiveStream<T> {
    /// Polls the timeout.
    ///
    /// If it has hit, we are done.
    fn poll_timeout(&mut self) -> Poll<(), io::Error> {
        if let Some(ref mut timeout) = self.timeout {
            timeout.poll()
        }
        else {
            Ok(Async::NotReady)
        }
    }

    /// Drops all expired pending requests.
    fn poll_pending(&mut self) {
        self.pending.expire(|item| item.timeout());
    }

    /// Polls the receiver if necessary.
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
    fn poll_recv(&mut self) -> Poll<Option<()>, io::Error> {
        if let Some(ref mut recv) = self.recv {
            if self.write.is_none() {
                match try_ready!(recv.poll()) {
                    Some(request) => {
                        self.write = new_write(request, &mut self.pending);
                        self.timeout = reactor::Timeout::new(self.keep_alive,
                                                             &self.reactor)
                                                        .ok();
                        return Ok(Async::Ready(Some(())))
                    }
                    None => { }
                }
            }
            else { return Ok(Async::Ready(Some(()))) }
        }
        else {
            if self.pending.is_empty() { return Ok(Async::Ready(None)) }
            else { return Ok(Async::NotReady) }
        };
        self.recv = None;
        Ok(Async::NotReady)
    }

    /// Does the writing.
    ///
    /// Returns ready if it is done writing, not ready if it needs to write
    /// some more but can’t and error if there is an error.
    fn poll_write(&mut self) -> Poll<(), io::Error> {
        match self.write {
            Some(ref mut write) => try_ready!(write.write(&mut self.stream)),
            None => return Ok(Async::Ready(()))
        }
        let request = self.write.take().unwrap().done();
        self.pending.push(request.id(), request);
        Ok(Async::Ready(()))
    }

    /// Does the reading.
    ///
    /// Tries to read a new message. If we receive one, find the request for
    /// it and respond to it. If we receive `None`, the socket has been
    /// closed normally and we are done.
    fn poll_read(&mut self) -> Poll<(), io::Error> {
        loop {
            match try_ready!(self.read.read(&mut self.stream)) {
                Some(response) => {
                    let id = response.header().id();
                    if let Some(request) = self.pending.pop(id) {
                        request.respond(response)
                    }
                }
                None => return Ok(Async::Ready(()))
            }
        }
    }
}

fn new_write(request: Request, pending: &mut PendingRequests<StreamRequest>)
             -> Option<WriteRequest> {
    match pending.reserve() {
        Ok(id) => match WriteRequest::new(request, id) {
            Some(write) => Some(write),
            None => {
                pending.unreserve(id);
                None
            }
        },
        Err(_) => {
            request.fail(RequestError::Local);
            None
        }
    }
}

impl<T: Read + Write> Drop for ActiveStream<T> {
    fn drop(&mut self) {
        for item in self.pending.drain() {
            item.timeout()
        }
    }
}


//------------ WriteRequest --------------------------------------------------

struct WriteRequest {
    request: StreamRequest,
    pos: usize
}

impl WriteRequest {
    fn new(request: Request, id: u16) -> Option<Self> {
        if let Some(request) = StreamRequest::new(request, id) {
            Some(WriteRequest { request: request, pos: 0 })
        }
        else { None }
    }

    /// Tries to write the request to `stream`.
    ///
    /// Returns ready if the request was written completely, not ready if
    /// there is some more writing necessary, and error if there is an error.
    fn write<W: Write>(&mut self, stream: &mut W) -> Poll<(), io::Error> {
        let buf = self.request.as_ref();
        while self.pos < buf.len() {
            let n = try_nb!(stream.write(&buf[self.pos..]));
            self.pos += n;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero,
                                          "zero-length write"))
            }
        }
        Ok(Async::Ready(()))
    }

    fn done(self) -> StreamRequest {
        self.request
    }
}


//------------ ReadResponse --------------------------------------------------

struct ReadResponse {
    item: ReadItem,
    pos: usize,
}

impl ReadResponse {
    fn new() -> Self {
        ReadResponse { item: ReadItem::size(), pos: 0 }
    }

    fn read<R: Read>(&mut self, stream: &mut R)
                     -> Poll<Option<MessageBuf>, io::Error> {
        loop {
            let size = {
                let buf = &mut self.item.buf()[self.pos..];
                try_nb!(stream.read(buf))
            };
            if size == 0 {
                return Ok(Async::Ready(None))
            }
            self.pos += size;
            if self.pos == self.item.len() {
                let next_item = self.item.next_item();
                self.pos = 0;
                let item = mem::replace(&mut self.item, next_item);
                match item.finish() {
                    Some(message) => return Ok(Async::Ready(Some(message))),
                    None => { }
                }
            }
        }
    }
}


//------------ ReadItem -----------------------------------------------------

enum ReadItem {
    Size([u8; 2]),
    Message(Vec<u8>),
}

impl ReadItem {
    fn size() -> Self {
        ReadItem::Size([0; 2])
    }

    fn message(size: u16) -> Self {
        ReadItem::Message(vec![0; size as usize])
    }

    fn buf(&mut self) -> &mut [u8] {
        match *self {
            ReadItem::Size(ref mut data) => data,
            ReadItem::Message(ref mut data) => data,
        }
    }

    fn len(&self) -> usize {
        match *self {
            ReadItem::Size(_) => 2,
            ReadItem::Message(ref data) => data.len(),
        }
    }

    fn next_item(&self) -> Self {
        match *self {
            ReadItem::Size(ref data) => {
                let size = u16::from_be(unsafe { mem::transmute(*data) });
                ReadItem::message(size)
            }
            ReadItem::Message(_) => ReadItem::size()
        }
    }

    fn finish(self) -> Option<MessageBuf> {
        match self {
            ReadItem::Size(_) => None,
            // XXX Simply drops short messages. Should we log?
            ReadItem::Message(data) => MessageBuf::from_vec(data).ok()
        }
    }
}


//------------ StreamRequest -------------------------------------------------

struct StreamRequest {
    request: Request,
    id: u16,
    buf: Vec<u8>,
}

impl StreamRequest {
    fn new(request: Request, id: u16) -> Option<Self> {
        let buf = match StreamRequest::new_buf(&request, id) {
            Ok(buf) => buf,
            Err(_) => {
                request.fail(RequestError::Global);
                return None
            }
        };
        Some(StreamRequest{request: request, id: id, buf: buf})
    }

    fn new_buf(request: &Request, id: u16) -> ComposeResult<Vec<u8>> {
        let mut buf = ComposeBuf::new(Some(0xFFFF), true);
        let pos = buf.pos();
        buf.push_u16(0).unwrap();
        let mut buf = try!(MessageBuilder::from_target(buf));
        buf.header_mut().set_id(id);
        buf.header_mut().set_rd(true);
        try!(Question::push(&mut buf, &request.query().name,
                            request.query().rtype, request.query().class));
        let mut buf = try!(buf.finish());
        let size = buf.delta(pos) - 2;
        try!(buf.update_u16(pos, size as u16));
        Ok(buf.finish())
    }

    fn id(&self) -> u16 {
        self.id
    }

    fn respond(self, response: MessageBuf) {
        let request = Message::from_bytes(&self.buf[2..]).unwrap();
        if response.is_answer(&request) {
            self.request.succeed(response)
        }
        else {
            self.request.fail(RequestError::Local)
        }
    }

    fn timeout(self) {
        self.request.fail(RequestError::Timeout)
    }
}

impl AsRef<[u8]> for StreamRequest {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}



