//! Transport for DNS

use std::io;
use std::mem;
use futures::{Async, Future, Poll};
use futures::stream::Stream;
use tokio_core::reactor;
use ::bits::MessageBuf;
use super::request::ServiceRequest;


//------------ Write ---------------------------------------------------------

/// A trait for the write half of a transport connection.
///
/// This is similar to `tokio_core::io::WriteAll` but for requests and not
/// loosing the request on error. Every call to `write()` will exchange the
/// value for a future that will try to send the request and can then be
/// exchanged for the value again plus the request for further processing.
pub trait Write: Sized {
    type Future: Future<Item=(Self, ServiceRequest),
                        Error=(io::Error, ServiceRequest)>;

    fn write(self, request: ServiceRequest) -> Self::Future;
}


//------------ Read ----------------------------------------------------------

/// A trait for the read half of a transport connection.
///
/// This is simply a stream of messages.
pub trait Read: Stream<Item=MessageBuf, Error=io::Error> { }


//------------ Transport -----------------------------------------------------

/// A trait for a DNS transport.
///
/// A transport is able to create transport connections to a given DNS server.
pub trait Transport: 'static {
    /// The type of the read half of the transport connection.
    type Read: Read;

    /// The type of the write half of the transport connection.
    type Write: Write;

    /// The type of the future used for connecting.
    type Future: Future<Item=(Self::Read, Self::Write), Error=io::Error>;

    /// Creates a transport connection for this transport.
    ///
    /// The connection should use sockets created atop the given reactor
    /// handle. If connecting fails, the implementation has a choice of
    /// returning `Err` right away or later as part of the future.
    fn create(&self, reactor: &reactor::Handle) -> io::Result<Self::Future>;
}


//------------ StreamWriter --------------------------------------------------

/// The write half of a stream transport.
pub struct StreamWriter<W: io::Write>(W);

impl<W: io::Write> Write for StreamWriter<W> {
    type Future = StreamWriteRequest<W>;

    fn write(self, request: ServiceRequest) -> Self::Future {
        StreamWriteRequest::new(self.0, request)
    }
}

impl<W: io::Write> From<W> for StreamWriter<W> {
    fn from(w: W) -> Self {
        StreamWriter(w)
    }
}


//------------ StreamWriteRequest --------------------------------------------

/// The future of the write half of a stream transport.
pub struct StreamWriteRequest<W: io::Write> {
    state: WriteState<W>
}

enum WriteState<W> {
    Writing {
        w: W,
        req: ServiceRequest,
        pos: usize
    },
    Done
}

impl<W: io::Write> StreamWriteRequest<W> {
    fn new(writer: W, request: ServiceRequest) -> Self {
        StreamWriteRequest {
            state: WriteState::Writing {
                w: writer,
                req: request,
                pos: 0
            }
        }
    }

    fn write(w: &mut W, req: &mut ServiceRequest, pos: &mut usize)
             -> Poll<(), io::Error> {
        let buf = req.stream_bytes();
        while *pos < buf.len() {
            let n = try_nb!(w.write(&buf[*pos..]));
            *pos += n;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero,
                                          "zero-length write"))
            }
        }
        Ok(Async::Ready(()))
    }
}

impl<W: io::Write> Future for StreamWriteRequest<W> {
    type Item = (StreamWriter<W>, ServiceRequest);
    type Error = (io::Error, ServiceRequest);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let res = match self.state {
            WriteState::Writing { ref mut w, ref mut req, ref mut pos } => {
                Self::write(w, req, pos)
            }
            WriteState::Done => {
                panic!("polling a resolved StreamWriteRequest");
            }
        };
        let res = match res {
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Ok(Async::Ready(())) => Ok(()),
            Err(err) => Err(err)
        };

        match mem::replace(&mut self.state, WriteState::Done) {
            WriteState::Writing { w, req, .. } => {
                match res {
                    Ok(()) => Ok((StreamWriter(w), req).into()),
                    Err(err) => Err((err, req))
                }
            }
            WriteState::Done => panic!()
        }
    }
}


//------------ StreamReader -------------------------------------------------

/// The read half of a stream transport.
pub struct StreamReader<R: io::Read> {
    reader: R,
    item: ReadItem,
    pos: usize
}

impl<R: io::Read> StreamReader<R> {
    pub fn new(reader: R) -> Self {
        StreamReader {
            reader: reader,
            item: ReadItem::size(),
            pos: 0
        }
    }
}

impl<R: io::Read> Read for StreamReader<R> { }

impl<R: io::Read> Stream for StreamReader<R> {
    type Item = MessageBuf;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            let size = {
                let buf = &mut self.item.buf()[self.pos..];
                try_nb!(self.reader.read(buf))
            };
            if size == 0 {
                return Ok(Async::Ready(None))
            }
            self.pos += size;
            if self.pos == self.item.len() {
                let next_item = self.item.next_item();
                self.pos = 0;
                let item = mem::replace(&mut self.item, next_item);
                if let Some(message) = item.finish() {
                    return Ok(Async::Ready(Some(message)))
                }
            }
        }

    }
}

impl<R: io::Read> From<R> for StreamReader<R> {
    fn from(r: R) -> Self {
        StreamReader::new(r)
    }
}


//------------ ReadItem -----------------------------------------------------

/// A item to read on a stream transport.
enum ReadItem {
    /// The size shim preceeding the actual message.
    Size([u8; 2]),

    /// The actual message.
    ///
    /// The vector will start out with the size read first.
    Message(Vec<u8>),
}

impl ReadItem {
    /// Creates a new `ReadItem::Size` item.
    fn size() -> Self {
        ReadItem::Size([0; 2])
    }

    /// Creates a new `ReadItem::Messge` item of the given size.
    fn message(size: u16) -> Self {
        ReadItem::Message(vec![0; size as usize])
    }

    /// Returns the bytes buffer for current read item.
    fn buf(&mut self) -> &mut [u8] {
        match *self {
            ReadItem::Size(ref mut data) => data,
            ReadItem::Message(ref mut data) => data,
        }
    }

    /// Returns the size of the current read item.
    fn len(&self) -> usize {
        match *self {
            ReadItem::Size(_) => 2,
            ReadItem::Message(ref data) => data.len(),
        }
    }

    /// Returns the item that should replace the current item.
    fn next_item(&self) -> Self {
        match *self {
            ReadItem::Size(ref data) => {
                let size = u16::from_be(unsafe { mem::transmute(*data) });
                ReadItem::message(size)
            }
            ReadItem::Message(_) => ReadItem::size()
        }
    }

    /// Extracts the message from the current item if it is a message item.
    fn finish(self) -> Option<MessageBuf> {
        match self {
            ReadItem::Size(_) => None,
            // XXX Simply drops short messages. Should we log?
            ReadItem::Message(data) => MessageBuf::from_vec(data).ok()
        }
    }
}


