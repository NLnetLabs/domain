//! The channel abstraction.
//!
//! A `Channel` is something that know how to exchange DNS messages with
//! some concrete network endpoint.
//! 
//! This module contains the `Channel` trait implemented by all channel
//! implementations as well as the type `StreamChannel` and its accompanying
//! trait `ConnectStream` for building channels atop stream transports such
//! as TCP.

use std::{io, mem};
use std::io::{Read, Write};
use futures::{Async, AsyncSink, Future, Poll, StartSend};
use ::bits::MessageBuf;
use super::request::TransportRequest;


//------------ Channel -------------------------------------------------------

/// A channel knows how to exchange DNS messages with some network endpoint.
///
/// A value of a type implementing this trait represents the ability
/// to exchange DNS messages with a concrete network endpoint using one
/// given transport protocol with the type representing that protocol.
/// Channels are lazy in that they only acquire the necessary resources, such
/// as networking sockets, once they are actually needed.
///
/// A channel that currently holds no resources is said to be in
/// *sleep mode,* while one that does is said to be *active.* A new channel
/// starts out in sleep mode, an active channel can be sent to sleep via the
/// `sleep()` method. It will be woken implicitely when the next send
/// operation is started.
///
/// Sending and receiving happens asynchronously based on the model of
/// futures.
///
/// Sending is similar to futures’ `Sink` for `TranportRequest`s
/// except that a successfully sent request is returned to the caller for
/// further processing. A request is queued up for sending via the
/// `start_send()` method and then actual sending happens via `poll_send()`.
///
/// Receiving, via the `poll_recv()` method, is similar to a stream of owned
/// DNS messages except that the stream never ends.
pub trait Channel {
    /// Attempts to start sending a request.
    ///
    /// Unlike with futures’ `Sink`, this really only tries to queue up the
    /// request for sending. It does not attempt any actual sending of any
    /// kind. This solely happens through `poll_send()`.
    ///
    /// If the channel is currently in sleep mode, calling this method
    /// automatically wakes it up.
    fn start_send(&mut self, request: TransportRequest)
                  -> StartSend<TransportRequest, io::Error>;

    /// Polls for completion of sending.
    ///
    /// If sending a request completes, ready-returns the request. If there
    /// is currently nothing to send, ready-returns `None`. If sending
    /// blocks, returns not ready.
    fn poll_send(&mut self) -> Poll<Option<TransportRequest>, io::Error>;

    /// Polls for a received response.
    fn poll_recv(&mut self) -> Poll<MessageBuf, io::Error>;

    /// Sends the channel into sleep mode.
    ///
    /// The channel should surrender all helt resources, ie., close all its
    /// sockets. If there are any requests queued up for sending, the
    /// channel can quietly drop them. It is the channel owner’s
    /// responsibility to make sure that doesn’t happen or at least does not
    /// cause any harm.
    fn sleep(&mut self) -> Result<(), io::Error>;
}


//------------ ConnectStream -------------------------------------------------

/// A trait for starting a connection of a stream transport.
///
/// Values of this type contain all information about the peer of the
/// connected socket.
pub trait ConnectStream {
    /// The type for the connected stream socket.
    type Stream: io::Read + io::Write;

    /// The future representing the connection process.
    type Future: Future<Item=Self::Stream, Error=io::Error>;

    /// Starts connecting.
    fn connect(&self) -> Self::Future;
}


//------------ StreamChannel -------------------------------------------------

/// A channel for stream transport protocols.
///
/// Stream protocols are those that provide reliable, sequenced, two-way
/// transport. Most commonly, these are TCP and TLS.
///
/// This type is generic over the the `ConnectStream` trait which provides
/// the ability to create a stream socket when needed.
pub struct StreamChannel<C: ConnectStream> {
    /// The thing that makes new sockets.
    connect: C,

    /// What state our socket is currently in.
    sock: SockState<C>,

    /// The transport request we are currently sending out, if any.
    wr: Option<TransportRequest>,

    /// How far we have gotten with sending the current request.
    wr_pos: usize,

    /// The current target for receiving.
    ///
    /// The size of this is known at all times.
    rd: ReadItem,

    /// How much we have read of the read item so far.
    rd_pos: usize,
}

impl<C: ConnectStream> StreamChannel<C> {
    /// Creates a new stream channel using the given connector.
    pub fn new(connect: C) -> Self {
        StreamChannel {
            connect: connect,
            sock: SockState::Idle,
            wr: None,
            wr_pos: 0,
            rd: ReadItem::size(),
            rd_pos: 0
        }
    }
}


//--- Channel and its helpers.

impl<C: ConnectStream> Channel for StreamChannel<C> {
    fn start_send(&mut self, request: TransportRequest)
                  -> StartSend<TransportRequest, io::Error> {
        if self.wr.is_some() {
            return Ok(AsyncSink::NotReady(request))
        }
        self.wr = Some(request);
        self.wr_pos = 0;
        if let SockState::Idle = self.sock {
            self.sock = SockState::Connecting(self.connect.connect())
        }
        Ok(AsyncSink::Ready)
    }

    fn poll_send(&mut self) -> Poll<Option<TransportRequest>, io::Error> {
        if self.wr.is_none() { return Ok(Async::Ready(None)) }
        try_ready!(self.advance_sock());   
        try_ready!(self.send());
        Ok(Async::Ready(self.wr.take()))
    }

    fn poll_recv(&mut self) -> Poll<MessageBuf, io::Error> {
        {
            let sock = match self.sock {
                SockState::Active(ref mut sock) => sock,
                _ => return Ok(Async::NotReady)
            };
            loop { 
                let size = {
                    let buf = &mut self.rd.buf()[self.rd_pos..];
                    try_nb!(sock.read(buf))
                };
                if size == 0 {
                    // Socket closed. We take care of that after the loop.
                    break;
                }
                self.rd_pos += size;
                if self.rd_pos == self.rd.len() {
                    let next = self.rd.next_item();
                    self.rd_pos = 0;
                    let item = mem::replace(&mut self.rd, next);
                    if let Some(message) = item.finish() {
                        return Ok(Async::Ready(message))
                    }
                }
            }
        }
        self.sock = SockState::Idle;
        Ok(Async::NotReady)
    }

    fn sleep(&mut self) -> Result<(), io::Error> {
        self.sock = SockState::Idle;
        self.wr = None;
        self.rd = ReadItem::size();
        self.rd_pos = 0;
        Ok(())
    }
}

impl<C: ConnectStream> StreamChannel<C> {
    /// Tries to make sure that the socket is in active state.
    ///
    /// Must be used within a task. If it returns ready, there is an active
    /// socket. If it returns non-ready, there is not. And an error is an
    /// error as always.
    fn advance_sock(&mut self) -> Poll<(), io::Error> {
        let sock = match self.sock {
            SockState::Idle => return Ok(Async::NotReady),
            SockState::Connecting(ref mut fut) => try_ready!(fut.poll()),
            SockState::Active(_) => return Ok(Async::Ready(())),
        };
        self.sock = SockState::Active(sock);
        Ok(Async::Ready(()))
    }

    /// Tries to send all of a pending request.
    ///
    /// Must be used within a task. Returns ready if all of the request was
    /// send.
    fn send(&mut self) -> Poll<(), io::Error> {
        let wr = match self.wr {
            Some(ref wr) => wr,
            None => return Ok(Async::NotReady),
        };
        let mut msg = wr.message();
        let buf = msg.stream_bytes();
        let sock = match self.sock {
            SockState::Active(ref mut sock) => sock,
            _ => return Ok(Async::NotReady)
        };

        while self.wr_pos < buf.len() {
            let n = try_nb!(sock.write(&buf[self.wr_pos..]));
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::WriteZero,
                                          "zero-length write"))
            }
            self.wr_pos += n;
        }
        Ok(Async::Ready(()))
    }
}


//------------ SockState -----------------------------------------------------

/// The current state of a socket.
enum SockState<C: ConnectStream> {
    /// There is no socket (waves hands).
    Idle,

    /// The socket is currently connecting.
    Connecting(C::Future),

    /// The socket is active and ready for sending and receiving.
    Active(C::Stream),
}


//------------ ReadItem -----------------------------------------------------

/// A item to read on a stream transport.
///
/// Reading alternates between the two variants of this type. To a channel,
/// a value will look like a mutable buffer to read into. Once the channel
/// has filled the buffer, it can transform it into a the next item and
/// optionally a message.
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
    ///
    /// This will return `None` if the current item is `ReadItem::Size` or
    /// if parsing the vector of a `ReadItem::Message` into an owned
    /// message fails.
    fn finish(self) -> Option<MessageBuf> {
        match self {
            ReadItem::Size(_) => None,
            // XXX Simply drops short messages. Should we log?
            ReadItem::Message(data) => MessageBuf::from_vec(data).ok()
        }
    }
}

