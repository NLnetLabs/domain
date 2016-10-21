//! Sending and receiving DNS messages.
//!
//! This module contains traits abstracting send and receiving of DNS
//! messages over the transport protocol as well as concrete types
//! implementing these traits for all supported protocols.
//!
//! The module abstracts over both connection-oriented protocols such as TCP
//! and connection-less protocols such as UDP. It does so by introducing the
//! concept of a flow which is a bi-directional stream of messages between
//! exactly two network endpoints, one local and one remote. For protocols
//! like TCP, flows are connections and thus have their very own underlying
//! socket. For UDP, flows sit on top of a single socket. When reading
//! messages, they are dispatched to their matching flow.
//!
//! While this may seem unnecessary wasteful for UDP, remember that we will
//! need to do things like rate limiting on a per-endpoint basis, anyway, so
//! having flows actually comes in handy.
//!
//! Flows implement the [`Flow`] trait defined herein. For server
//! implementations where flows are created by remote endpoints, a local
//! server represents the process of accepting new flows. There is no
//! separate trait for these. Instead, they simply are a `Stream` producing
//! something implementing [`Flow`].
//!
//! [`Flow`]: trait.Flow.html

use std::io;
use futures::Async;
use super::{ComposeMode, MessageBuf};

pub use self::tcp::{TcpServer, TcpFlow};
pub use self::udp::{UdpServer, UdpServerFlow, UdpClientFlow};

pub mod mpsc;

mod stream;
mod tcp;
mod udp;



/// A flow is a (possibly virtual) connection between two network endpoints.
///
/// For connection oriented protocols, this is a connection. For
/// connection-less protocols, this is a virtual entity.
pub trait Flow {
    /// Returns the most relaxed composition mode for responses.
    ///
    /// For stream protocols, this should be `ComposeMode::Stream`.
    /// For datagram protocols, this should be `ComposeMode::Limited(_)`
    /// with the attribute set to the largest size allowed by the underlying
    /// transport.
    fn compose_mode(&self) -> ComposeMode;

    /// Queues a message for sending to the remote endpoint of the flow.
    ///
    /// The message must have been produced by a [`Composer`] with a
    /// compose mode no less relaxed than the mode returned by the
    /// `compose_mode()` method. In particular, stream protocols require
    /// `ComposeMode::Stream` to properly interlace messages.
    ///
    /// The method will take ownership of the message and queue it up for
    /// later sending via [`flush()`]. No actual sending happens here.
    ///
    /// [`Composer`]: ../compose/struct.Composer.html
    /// [`flush()`]: #method.flush
    fn send(&mut self, msg: Vec<u8>) -> io::Result<()>;

    /// Tries to send any queued up messages.
    ///
    /// Since the underlying transport is non-blocking, messages may be
    /// queued up for sending. This method tries to send those messages.
    /// It is important to call this method every time during an
    /// implementation of `Future::poll()`.
    fn flush(&mut self) -> io::Result<Async<()>>;

    /// Tries to receive a new message.
    ///
    /// This methods behaves like a stream of messages. That is, it returns
    /// `Ok(Async::Ready(None))` to signal an orderly shutdown of the
    /// underlying socket by the remote endpoint.
    fn recv(&mut self) -> io::Result<Async<Option<MessageBuf>>>;
}

