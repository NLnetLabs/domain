//! Sending and receiving DNS messages.

use std::io;
use futures::Async;
use super::{ComposeMode, MessageBuf};

pub mod mpsc;
pub mod tcp;
pub mod udp;

mod stream;


/// A flow is a (possibly virtual) connection between two endpoints.
///
/// For connection oriented protocols, this is a connection. For
/// connection-less protocols, this is a virtual entity.
pub trait Flow {
    fn compose_mode(&self) -> ComposeMode;

    fn send(&mut self, msg: Vec<u8>) -> io::Result<Async<()>>;
    fn flush(&mut self) -> io::Result<Async<()>>;
    fn recv(&mut self) -> io::Result<Async<Option<MessageBuf>>>;
}


