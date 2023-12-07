//! Trait for composing a request by applying limited changes.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use crate::base::opt::TcpKeepalive;
use crate::base::Header;
use crate::base::Message;

use std::boxed::Box;
use std::fmt::Debug;
use std::vec::Vec;

#[derive(Clone, Debug)]
/// Capture the various EDNS options.
pub enum OptTypes {
    /// TcpKeepalive variant
    TypeTcpKeepalive(TcpKeepalive),
}

/// A trait that allows composing a request as a series.
pub trait ComposeRequest: Debug + Send + Sync {
    /// Return a boxed dyn of the current object.
    fn as_box_dyn(&self) -> Box<dyn ComposeRequest>;

    /// Create a message that captures the recorded changes.
    fn to_message(&self) -> Message<Vec<u8>>;

    /// Create a message that captures the recorded changes and convert to
    /// a Vec.
    fn to_vec(&self) -> Vec<u8>;

    /// Return a reference to a mutable Header to record changes to the header.
    fn header_mut(&mut self) -> &mut Header;

    /// Set the UDP payload size.
    fn set_udp_payload_size(&mut self, value: u16);

    /// Add an EDNS option.
    fn add_opt(&mut self, opt: OptTypes);
}
