//! Trait for building a message by applying changes to a base message.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use crate::base::Header;
use crate::base::Message;
//use crate::base::message_builder::OptBuilder;
use crate::base::opt::TcpKeepalive;

use std::boxed::Box;
use std::fmt::Debug;
use std::vec::Vec;

#[derive(Clone, Debug)]
/// Capture the various EDNS options.
pub enum OptTypes {
    /// TcpKeepalive variant
    TypeTcpKeepalive(TcpKeepalive),
}

/// A trait that allows construction of a message as a series to changes to
/// an existing message.
pub trait BaseMessageBuilder: Debug + Send + Sync {
    /// Return a boxed dyn of the current object.
    fn as_box_dyn(&self) -> Box<dyn BaseMessageBuilder>;

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
