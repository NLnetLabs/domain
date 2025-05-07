//! Building DNS messages in the wire format.
//!
//! The [`wire`](super::wire) module provides basic serialization capability,
//! but it is not specialized to DNS messages.  This module provides that
//! specialization within an ergonomic interface.
//!
//! The core of the high-level interface is [`MessageBuilder`].  It provides
//! the most intuitive methods for appending whole questions and records.
//!
//! ```
//! use domain::new_base::{Header, HeaderFlags, Question, QType, QClass};
//! use domain::new_base::build::{BuilderContext, MessageBuilder, BuildInMessage};
//! use domain::new_base::name::RevName;
//! use domain::new_base::wire::U16;
//!
//! // Initialize a DNS message builder.
//! let mut buffer = [0u8; 512];
//! let mut context = BuilderContext::default();
//! let mut builder = MessageBuilder::new(&mut buffer, &mut context);
//!
//! // Initialize the message header.
//! let header = builder.header_mut();
//! *builder.header_mut() = Header {
//!     // Select a randomized ID here.
//!     id: U16::new(1234),
//!     // A recursive query for authoritative data.
//!     flags: *HeaderFlags::default()
//!         .set_qr(false)
//!         .set_opcode(0)
//!         .set_aa(true)
//!         .set_rd(true),
//!     counts: Default::default(),
//! };
//!
//! // Add a question for an A record.
//! // TODO: Use a more ergonomic way to make a name.
//! let name = b"\x00\x03org\x07example\x03www";
//! let name = unsafe { RevName::from_bytes_unchecked(name) };
//! let question = Question {
//!     qname: name,
//!     qtype: QType::A,
//!     qclass: QClass::IN,
//! };
//! let _ = builder.build_question(&question).unwrap().unwrap();
//!
//! // Use the built message.
//! let message = builder.message();
//! # let _ = message;
//! ```

mod message;
pub use message::{MessageBuildError, MessageBuilder};

pub use super::name::NameCompressor;
pub use super::wire::{AsBytes, BuildBytes, TruncationError};

//----------- BuildInMessage -------------------------------------------------

/// Building into a DNS message.
pub trait BuildInMessage {
    /// Write this object in a DNS message.
    ///
    /// The contents of the DNS message (i.e. the data after the 12-byte
    /// header) are stored in a byte buffer, provided here as `contents`.
    /// `self` will be serialized and written to `contents[start..]`.
    ///
    /// Upon success, the position future content should be written to is
    /// returned (i.e. `start` + the number of bytes written here).
    ///
    /// ## Errors
    ///
    /// Fails if the message buffer is too small to fit the object.  Parts of
    /// the message buffer (anything after `start`) may have been modified,
    /// but should not be considered part of the initialized message.  The
    /// caller should explicitly reset the name compressor to `start` to undo
    /// the effects of this function.
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        name: &mut NameCompressor,
    ) -> Result<usize, TruncationError>;
}

impl<T: ?Sized + BuildInMessage> BuildInMessage for &T {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        T::build_in_message(*self, contents, start, name)
    }
}

impl BuildInMessage for () {
    fn build_in_message(
        &self,
        _contents: &mut [u8],
        start: usize,
        _name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        Ok(start)
    }
}

impl BuildInMessage for u8 {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        match contents.get_mut(start..) {
            Some(&mut [ref mut b, ..]) => {
                *b = *self;
                Ok(start + 1)
            }
            _ => Err(TruncationError),
        }
    }
}

impl<T: BuildInMessage> BuildInMessage for [T] {
    /// Write a sequence of elements to a DNS message.
    ///
    /// If an element cannot be written due to a truncation error, the whole
    /// sequence is considered to have failed.  For more nuanced behaviour on
    /// truncation, build each element manually.
    fn build_in_message(
        &self,
        contents: &mut [u8],
        mut start: usize,
        name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        for item in self {
            start = item.build_in_message(contents, start, name)?;
        }
        Ok(start)
    }
}

impl<T: BuildInMessage, const N: usize> BuildInMessage for [T; N] {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        self.as_slice().build_in_message(contents, start, name)
    }
}

#[cfg(feature = "alloc")]
impl<T: ?Sized + BuildInMessage> BuildInMessage for alloc::boxed::Box<T> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        T::build_in_message(self, contents, start, name)
    }
}

#[cfg(feature = "alloc")]
impl<T: ?Sized + BuildInMessage> BuildInMessage for alloc::rc::Rc<T> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        T::build_in_message(self, contents, start, name)
    }
}

#[cfg(feature = "alloc")]
impl<T: ?Sized + BuildInMessage> BuildInMessage for alloc::sync::Arc<T> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        T::build_in_message(self, contents, start, name)
    }
}

#[cfg(feature = "alloc")]
impl<T: BuildInMessage> BuildInMessage for alloc::vec::Vec<T> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        self.as_slice().build_in_message(contents, start, name)
    }
}
