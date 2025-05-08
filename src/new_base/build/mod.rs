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
//! use domain::new_base::{
//!     Header, HeaderFlags, Message,
//!     Question, QType, QClass,
//!     Record, RType, RClass,
//! };
//! use domain::new_base::build::{AsBytes, MessageBuilder, NameCompressor};
//! use domain::new_base::name::RevNameBuf;
//! use domain::new_base::wire::U16;
//! use domain::new_rdata::RecordData;
//!
//! // Initialize a DNS message builder.
//! let mut buffer = [0u8; 512];
//! let mut compressor = NameCompressor::default();
//! let mut builder = MessageBuilder::new(
//!     &mut buffer,
//!     &mut compressor,
//!     // Select a randomized ID here.
//!     U16::new(1234),
//!     // A response to a recursive query for authoritative data.
//!     *HeaderFlags::default()
//!         .set_qr(true)
//!         .set_opcode(0)
//!         .set_aa(true)
//!         .set_rd(true)
//!         .set_rcode(0));
//!
//! // Add a question for an A record.
//! builder.push_question(&Question {
//!     qname: "www.example.org".parse::<RevNameBuf>().unwrap(),
//!     qtype: QType::A,
//!     qclass: QClass::IN,
//! }).unwrap();
//!
//! // Add an answer.
//! builder.push_answer(&Record {
//!     rname: "www.example.org".parse::<RevNameBuf>().unwrap(),
//!     rtype: RType::A,
//!     rclass: RClass::IN,
//!     ttl: 3600.into(),
//!     rdata: <RecordData<'_, ()>>::A("127.0.0.1".parse().unwrap()),
//! }).unwrap();
//!
//! // Use the built message (e.g. send it).
//! let message: &mut Message = builder.finish();
//! let bytes: &[u8] = message.as_bytes();
//! # let _ = bytes;
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
