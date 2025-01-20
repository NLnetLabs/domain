//! Building DNS messages in the wire format.
//!
//! The [`wire`](super::wire) module provides basic serialization capability,
//! but it is not specialized to DNS messages.  This module provides that
//! specialization within an ergonomic interface.
//!
//! # The High-Level Interface
//!
//! The core of the high-level interface is [`MessageBuilder`].  It provides
//! the most intuitive methods for appending whole questions and records.
//!
//! ```
//! use domain::new_base::{Header, HeaderFlags, Question, QType, QClass};
//! use domain::new_base::build::{BuilderContext, MessageBuilder, BuildIntoMessage};
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
//!     flags: HeaderFlags::default()
//!         .query(0)
//!         .set_authoritative(true)
//!         .request_recursion(true),
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
//! builder.append_question(&question).unwrap();
//!
//! // Use the built message.
//! let message = builder.message();
//! # let _ = message;
//! ```
//!
//! # The Low-Level Interface
//!
//! [`Builder`] is a powerful low-level interface that can be used to build
//! DNS messages.  It implements atomic building and name compression, and is
//! the foundation of [`MessageBuilder`].
//!
//! The [`Builder`] interface does not know about questions and records; it is
//! only capable of appending simple bytes and compressing domain names.  Its
//! access to the message buffer is limited; it can only append, modify, or
//! truncate the message up to a certain point (all data before that point is
//! immutable).  Special attention is given to the message header, as it can
//! be modified at any point in the message building process.
//!
//! ```
//! use domain::new_base::build::{BuilderContext, Builder, BuildIntoMessage};
//! use domain::new_rdata::A;
//!
//! // Construct a builder for a particular buffer.
//! let mut buffer = [0u8; 20];
//! let mut context = BuilderContext::default();
//! let mut builder = Builder::new(&mut buffer, &mut context);
//!
//! // Try appending some raw bytes to the builder.
//! builder.append_bytes(b"hi! ").unwrap();
//! assert_eq!(builder.appended(), b"hi! ");
//!
//! // Try appending some structured content to the builder.
//! A::from(std::net::Ipv4Addr::new(127, 0, 0, 1))
//!     .build_into_message(builder.delegate())
//!     .unwrap();
//! assert_eq!(builder.appended(), b"hi! \x7F\x00\x00\x01");
//!
//! // Finish using the builder.
//! builder.commit();
//!
//! // Note: the first 12 bytes hold the message header.
//! assert_eq!(&buffer[12..20], b"hi! \x7F\x00\x00\x01");
//! ```

mod builder;
pub use builder::{Builder, BuilderContext};

mod message;
pub use message::MessageBuilder;

mod record;
pub use record::RecordBuilder;

use super::wire::TruncationError;

//----------- Message-aware building traits ----------------------------------

/// Building into a DNS message.
pub trait BuildIntoMessage {
    // Append this value to the DNS message.
    ///
    /// If the builder has enough capacity to fit the message, it is appended
    /// and committed.   Otherwise, a [`TruncationError`] is returned.
    fn build_into_message(&self, builder: Builder<'_>) -> BuildResult;
}

impl<T: ?Sized + BuildIntoMessage> BuildIntoMessage for &T {
    fn build_into_message(&self, builder: Builder<'_>) -> BuildResult {
        (**self).build_into_message(builder)
    }
}

impl BuildIntoMessage for [u8] {
    fn build_into_message(&self, mut builder: Builder<'_>) -> BuildResult {
        builder.append_bytes(self)?;
        Ok(builder.commit())
    }
}

//----------- BuildResult ----------------------------------------------------

/// The result of building into a DNS message.
///
/// This is used in [`BuildIntoMessage::build_into_message()`].
pub type BuildResult = Result<BuildCommitted, TruncationError>;

//----------- BuildCommitted -------------------------------------------------

/// The output of [`Builder::commit()`].
///
/// This is a simple marker type, produced by [`Builder::commit()`].  Certain
/// trait methods (e.g. [`BuildIntoMessage::build_into_message()`]) require it
/// in the return type, as a way to remind users to commit their builders.
///
/// # Examples
///
/// If `build_into_message()` simply returned a unit type, an example impl may
/// look like:
///
/// ```compile_fail
/// # use domain::new_base::name::RevName;
/// # use domain::new_base::build::{BuildIntoMessage, Builder, BuildResult};
/// # use domain::new_base::wire::AsBytes;
///
/// struct Foo<'a>(&'a RevName, u8);
///
/// impl BuildIntoMessage for Foo<'_> {
///     fn build_into_message(
///         &self,
///         mut builder: Builder<'_>,
///     ) -> BuildResult {
///         builder.append_name(self.0)?;
///         builder.append_bytes(self.1.as_bytes());
///         Ok(())
///     }
/// }
/// ```
///
/// This code is incorrect: since the appended content is not committed, the
/// builder will remove it when it is dropped (at the end of the function),
/// and so nothing gets written.  Instead, users have to write:
///
/// ```
/// # use domain::new_base::name::RevName;
/// # use domain::new_base::build::{BuildIntoMessage, Builder, BuildResult};
/// # use domain::new_base::wire::AsBytes;
///
/// struct Foo<'a>(&'a RevName, u8);
///
/// impl BuildIntoMessage for Foo<'_> {
///     fn build_into_message(
///         &self,
///         mut builder: Builder<'_>,
///     ) -> BuildResult {
///         builder.append_name(self.0)?;
///         builder.append_bytes(self.1.as_bytes());
///         Ok(builder.commit())
///     }
/// }
/// ```
#[derive(Debug)]
pub struct BuildCommitted;
