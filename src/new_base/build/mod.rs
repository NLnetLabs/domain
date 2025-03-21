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
//!     flags: *HeaderFlags::default()
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
//! let _ = builder.build_question(&question).unwrap().unwrap();
//!
//! // Use the built message.
//! let message = builder.message();
//! # let _ = message;
//! ```

mod builder;
pub use builder::Builder;

mod context;
pub use context::{BuilderContext, MessageState};

mod message;
pub use message::MessageBuilder;

mod question;
pub use question::QuestionBuilder;

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

impl BuildIntoMessage for u8 {
    fn build_into_message(&self, mut builder: Builder<'_>) -> BuildResult {
        builder.append_bytes(&[*self])?;
        Ok(builder.commit())
    }
}

impl<T: BuildIntoMessage> BuildIntoMessage for [T] {
    fn build_into_message(&self, mut builder: Builder<'_>) -> BuildResult {
        for elem in self {
            elem.build_into_message(builder.delegate())?;
        }
        Ok(builder.commit())
    }
}

impl<T: BuildIntoMessage, const N: usize> BuildIntoMessage for [T; N] {
    fn build_into_message(&self, builder: Builder<'_>) -> BuildResult {
        self.as_slice().build_into_message(builder)
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
