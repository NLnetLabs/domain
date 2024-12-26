//! Building DNS messages in the wire format.

use core::fmt;

mod builder;
pub use builder::{Builder, BuilderContext};

//----------- Message-aware building traits ----------------------------------

/// Building into a DNS message.
pub trait BuildIntoMessage {
    // Append this value to the DNS message.
    ///
    /// If the byte string is long enough to fit the message, it is appended
    /// using the given message builder and committed.   Otherwise, a
    /// [`TruncationError`] is returned.
    fn build_into_message(
        &self,
        builder: Builder<'_>,
    ) -> Result<(), TruncationError>;
}

impl<T: ?Sized + BuildIntoMessage> BuildIntoMessage for &T {
    fn build_into_message(
        &self,
        builder: Builder<'_>,
    ) -> Result<(), TruncationError> {
        (**self).build_into_message(builder)
    }
}

//----------- Low-level building traits --------------------------------------

/// Building into a byte string.
pub trait BuildInto {
    /// Append this value to the byte string.
    ///
    /// If the byte string is long enough to fit the message, the remaining
    /// (unfilled) part of the byte string is returned.   Otherwise, a
    /// [`TruncationError`] is returned.
    fn build_into<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError>;
}

impl<T: ?Sized + BuildInto> BuildInto for &T {
    fn build_into<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        (**self).build_into(bytes)
    }
}

//----------- TruncationError ------------------------------------------------

/// A DNS message did not fit in a buffer.
#[derive(Clone, Debug, PartialEq, Hash)]
pub struct TruncationError;

//--- Formatting

impl fmt::Display for TruncationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("A buffer was too small to fit a DNS message")
    }
}
