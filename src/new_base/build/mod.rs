//! Building DNS messages in the wire format.

use core::fmt;

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
