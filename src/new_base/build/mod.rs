//! Building DNS messages in the wire format.

use core::fmt;

use zerocopy::network_endian::{U16, U32};

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

impl BuildIntoMessage for [u8] {
    fn build_into_message(
        &self,
        mut builder: Builder<'_>,
    ) -> Result<(), TruncationError> {
        builder.append_bytes(self)?;
        builder.commit();
        Ok(())
    }
}

//----------- Low-level building traits --------------------------------------

/// Serializing into a byte string.
pub trait BuildBytes {
    /// Serialize into a byte string.
    ///
    /// `self` is serialized into a byte string and written to the given
    /// buffer.  If the buffer is large enough, the whole object is written
    /// and the remaining (unmodified) part of the buffer is returned.
    ///
    /// if the buffer is too small, a [`TruncationError`] is returned (and
    /// parts of the buffer may be modified).
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError>;
}

impl<T: ?Sized + BuildBytes> BuildBytes for &T {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        T::build_bytes(*self, bytes)
    }
}

impl BuildBytes for u8 {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        if let Some((elem, rest)) = bytes.split_first_mut() {
            *elem = *self;
            Ok(rest)
        } else {
            Err(TruncationError)
        }
    }
}

impl BuildBytes for str {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_bytes().build_bytes(bytes)
    }
}

impl BuildBytes for U16 {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_bytes().build_bytes(bytes)
    }
}

impl BuildBytes for U32 {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_bytes().build_bytes(bytes)
    }
}

impl<T: BuildBytes> BuildBytes for [T] {
    fn build_bytes<'b>(
        &self,
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        for elem in self {
            bytes = elem.build_bytes(bytes)?;
        }
        Ok(bytes)
    }
}

impl<T: BuildBytes, const N: usize> BuildBytes for [T; N] {
    fn build_bytes<'b>(
        &self,
        mut bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        for elem in self {
            bytes = elem.build_bytes(bytes)?;
        }
        Ok(bytes)
    }
}

/// Interpreting a value as a byte string.
///
/// # Safety
///
/// A type `T` can soundly implement [`AsBytes`] if and only if:
///
/// - It has no padding bytes.
/// - It has no interior mutability.
pub unsafe trait AsBytes {
    /// Interpret this value as a sequence of bytes.
    ///
    /// ## Invariants
    ///
    /// For the statement `let bytes = this.as_bytes();`,
    ///
    /// - `bytes.as_ptr() as usize == this as *const _ as usize`.
    /// - `bytes.len() == core::mem::size_of_val(this)`.
    ///
    /// The default implementation automatically satisfies these invariants.
    fn as_bytes(&self) -> &[u8] {
        // SAFETY:
        // - 'Self' has no padding bytes and no interior mutability.
        // - Its size in memory is exactly 'size_of_val(self)'.
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of_val(self),
            )
        }
    }
}

unsafe impl AsBytes for u8 {}
unsafe impl AsBytes for str {}

unsafe impl<T: AsBytes> AsBytes for [T] {}
unsafe impl<T: AsBytes, const N: usize> AsBytes for [T; N] {}

unsafe impl AsBytes for U16 {}
unsafe impl AsBytes for U32 {}

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
