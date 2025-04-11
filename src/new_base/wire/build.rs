//! Building data in the basic network format.

use core::fmt;

//----------- BuildBytes -----------------------------------------------------

/// Serializing into a byte sequence.
pub trait BuildBytes {
    /// Serialize into a byte sequence.
    ///
    /// `self` is serialized into a byte sequence and written to the given
    /// buffer.  If the buffer is large enough, the whole object is written
    /// and the remaining (unmodified) part of the buffer is returned.
    ///
    /// If the buffer is too small, a [`TruncationError`] is returned (and
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

impl<T: ?Sized + BuildBytes> BuildBytes for &mut T {
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
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_slice().build_bytes(bytes)
    }
}

#[cfg(feature = "std")]
impl<T: ?Sized + BuildBytes> BuildBytes for std::boxed::Box<T> {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        T::build_bytes(self, bytes)
    }
}

#[cfg(feature = "std")]
impl<T: BuildBytes> BuildBytes for std::vec::Vec<T> {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_slice().build_bytes(bytes)
    }
}

#[cfg(feature = "std")]
impl BuildBytes for std::string::String {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_str().build_bytes(bytes)
    }
}

/// Deriving [`BuildBytes`] automatically.
///
/// [`BuildBytes`] can be derived on `struct`s (not `enum`s or `union`s).  The
/// generated implementation will call [`build_bytes()`] with each field, in
/// the order they are declared.  The trait implementation will be bounded by
/// the type of every field implementing [`BuildBytes`].
///
/// [`build_bytes()`]: BuildBytes::build_bytes()
///
/// Here's a simple example:
///
/// ```
/// # use domain::new_base::wire::{BuildBytes, U32, TruncationError};
/// struct Foo<T> {
///     a: U32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T> { data: T }
///
/// // The generated impl with 'derive(BuildBytes)':
/// impl<T> BuildBytes for Foo<T>
/// where Bar<T>: BuildBytes {
///     fn build_bytes<'bytes>(
///         &self,
///         mut bytes: &'bytes mut [u8],
///     ) -> Result<&'bytes mut [u8], TruncationError> {
///         bytes = self.a.build_bytes(bytes)?;
///         bytes = self.b.build_bytes(bytes)?;
///         Ok(bytes)
///     }
/// }
/// ```
pub use domain_macros::BuildBytes;

//----------- AsBytes --------------------------------------------------------

/// Interpreting a value as a byte sequence.
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

/// Deriving [`AsBytes`] automatically.
///
/// [`AsBytes`] can be derived on `struct`s (not `enum`s or `union`s), where a
/// fixed memory layout (`repr(C)` or `repr(transparent)`) is used.  Every
/// field must implement [`AsBytes`].
///
/// Here's a simple example:
///
/// ```
/// # use domain::new_base::wire::{AsBytes, U32};
/// #[repr(C)]
/// struct Foo<T> {
///     a: U32,
///     b: Bar<T>,
/// }
///
/// # struct Bar<T> { data: T }
///
/// // The generated impl with 'derive(AsBytes)':
/// unsafe impl<T> AsBytes for Foo<T>
/// where Bar<T>: AsBytes {
///     // The default implementation of 'as_bytes()' works.
/// }
/// ```
pub use domain_macros::AsBytes;

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
