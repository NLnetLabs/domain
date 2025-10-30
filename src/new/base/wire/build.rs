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

    /// The size of `self` when serialized into a byte sequence.
    ///
    /// This reports the exact number of bytes that will be written to the
    /// buffer passed to [`Self::build_bytes()`].  Note that this is not the
    /// cheapest operation; it may have to traverse all the fields in `self`.
    fn built_bytes_size(&self) -> usize;
}

impl<T: ?Sized + BuildBytes> BuildBytes for &T {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        T::build_bytes(*self, bytes)
    }

    fn built_bytes_size(&self) -> usize {
        T::built_bytes_size(*self)
    }
}

impl<T: ?Sized + BuildBytes> BuildBytes for &mut T {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        T::build_bytes(*self, bytes)
    }

    fn built_bytes_size(&self) -> usize {
        T::built_bytes_size(*self)
    }
}

impl BuildBytes for () {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        Ok(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        0
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

    fn built_bytes_size(&self) -> usize {
        1
    }
}

impl BuildBytes for str {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_bytes().build_bytes(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        self.len()
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

    fn built_bytes_size(&self) -> usize {
        self.iter().map(|e| e.built_bytes_size()).sum()
    }
}

impl<T: BuildBytes, const N: usize> BuildBytes for [T; N] {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_slice().build_bytes(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        self.as_slice().built_bytes_size()
    }
}

#[cfg(feature = "alloc")]
impl<T: ?Sized + BuildBytes> BuildBytes for alloc::boxed::Box<T> {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        T::build_bytes(self, bytes)
    }

    fn built_bytes_size(&self) -> usize {
        T::built_bytes_size(self)
    }
}

#[cfg(feature = "alloc")]
impl<T: BuildBytes> BuildBytes for alloc::vec::Vec<T> {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_slice().build_bytes(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        self.as_slice().built_bytes_size()
    }
}

#[cfg(feature = "alloc")]
impl BuildBytes for alloc::string::String {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        self.as_str().build_bytes(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        self.as_str().built_bytes_size()
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
/// ```no_run
/// # use domain::new::base::wire::{BuildBytes, U32, TruncationError};
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
///
///     fn built_bytes_size(&self) -> usize {
///         0 + self.a.built_bytes_size() + self.b.built_bytes_size()
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
/// ```no_run
/// # use domain::new::base::wire::{AsBytes, U32};
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

/// An object could not be serialized because it was too big.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TruncationError;

#[cfg(feature = "std")]
impl std::error::Error for TruncationError {}

//--- Formatting

impl fmt::Display for TruncationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object was too large to be serialized")
    }
}
