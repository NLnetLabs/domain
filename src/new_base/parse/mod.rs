//! Parsing DNS messages from the wire format.

use core::{fmt, ops::Range};

use zerocopy::{
    network_endian::{U16, U32},
    FromBytes, IntoBytes,
};

mod message;
pub use message::{MessagePart, ParseMessage, VisitMessagePart};

mod question;
pub use question::{ParseQuestion, ParseQuestions, VisitQuestion};

mod record;
pub use record::{ParseRecord, ParseRecords, VisitRecord};

use super::Message;

//----------- Message-aware parsing traits -----------------------------------

/// A type that can be parsed from a DNS message.
pub trait SplitFromMessage<'a>: Sized + ParseFromMessage<'a> {
    /// Parse a value of [`Self`] from the start of a byte string within a
    /// particular DNS message.
    ///
    /// If parsing is successful, the parsed value and the rest of the string
    /// are returned.  Otherwise, a [`ParseError`] is returned.
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError>;
}

/// A type that can be parsed from a string in a DNS message.
pub trait ParseFromMessage<'a>: Sized {
    /// Parse a value of [`Self`] from a byte string within a particular DNS
    /// message.
    ///
    /// If parsing is successful, the parsed value is returned.  Otherwise, a
    /// [`ParseError`] is returned.
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError>;
}

impl<'a, T: ?Sized + SplitBytesByRef> SplitFromMessage<'a> for &'a T {
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let message = message.as_bytes();
        let bytes = message.get(start..).ok_or(ParseError)?;
        let (this, rest) = T::split_bytes_by_ref(bytes)?;
        Ok((this, message.len() - rest.len()))
    }
}

impl<'a, T: ?Sized + ParseBytesByRef> ParseFromMessage<'a> for &'a T {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        let message = message.as_bytes();
        let bytes = message.get(range).ok_or(ParseError)?;
        T::parse_bytes_by_ref(bytes)
    }
}

//----------- Low-level parsing traits ---------------------------------------

/// Parsing from the start of a byte string.
pub trait SplitBytes<'a>: Sized + ParseBytes<'a> {
    /// Parse a value of [`Self`] from the start of the byte string.
    ///
    /// If parsing is successful, the parsed value and the rest of the string
    /// are returned.  Otherwise, a [`ParseError`] is returned.
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError>;
}

/// Parsing from a byte string.
pub trait ParseBytes<'a>: Sized {
    /// Parse a value of [`Self`] from the given byte string.
    ///
    /// If parsing is successful, the parsed value is returned.  Otherwise, a
    /// [`ParseError`] is returned.
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError>;
}

impl<'a, T: ?Sized + SplitBytesByRef> SplitBytes<'a> for &'a T {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        T::split_bytes_by_ref(bytes).map_err(|_| ParseError)
    }
}

impl<'a, T: ?Sized + ParseBytesByRef> ParseBytes<'a> for &'a T {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        T::parse_bytes_by_ref(bytes).map_err(|_| ParseError)
    }
}

impl<'a> SplitBytes<'a> for u8 {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        bytes.split_first().map(|(&f, r)| (f, r)).ok_or(ParseError)
    }
}

impl<'a> ParseBytes<'a> for u8 {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let [result] = bytes else {
            return Err(ParseError);
        };

        Ok(*result)
    }
}

impl<'a> SplitBytes<'a> for U16 {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        Self::read_from_prefix(bytes).map_err(Into::into)
    }
}

impl<'a> ParseBytes<'a> for U16 {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        Self::read_from_bytes(bytes).map_err(Into::into)
    }
}

impl<'a> SplitBytes<'a> for U32 {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        Self::read_from_prefix(bytes).map_err(Into::into)
    }
}

impl<'a> ParseBytes<'a> for U32 {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        Self::read_from_bytes(bytes).map_err(Into::into)
    }
}

/// Zero-copy parsing from the start of a byte string.
///
/// This is an extension of [`ParseBytesByRef`] for types which can determine
/// their own length when parsing.  It is usually implemented by [`Sized`]
/// types (where the length is just the size of the type), although it can be
/// sometimes implemented by unsized types.
///
/// # Safety
///
/// Every implementation of [`SplitBytesByRef`] must satisfy the invariants
/// documented on [`split_bytes_by_ref()`].  An incorrect implementation is
/// considered to cause undefined behaviour.
///
/// [`split_bytes_by_ref()`]: Self::split_bytes_by_ref()
///
/// Note that [`ParseBytesByRef`], required by this trait, also has several
/// invariants that need to be considered with care.
pub unsafe trait SplitBytesByRef: ParseBytesByRef {
    /// Interpret a byte string as an instance of [`Self`].
    ///
    /// The byte string will be validated and re-interpreted as a reference to
    /// [`Self`].  The length of [`Self`] will be determined, possibly based
    /// on the contents (but not the length!) of the input, and the remaining
    /// bytes will be returned.  If the input does not begin with a valid
    /// instance of [`Self`], a [`ParseError`] is returned.
    ///
    /// ## Invariants
    ///
    /// For the statement `let (this, rest) = T::split_bytes_by_ref(bytes)?;`,
    ///
    /// - `bytes.as_ptr() == this as *const T as *const u8`.
    /// - `bytes.len() == core::mem::size_of_val(this) + rest.len()`.
    /// - `bytes.as_ptr().offset(size_of_val(this)) == rest.as_ptr()`.
    fn split_bytes_by_ref(bytes: &[u8])
        -> Result<(&Self, &[u8]), ParseError>;
}

/// Zero-copy parsing from a byte string.
///
/// # Safety
///
/// Every implementation of [`ParseBytesByRef`] must satisfy the invariants
/// documented on [`parse_bytes_by_ref()`] and [`ptr_with_address()`].  An
/// incorrect implementation is considered to cause undefined behaviour.
///
/// [`parse_bytes_by_ref()`]: Self::parse_bytes_by_ref()
/// [`ptr_with_address()`]: Self::ptr_with_address()
///
/// Implementing types must also have no alignment (i.e. a valid instance of
/// [`Self`] can occur at any address).  This eliminates the possibility of
/// padding bytes, even when [`Self`] is part of a larger aggregate type.
pub unsafe trait ParseBytesByRef {
    /// Interpret a byte string as an instance of [`Self`].
    ///
    /// The byte string will be validated and re-interpreted as a reference to
    /// [`Self`].  The whole byte string will be used.  If the input is not a
    /// valid instance of [`Self`], a [`ParseError`] is returned.
    ///
    /// ## Invariants
    ///
    /// For the statement `let this: &T = T::parse_bytes_by_ref(bytes)?;`,
    ///
    /// - `bytes.as_ptr() == this as *const T as *const u8`.
    /// - `bytes.len() == core::mem::size_of_val(this)`.
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError>;

    /// Change the address of a pointer to [`Self`].
    ///
    /// When [`Self`] is used as the last field in a type that also implements
    /// [`ParseBytesByRef`], it may be dynamically sized, and so a pointer (or
    /// reference) to it may include additional metadata.  This metadata is
    /// included verbatim in any reference/pointer to the containing type.
    ///
    /// When the containing type implements [`ParseBytesByRef`], it needs to
    /// construct a reference/pointer to itself, which includes this metadata.
    /// Rust does not currently offer a general way to extract this metadata
    /// or pair it with another address, so this function is necessary.  The
    /// caller can construct a reference to [`Self`], then change its address
    /// to point to the containing type, then cast that pointer to the right
    /// type.
    ///
    /// # Implementing
    ///
    /// Most users will derive [`ParseBytesByRef`] and so don't need to worry
    /// about this.  For manual implementations:
    ///
    /// In the future, an adequate default implementation for this function
    /// may be provided.  Until then, it should be implemented using one of
    /// the following expressions:
    ///
    /// ```ignore
    /// fn ptr_with_address(
    ///     &self,
    ///     addr: *const (),
    /// ) -> *const Self {
    ///     // If 'Self' is Sized:
    ///     addr.cast::<Self>()
    ///
    ///     // If 'Self' is an aggregate whose last field is 'last':
    ///     self.last.ptr_with_address(addr) as *const Self
    /// }
    /// ```
    ///
    /// # Invariants
    ///
    /// For the statement `let result = Self::ptr_with_address(ptr, addr);`:
    ///
    /// - `result as usize == addr as usize`.
    /// - `core::ptr::metadata(result) == core::ptr::metadata(ptr)`.
    fn ptr_with_address(&self, addr: *const ()) -> *const Self;
}

unsafe impl SplitBytesByRef for u8 {
    fn split_bytes_by_ref(
        bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        bytes.split_first().ok_or(ParseError)
    }
}

unsafe impl ParseBytesByRef for u8 {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        let [result] = bytes else {
            return Err(ParseError);
        };

        Ok(result)
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        addr.cast()
    }
}

unsafe impl SplitBytesByRef for U16 {
    fn split_bytes_by_ref(
        bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        Self::ref_from_prefix(bytes).map_err(Into::into)
    }
}

unsafe impl ParseBytesByRef for U16 {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        Self::ref_from_bytes(bytes).map_err(Into::into)
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        addr.cast()
    }
}

unsafe impl SplitBytesByRef for U32 {
    fn split_bytes_by_ref(
        bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        Self::ref_from_prefix(bytes).map_err(Into::into)
    }
}

unsafe impl ParseBytesByRef for U32 {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        Self::ref_from_bytes(bytes).map_err(Into::into)
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        addr.cast()
    }
}

unsafe impl ParseBytesByRef for [u8] {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        Ok(bytes)
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        core::ptr::slice_from_raw_parts(addr.cast(), self.len())
    }
}

unsafe impl ParseBytesByRef for str {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        core::str::from_utf8(bytes).map_err(|_| ParseError)
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        // NOTE: The Rust Reference indicates that 'str' has the same layout
        // as '[u8]' [1].  This is also the most natural layout for it.  Since
        // there's no way to construct a '*const str' from raw parts, we will
        // just construct a raw slice and transmute it.
        //
        // [1]: https://doc.rust-lang.org/reference/type-layout.html#str-layout

        self.as_bytes().ptr_with_address(addr) as *const Self
    }
}

unsafe impl<T: SplitBytesByRef, const N: usize> SplitBytesByRef for [T; N] {
    fn split_bytes_by_ref(
        mut bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        let start = bytes.as_ptr();
        for _ in 0..N {
            (_, bytes) = T::split_bytes_by_ref(bytes)?;
        }

        // SAFETY:
        // - 'T::split_bytes_by_ref()' was called 'N' times on successive
        //   positions, thus the original 'bytes' starts with 'N' instances
        //   of 'T' (even if 'T' is a ZST and so all instances overlap).
        // - 'N' consecutive 'T's have the same layout as '[T; N]'.
        // - Thus it is safe to cast 'start' to '[T; N]'.
        // - The referenced data has the same lifetime as the output.
        Ok((unsafe { &*start.cast::<[T; N]>() }, bytes))
    }
}

unsafe impl<T: SplitBytesByRef, const N: usize> ParseBytesByRef for [T; N] {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        let (this, rest) = Self::split_bytes_by_ref(bytes)?;
        if rest.is_empty() {
            Ok(this)
        } else {
            Err(ParseError)
        }
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        addr.cast()
    }
}

//----------- ParseError -----------------------------------------------------

/// A DNS message parsing error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ParseError;

//--- Formatting

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DNS data could not be parsed from the wire format")
    }
}

//--- Conversion from 'zerocopy' errors

impl<A, S, V> From<zerocopy::ConvertError<A, S, V>> for ParseError {
    fn from(_: zerocopy::ConvertError<A, S, V>) -> Self {
        Self
    }
}

impl<Src, Dst: ?Sized> From<zerocopy::SizeError<Src, Dst>> for ParseError {
    fn from(_: zerocopy::SizeError<Src, Dst>) -> Self {
        Self
    }
}
