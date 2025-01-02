//! Parsing DNS messages from the wire format.

use core::{fmt, ops::Range};

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

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

//--- Carrying over 'zerocopy' traits

// NOTE: We can't carry over 'read_from_prefix' because the trait impls would
// conflict.  We kept 'ref_from_prefix' since it's more general.

impl<'a, T: ?Sized> SplitFromMessage<'a> for &'a T
where
    T: FromBytes + KnownLayout + Immutable,
{
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let message = message.as_bytes();
        let bytes = message.get(start..).ok_or(ParseError)?;
        let (this, rest) = T::ref_from_prefix(bytes)?;
        Ok((this, message.len() - rest.len()))
    }
}

impl<'a, T: ?Sized> ParseFromMessage<'a> for &'a T
where
    T: FromBytes + KnownLayout + Immutable,
{
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        let message = message.as_bytes();
        let bytes = message.get(range).ok_or(ParseError)?;
        Ok(T::ref_from_bytes(bytes)?)
    }
}

//----------- Low-level parsing traits ---------------------------------------

/// Parsing from the start of a byte string.
pub trait SplitFrom<'a>: Sized + ParseFrom<'a> {
    /// Parse a value of [`Self`] from the start of the byte string.
    ///
    /// If parsing is successful, the parsed value and the rest of the string
    /// are returned.  Otherwise, a [`ParseError`] is returned.
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError>;
}

/// Parsing from a byte string.
pub trait ParseFrom<'a>: Sized {
    /// Parse a value of [`Self`] from the given byte string.
    ///
    /// If parsing is successful, the parsed value is returned.  Otherwise, a
    /// [`ParseError`] is returned.
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError>;
}

/// Zero-copy parsing from the start of a byte string.
///
/// # Safety
///
/// Every implementation of [`SplitBytesByRef`] must satisfy the invariants
/// documented on [`split_bytes_by_ref()`].  An incorrect implementation is
/// considered to cause undefined behaviour.
///
/// Implementing types should almost always be unaligned, but foregoing this
/// will not cause undefined behaviour (however, it will be very confusing for
/// users).
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
/// Implementing types should almost always be unaligned, but foregoing this
/// will not cause undefined behaviour (however, it will be very confusing for
/// users).
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

        return Ok(result);
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

unsafe impl<const N: usize> SplitBytesByRef for [u8; N] {
    fn split_bytes_by_ref(
        bytes: &[u8],
    ) -> Result<(&Self, &[u8]), ParseError> {
        if bytes.len() < N {
            Err(ParseError)
        } else {
            let (bytes, rest) = bytes.split_at(N);

            // SAFETY:
            // - It is known that 'bytes.len() == N'.
            // - Thus '&bytes' has the same layout as '[u8; N]'.
            // - Thus it is safe to cast a pointer to it to '[u8; N]'.
            // - The referenced data has the same lifetime as the output.
            Ok((unsafe { &*bytes.as_ptr().cast::<[u8; N]>() }, rest))
        }
    }
}

unsafe impl<const N: usize> ParseBytesByRef for [u8; N] {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        if bytes.len() != N {
            Err(ParseError)
        } else {
            // SAFETY:
            // - It is known that 'bytes.len() == N'.
            // - Thus '&bytes' has the same layout as '[u8; N]'.
            // - Thus it is safe to cast a pointer to it to '[u8; N]'.
            // - The referenced data has the same lifetime as the output.
            Ok(unsafe { &*bytes.as_ptr().cast::<[u8; N]>() })
        }
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        addr.cast()
    }
}

//--- Carrying over 'zerocopy' traits

// NOTE: We can't carry over 'read_from_prefix' because the trait impls would
// conflict.  We kept 'ref_from_prefix' since it's more general.

impl<'a, T: ?Sized> SplitFrom<'a> for &'a T
where
    T: FromBytes + KnownLayout + Immutable,
{
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        T::ref_from_prefix(bytes).map_err(|_| ParseError)
    }
}

impl<'a, T: ?Sized> ParseFrom<'a> for &'a T
where
    T: FromBytes + KnownLayout + Immutable,
{
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        T::ref_from_bytes(bytes).map_err(|_| ParseError)
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
