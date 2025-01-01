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

/// Zero-copy parsing from a byte string.
///
/// # Safety
///
/// Every implementation of [`ParseBytesByRef`] must satisfy the invariants
/// documented on [`parse_bytes_by_ref()`].  An incorrect implementation is
/// considered to cause undefined behaviour.
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
