//! Parsing DNS messages from the wire format.

/// Parsing from the start of a byte string.
pub trait SplitFrom<'a>: Sized {
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

/// A parse error.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ParseError;

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
