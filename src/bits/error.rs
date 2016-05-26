//! Errors and results.
//!
//! There are three different pairs of errors and results related to the
//! three different operations that can fail:
//!
//! `ParseError` and `ParseResult` are used when parsing DNS data from its
//! wire-format.
//!
//! `ComposeError` and `ComposeResult` are used when composing DNS wire-format
//! data.
//!
//! `FromStrError` and `FromStrResult` are used when converting data from
//! strings.

use std::error::Error;
use std::fmt;


//------------ ComposeError and ComposeResult -------------------------------

/// An error happening when composing wire-format DNS data.
#[derive(Clone, Debug, PartialEq)]
pub enum ComposeError {
    /// The maximum size of the message has been exceeded.
    SizeExceeded,

    /// An internal counter has overflown.
    ///
    /// Examples of these are record counters for the various sections in the
    /// message header.
    Overflow,

    /// A `ParseError` has happened while preparing data for composing.
    ///
    /// Since we are trying to be as lazy as possible, parse errors can
    /// happen very late. For instance, when writing a lazy domain name,
    /// that name is only checked when it is being written and may contain
    /// invalid references.
    ParseError(ParseError),
}

impl Error for ComposeError {
    fn description(&self) -> &str {
        use self::ComposeError::*;

        match *self {
            SizeExceeded => "message size has been exceeded",
            Overflow => "a counter has overflown",
            ParseError(ref error) => error.description(),
        }
    }
}

impl From<ParseError> for ComposeError {
    fn from(error: ParseError) -> ComposeError {
        ComposeError::ParseError(error)
    }
}

impl fmt::Display for ComposeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.description().fmt(f)
    }
}


/// The result type for a `ComposeError`.
pub type ComposeResult<T> = Result<T, ComposeError>;


//------------ ParseError and ParseResult -----------------------------------

/// An error happening during parsing of wire-format DNS data.
#[derive(Clone, Debug, PartialEq)]
pub enum ParseError {
    /// The raw data ended unexpectedly in the middle of a structure.
    UnexpectedEnd,

    /// An unknown label type was encountered in a domain name.
    ///
    /// Several possible values for label types are not currently assigned
    /// (and likely never will). This is fatal since the label type defines
    /// how a label is parsed.
    UnknownLabel,

    /// A compressed label was encountered in a `DNameRef` or `OwnedDName`.
    CompressedLabel,
}

impl Error for ParseError {
    fn description(&self) -> &str {
        use self::ParseError::*;

        match *self {
            UnexpectedEnd => "unexpected end of data",
            UnknownLabel => "unknown label type in domain name",
            CompressedLabel => "a compressed label was encountered",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.description().fmt(f)
    }
}

/// The result type for a `ParseError`.
pub type ParseResult<T> = Result<T, ParseError>;


//------------ FromStrError and FromStrResult -------------------------------

/// An error happening while creating a DNS value from a string.
#[derive(Clone, Debug)]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    UnexpectedEnd,

    /// A domain name label has more than 63 octets.
    LongLabel,

    /// A character string has more than 255 octets.
    LongString,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    IllegalCharacter,

    /// An unknown record type name was encountered.
    UnknownType,

    /// An unknown class name was encountered.
    UnknownClass,
}

impl Error for FromStrError {
    fn description(&self) -> &str {
        use self::FromStrError::*;

        match *self {
            UnexpectedEnd => "unexpected end of input",
            LongLabel => "domain name label with more than 63 octets",
            LongString => "character string with more than 255 octets",
            IllegalEscape => "illegal escape sequence",
            IllegalCharacter => "illegal character",
            UnknownType => "unknown type",
            UnknownClass => "unknown class",
        }
    }
}

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.description().fmt(f)
    }
}

/// The result type for a `FromStrError`.
pub type FromStrResult<T> = Result<T, FromStrError>;

