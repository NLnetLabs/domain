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

#[derive(Clone, Debug)]
pub enum ComposeError {
    SizeExceeded,
    Overflow,
    ParseError(ParseError),
}

impl Error for ComposeError {
    fn description(&self) -> &str {
        use self::ComposeError::*;

        match *self {
            SizeExceeded => "message size has been exceeded",
            Overflow => "a counter has overflowed",
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


pub type ComposeResult<T> = Result<T, ComposeError>;


//------------ ParseError and ParseResult -----------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum ParseError {
    UnexpectedEnd,
    UnknownLabel,
    UnknownType,
    CompressedLabel,
}

impl Error for ParseError {
    fn description(&self) -> &str {
        use self::ParseError::*;

        match *self {
            UnexpectedEnd => "unexpected end of data",
            UnknownLabel => "unknown label type in domain name",
            UnknownType => "unknown type",
            CompressedLabel => "a compressed label was encountered",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.description().fmt(f)
    }
}

pub type ParseResult<T> = Result<T, ParseError>;


//------------ FromStrError and FromStrResult -------------------------------

#[derive(Clone, Debug)]
pub enum FromStrError {
    UnexpectedEnd,
    LongLabel,
    LongString,
    IllegalEscape,
    IllegalCharacter,
    UnknownType,
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

pub type FromStrResult<T> = Result<T, FromStrError>;

