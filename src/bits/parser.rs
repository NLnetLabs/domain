//! Traits and implementations for parsing.

use std::error;
use std::fmt;
use byteorder::{BigEndian, ByteOrder};


//------------ Parser --------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
    limit: usize,
}

impl<'a> Parser<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Parser{limit: bytes.len(), bytes: bytes, pos: 0}
    }

    /// Limits the parser to `len` bytes from its current position.
    ///
    /// If the limit would be beyond the end of the parser, returns
    /// `Err(ParseError::UnexpectedEnd)`.
    pub fn set_limit(&mut self, len: usize) -> ParseResult<()> {
        let limit = self.pos + len;
        if len > self.bytes.len() {
            Err(ParseError::UnexpectedEnd)
        }
        else {
            self.limit = limit;
            Ok(())
        }
    }

    /// Removes any limit from the parser.
    pub fn remove_limit(&mut self) {
        self.limit = self.bytes.len()
    }
}

impl<'a> Parser<'a> {
    /// Returns a reference to the complete message.
    ///
    /// The returned slice contains all bytes. It disregards the current
    /// position and any limit.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Returns the current parser position.
    ///
    /// This is the index in `self.bytes()` where the next octet would be
    /// read.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the number of bytes left to parse.
    ///
    /// If a limit is set, the returned number is up until that limit.
    pub fn remaining(&self) -> usize {
        self.limit - self.pos
    }

    /// Resets the position of the parser.
    ///
    /// The new position is relative to the beginning of the parser’s message.
    /// The function fails if the position is beyond the end of the message
    /// or, if a limit is set, beyond the limit. In either case, the
    /// function will return `Err(ParseError::UnexpectedEnd)`.
    pub fn seek(&mut self, pos: usize) -> ParseResult<()> {
        if pos > self.limit {
            Err(ParseError::UnexpectedEnd)
        }
        else {
            self.pos = pos;
            Ok(())
        }
    }
}

impl<'a> Parser<'a> {
    /// Skips over `len` bytes.
    ///
    /// If this would go beyond the current limit or the end of the message,
    /// returns `Err(ParseError::UnexpectedEnd)`.
    pub fn skip(&mut self, len: usize) -> ParseResult<()> {
        self.parse_bytes(len).map(|_| ())
    }

    /// Parses a bytes slice of the given length.
    ///
    /// The slice returned upon success references the parser’s message
    /// directly. The parser’s position is advanced until the end of the
    /// slice.
    ///
    /// The method will return `Err(ParseError::UnexpectedEnd)` if the 
    /// length would take the parser beyond the current limit or the
    /// end of the message.
    pub fn parse_bytes(&mut self, len: usize) -> ParseResult<&'a [u8]> {
        let end = self.pos + len;
        if end > self.limit {
            return Err(ParseError::UnexpectedEnd)
        }
        let res = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(res)
    }

    pub fn parse_u8(&mut self) -> ParseResult<u8> {
        self.parse_bytes(1).map(|res| res[0])
    }

    pub fn parse_u16(&mut self) -> ParseResult<u16> {
        self.parse_bytes(2).map(BigEndian::read_u16)
    }

    pub fn parse_u32(&mut self) -> ParseResult<u32> {
        self.parse_bytes(4).map(BigEndian::read_u32)
    }
}

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

    /// A format error was encountered.
    FormErr,
}

impl error::Error for ParseError {
    fn description(&self) -> &str {
        use self::ParseError::*;

        match *self {
            UnexpectedEnd => "unexpected end of data",
            UnknownLabel => "unknown label type in domain name",
            FormErr => "format error",
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}

/// The result type for a `ParseError`.
pub type ParseResult<T> = Result<T, ParseError>;

