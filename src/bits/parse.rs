//! Parsing DNS wire-format data.
//!
//! This module provides a [`Parser`] that helps extracting data from DNS
//! messages and a trait [`Parseable`] for types that know how to parse
//! themselves.
//!
//! [`Parser`]: struct.Parser.html
//! [`Parseable`]: trait.Parseable.html
use std::{error, fmt};
use bytes::{BigEndian, ByteOrder, Bytes};


//------------ Parser --------------------------------------------------------

/// The raw data and state of a DNS message being parsed.
///
/// Because of name compression, a full message needs to be available for
/// parsing of DNS data. This type is a small layer atop a [`Bytes`] value.
/// You can wrap one using the [`from_bytes()`] function.
///
/// The parser allows you to successively parse one item after the another
/// out of the message via a few methods prefixed with `parse_`. Additional
/// methods are available for repositioning the parser’s position or access
/// the raw, underlying bytes.
///
/// The methods of a parser never panic if you try to go beyond the end of
/// the parser’s data. Instead, they will return a [`ShortParser`] error,
/// making it more straightforward to implement a complex parser.
///
/// Parsers are `Clone`, so you can keep around a copy of a parser for later
/// use. This is, for instance, done by [`ParsedFqdn`] in order to be able
/// to rummage around the message bytes to find all its labels.
///
/// [`from_bytes()`]: #method.from_bytes
/// [`Bytes`]: ../../../bytes/struct.Bytes.html
/// [`ParsedFqdn`]: ../name/struct.ParsedFqdn.html
/// [`ShortParser`]: ../struct.ShortParser.html
#[derive(Clone, Debug)]
pub struct Parser {
    bytes: Bytes,
    pos: usize
}

impl Parser {
    /// Creates a new parser atop a bytes value.
    pub fn from_bytes(bytes: Bytes) -> Self {
        Parser { bytes, pos: 0 }
    }
}

impl Parser {
    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Returns the current parse position as an index into the byte slice.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the number of remaining bytes to parse.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    /// Returns a reference to a slice of the bytes left to parse.
    pub fn peek(&self) -> &[u8] {
        &self.bytes.as_ref()[self.pos..]
    }

    /// Repositions the parser to the given position.
    ///
    /// If `pos` is larger than the length of the parser, an error is
    /// returned.
    pub fn seek(&mut self, pos: usize) -> Result<(), ShortParser> {
        if pos > self.bytes.len() {
            Err(ShortParser)
        }
        else {
            self.pos = pos;
            Ok(())
        }
    }

    /// Advances the parser‘s position by `len` bytes.
    ///
    /// If this would take the parser beyond its end, an error is returned.
    pub fn advance(&mut self, len: usize) -> Result<(), ShortParser> {
        if len > self.remaining() {
            Err(ShortParser)
        }
        else {
            self.pos += len;
            Ok(())
        }
    }

    /// Checks that there are `len` bytes left to parse.
    ///
    /// If there aren’t, returns an error.
    pub fn check_len(&self, len: usize) -> Result<(), ShortParser> {
        if self.remaining() < len {
            Err(ShortParser)
        }
        else {
            Ok(())
        }
    }

    /// Takes the next `len` bytes and returns them as a `Bytes` value.
    ///
    /// Advances the parser by `len` bytes. If there aren’t enough bytes left,
    /// leaves the parser untouched and returns an error, instead.
    pub fn parse_bytes(&mut self, len: usize) -> Result<Bytes, ShortParser> {
        let end = self.pos + len;
        if end > self.bytes.len() {
            return Err(ShortParser.into())
        }
        let res = self.bytes.slice(self.pos, end);
        self.pos = end;
        Ok(res)
    }

    /// Takes a `i8` from the beginning of the parser.
    ///
    /// Advances the parser by one byte. If there aren’t enough bytes left,
    /// leaves the parser untouched and returns an error, instead.
    pub fn parse_i8(&mut self) -> Result<i8, ShortParser> {
        self.check_len(1)?;
        let res = self.peek()[0] as i8;
        self.pos += 1;
        Ok(res)
    }

    /// Takes a `u8` from the beginning of the parser.
    ///
    /// Advances the parser by one byte. If there aren’t enough bytes left,
    /// leaves the parser untouched and returns an error, instead.
    pub fn parse_u8(&mut self) -> Result<u8, ShortParser> {
        self.check_len(1)?;
        let res = self.peek()[0];
        self.pos += 1;
        Ok(res)
    }

    /// Takes a `i16` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by two bytes. If there
    /// aren’t enough bytes left, leaves the parser untouched and returns an
    /// error, instead.
    pub fn parse_i16(&mut self) -> Result<i16, ShortParser> {
        self.check_len(2)?;
        let res = BigEndian::read_i16(self.peek());
        self.pos += 2;
        Ok(res)
    }

    /// Takes a `u16` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by two bytes. If there
    /// aren’t enough bytes left, leaves the parser untouched and returns an
    /// error, instead.
    pub fn parse_u16(&mut self) -> Result<u16, ShortParser> {
        self.check_len(2)?;
        let res = BigEndian::read_u16(self.peek());
        self.pos += 2;
        Ok(res)
    }

    /// Takes a `i32` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by four bytes. If
    /// there aren’t enough bytes left, leaves the parser untouched and
    /// returns an error, instead.
    pub fn parse_i32(&mut self) -> Result<i32, ShortParser> {
        self.check_len(4)?;
        let res = BigEndian::read_i32(self.peek());
        self.pos += 4;
        Ok(res)
    }

    /// Takes a `u32` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by four bytes. If
    /// there aren’t enough bytes left, leaves the parser untouched and
    /// returns an error, instead.
    pub fn parse_u32(&mut self) -> Result<u32, ShortParser> {
        self.check_len(4)?;
        let res = BigEndian::read_u32(self.peek());
        self.pos += 4;
        Ok(res)
    }
}


//------------ Parseable ------------------------------------------------------

/// A type that knows how to extrac a value of itself from a parser.
pub trait Parseable: Sized {
    /// The type of an error returned when parsing fails.
    type Err;

    /// Extracts a value from the beginning of `parser`.
    ///
    /// If parsing fails and an error is returned, the parser’s position
    /// should be considered to be undefined. If it supposed to be reused in
    /// this case, you should store the position before attempting to parse
    /// and seek to that position again before continuing.
    fn parse(parser: &mut Parser) -> Result<Self, Self::Err>;
}

impl Parseable for i8 {
    type Err = ShortParser;
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_i8()
    }
}

impl Parseable for u8 {
    type Err = ShortParser;
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_u8()
    }
}

impl Parseable for i16 {
    type Err = ShortParser;
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_i16()
    }
}

impl Parseable for u16 {
    type Err = ShortParser;
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_u16()
    }
}

impl Parseable for i32 {
    type Err = ShortParser;
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_i32()
    }
}

impl Parseable for u32 {
    type Err = ShortParser;
    fn parse(parser: &mut Parser) -> Result<Self, ShortParser> {
        parser.parse_u32()
    }
}


//------------ ShortParser ---------------------------------------------------

/// An attempt was made to go beyond the end of a parser.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ShortParser;

impl error::Error for ShortParser {
    fn description(&self) -> &str {
        "unexpected end of data"
    }
}

impl fmt::Display for ShortParser {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}

