//! Parsing DNS wire-format data.
//!
//! This module provides a [`Parser`] that helps extracting data from DNS
//! messages and a trait [`Parse`] for types that know how to parse
//! themselves.
//!
//! [`Parser`]: struct.Parser.html
//! [`Parse`]: trait.Parse.html
use std::net::{Ipv4Addr, Ipv6Addr};
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
/// the parser’s data. Instead, they will return a [`ShortBuf`] error,
/// making it more straightforward to implement a complex parser.
///
/// Parsers are `Clone`, so you can keep around a copy of a parser for later
/// use. This is, for instance, done by [`ParsedFqdn`] in order to be able
/// to rummage around the message bytes to find all its labels.
///
/// [`from_bytes()`]: #method.from_bytes
/// [`Bytes`]: ../../../bytes/struct.Bytes.html
/// [`ParsedFqdn`]: ../name/struct.ParsedFqdn.html
/// [`ShortBuf`]: ../struct.ShortBuf.html
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

    /// Creates a new parser atop a static byte slice.
    ///
    /// This function is most useful for testing.
    pub fn from_static(slice: &'static [u8]) -> Self {
        Self::from_bytes(Bytes::from_static(slice))
    }

    /// Extracts the underlying bytes value from the parser.
    ///
    /// This will be the same bytes value the parser was created with. It
    /// will not be modified by parsing at all.
    pub fn unwrap(self) -> Bytes {
        self.bytes
    }
}

impl Parser {
    /// Returns a reference to the underlying bytes.
    pub fn as_bytes(&self) -> &Bytes {
        &self.bytes
    }

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
    pub fn peek(&self, len: usize) -> Result<&[u8], ShortBuf> {
        self.check_len(len)?;
        Ok(&self.peek_all()[..len])
    }

    pub fn peek_all(&self) -> &[u8] {
        &self.bytes.as_ref()[self.pos..]
    }

    /// Repositions the parser to the given position.
    ///
    /// If `pos` is larger than the length of the parser, an error is
    /// returned.
    pub fn seek(&mut self, pos: usize) -> Result<(), ShortBuf> {
        if pos > self.bytes.len() {
            Err(ShortBuf)
        }
        else {
            self.pos = pos;
            Ok(())
        }
    }

    /// Advances the parser‘s position by `len` bytes.
    ///
    /// If this would take the parser beyond its end, an error is returned.
    pub fn advance(&mut self, len: usize) -> Result<(), ShortBuf> {
        if len > self.remaining() {
            Err(ShortBuf)
        }
        else {
            self.pos += len;
            Ok(())
        }
    }

    /// Checks that there are `len` bytes left to parse.
    ///
    /// If there aren’t, returns an error.
    pub fn check_len(&self, len: usize) -> Result<(), ShortBuf> {
        if self.remaining() < len {
            Err(ShortBuf)
        }
        else {
            Ok(())
        }
    }

    /// Takes the next `len` bytes and returns them as a `Bytes` value.
    ///
    /// Advances the parser by `len` bytes. If there aren’t enough bytes left,
    /// leaves the parser untouched and returns an error, instead.
    pub fn parse_bytes(&mut self, len: usize) -> Result<Bytes, ShortBuf> {
        let end = self.pos + len;
        if end > self.bytes.len() {
            return Err(ShortBuf)
        }
        let res = self.bytes.slice(self.pos, end);
        self.pos = end;
        Ok(res)
    }

    /// Fills the provided buffer by taking bytes from the parser.
    pub fn parse_buf(&mut self, buf: &mut [u8]) -> Result<(), ShortBuf> {
        let pos = self.pos;
        self.advance(buf.len())?;
        buf.copy_from_slice(&self.bytes.as_ref()[pos..self.pos]);
        Ok(())
    }

    /// Takes a `i8` from the beginning of the parser.
    ///
    /// Advances the parser by one byte. If there aren’t enough bytes left,
    /// leaves the parser untouched and returns an error, instead.
    pub fn parse_i8(&mut self) -> Result<i8, ShortBuf> {
        let res = self.peek(1)?[0] as i8;
        self.pos += 1;
        Ok(res)
    }

    /// Takes a `u8` from the beginning of the parser.
    ///
    /// Advances the parser by one byte. If there aren’t enough bytes left,
    /// leaves the parser untouched and returns an error, instead.
    pub fn parse_u8(&mut self) -> Result<u8, ShortBuf> {
        let res = self.peek(1)?[0];
        self.pos += 1;
        Ok(res)
    }

    /// Takes a `i16` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by two bytes. If there
    /// aren’t enough bytes left, leaves the parser untouched and returns an
    /// error, instead.
    pub fn parse_i16(&mut self) -> Result<i16, ShortBuf> {
        let res = BigEndian::read_i16(self.peek(2)?);
        self.pos += 2;
        Ok(res)
    }

    /// Takes a `u16` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by two bytes. If there
    /// aren’t enough bytes left, leaves the parser untouched and returns an
    /// error, instead.
    pub fn parse_u16(&mut self) -> Result<u16, ShortBuf> {
        let res = BigEndian::read_u16(self.peek(2)?);
        self.pos += 2;
        Ok(res)
    }

    /// Takes a `i32` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by four bytes. If
    /// there aren’t enough bytes left, leaves the parser untouched and
    /// returns an error, instead.
    pub fn parse_i32(&mut self) -> Result<i32, ShortBuf> {
        let res = BigEndian::read_i32(self.peek(4)?);
        self.pos += 4;
        Ok(res)
    }

    /// Takes a `u32` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by four bytes. If
    /// there aren’t enough bytes left, leaves the parser untouched and
    /// returns an error, instead.
    pub fn parse_u32(&mut self) -> Result<u32, ShortBuf> {
        let res = BigEndian::read_u32(self.peek(4)?);
        self.pos += 4;
        Ok(res)
    }
}


//------------ Parse ------------------------------------------------------

/// A type that knows how to extrac a value of itself from a parser.
pub trait Parse: Sized {
    /// The type of an error returned when parsing fails.
    type Err: From<ShortBuf>;

    /// Extracts a value from the beginning of `parser`.
    ///
    /// If parsing fails and an error is returned, the parser’s position
    /// should be considered to be undefined. If it supposed to be reused in
    /// this case, you should store the position before attempting to parse
    /// and seek to that position again before continuing.
    fn parse(parser: &mut Parser) -> Result<Self, Self::Err>;

    /// Skips over a value of this type at the beginning of `parser`.
    ///
    /// This function is the same as `parse` but doesn’t return the result.
    /// It can be used to check if the content of `parser` is correct.
    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        Self::parse(parser).map(|_| ())
    }
}

impl Parse for i8 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_i8()
    }
}

impl Parse for u8 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_u8()
    }
}

impl Parse for i16 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_i16()
    }
}

impl Parse for u16 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_u16()
    }
}

impl Parse for i32 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_i32()
    }
}

impl Parse for u32 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_u32()
    }
}

impl Parse for Ipv4Addr {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        Ok(Self::new(
            u8::parse(parser)?,
            u8::parse(parser)?,
            u8::parse(parser)?,
            u8::parse(parser)?
        ))
    }
}

impl Parse for Ipv6Addr {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let mut buf = [0u8; 16];
        parser.parse_buf(&mut buf)?;
        Ok(buf.into())
    }
}


//------------ ParseAll ------------------------------------------------------

pub trait ParseAll: Sized {
    type Err: From<ShortBuf>;

    fn parse_all(parser: &mut Parser, len: usize)
                 -> Result<Self, Self::Err>;
}

impl ParseAll for u8 {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 1 {
            Err(ParseAllError::ShortField)
        }
        else if len > 1 {
            Err(ParseAllError::TrailingData)
        }
        else {
            Ok(Self::parse(parser)?)
        }
    }
}

impl ParseAll for u16 {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 2 {
            Err(ParseAllError::ShortField)
        }
        else if len > 2 {
            Err(ParseAllError::TrailingData)
        }
        else {
            Ok(Self::parse(parser)?)
        }
    }
}

impl ParseAll for u32 {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 4 {
            Err(ParseAllError::ShortField)
        }
        else if len > 4 {
            Err(ParseAllError::TrailingData)
        }
        else {
            Ok(Self::parse(parser)?)
        }
    }
}

impl ParseAll for Ipv4Addr {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 4 {
            Err(ParseAllError::ShortField)
        }
        else if len > 4 {
            Err(ParseAllError::TrailingData)
        }
        else {
            Ok(Self::parse(parser)?)
        }
    }
}

impl ParseAll for Ipv6Addr {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 16 {
            Err(ParseAllError::ShortField)
        }
        else if len > 16 {
            Err(ParseAllError::TrailingData)
        }
        else {
            Ok(Self::parse(parser)?)
        }
    }
}


//------------ ParseOpenError ------------------------------------------------

/// An error happened when parsing all of a minimum length, open size type.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum ParseOpenError {
    #[fail(display="short field")]
    ShortField,

    #[fail(display="unexpected end of buffer")]
    ShortBuf
}

impl From<ShortBuf> for ParseOpenError {
    fn from(_: ShortBuf) -> Self {
        ParseOpenError::ShortBuf
    }
}


//------------ ShortBuf ------------------------------------------------------

/// An attempt was made to go beyond the end of a buffer.
#[derive(Clone, Debug, Eq, Fail, PartialEq)]
#[fail(display="unexpected end of buffer")]
pub struct ShortBuf;


//--------- ParseAllError ----------------------------------------------------

/// An error happened while trying to length-parse a type with built-in limit.
///
/// This error type is used for type that have their own length indicators
/// and where any possible byte combination is valid.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum ParseAllError {
    #[fail(display="trailing data")]
    TrailingData,

    #[fail(display="short field")]
    ShortField,

    #[fail(display="unexpected end of buffer")]
    ShortBuf
}

impl ParseAllError {
    pub fn check(expected: usize, got: usize) -> Result<(), Self> {
        if expected < got {
            Err(ParseAllError::TrailingData)
        }
        else if expected > got {
            Err(ParseAllError::ShortField)
        }
        else {
            Ok(())
        }
    }
}

impl From<ShortBuf> for ParseAllError {
    fn from(_: ShortBuf) -> Self {
        ParseAllError::ShortBuf
    }
}

