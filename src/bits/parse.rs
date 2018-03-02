//! Parsing DNS wire-format data.
//!
//! This module provides a [`Parser`] that helps extracting data from DNS
//! messages and two traits for types that know how to parse themselves:
//! [`Parse`] for types that have an encoding of determinable length and
//! [`ParseAll`] for types that fill the entire available space.
//!
//! [`Parser`]: struct.Parser.html
//! [`Parse`]: trait.Parse.html
//! [`ParseAll`]: trait.ParseAll.html
use std::net::{Ipv4Addr, Ipv6Addr};
use bytes::{BigEndian, ByteOrder, Bytes};


//------------ Parser --------------------------------------------------------

/// The raw data and state of a DNS message being parsed.
///
/// Because of name compression, a full message needs to be available for
/// parsing of DNS data. This type is a small layer atop a [`Bytes`] value.
/// You can wrap one using the [`from_bytes()`] function.
///
/// The parser allows you to successively parse one item after another
/// out of the message via a few methods prefixed with `parse_`. Additional
/// methods are available for repositioning the parser’s position or access
/// the raw, underlying bytes.
///
/// The methods of a parser never panic if you try to go beyond the end of
/// the parser’s data. Instead, they will return a [`ShortBuf`] error,
/// making it more straightforward to implement a complex parser. Since an
/// error normally leads to processing being aborted, functions that return
/// an error can leave the parser at whatever position they like. In the
/// rare case that you actually need to backtrack on the parser in case of
/// an error, you will have to remember and reposition yourself. 
///
/// Parsers are `Clone`, so you can keep around a copy of a parser for later
/// use. This is, for instance, done by [`ParsedDname`] in order to be able
/// to rummage around the message bytes to find all its labels. Because
/// copying a [`Bytes`] value is relatively cheap, cloning a parser is cheap,
/// too.
///
/// [`from_bytes()`]: #method.from_bytes
/// [`Bytes`]: ../../../bytes/struct.Bytes.html
/// [`ParsedDname`]: ../name/struct.ParsedDname.html
/// [`ShortBuf`]: ../struct.ShortBuf.html
#[derive(Clone, Debug)]
pub struct Parser {
    /// The underlying data.
    bytes: Bytes,

    /// The index in `bytes` where parsing should continue.
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

    /// Returns a slice containing the next `len` bytes.
    ///
    /// If less than `len` bytes are left, returns an error.
    pub fn peek(&self, len: usize) -> Result<&[u8], ShortBuf> {
        self.check_len(len)?;
        Ok(&self.peek_all()[..len])
    }

    /// Returns a byte slice of the data left to parse.
    pub fn peek_all(&self) -> &[u8] {
        &self.bytes.as_ref()[self.pos..]
    }

    /// Repositions the parser to the given index.
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

    /// Takes an `i8` from the beginning of the parser.
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

    /// Takes an `i16` from the beginning of the parser.
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

    /// Takes an `i32` from the beginning of the parser.
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

/// A type that can extract a value from the beginning of a parser.
///
/// Types that encode this trait must use an encoding where the end of a
/// value in the parser can be determined from data read so far. These are
/// either fixed length types like `u32` or types that either contain length
/// bytes or boundary markers.
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
    /// It can be used to check if the content of `parser` is correct or to
    /// skip over unneeded parts of a message.
    fn skip(parser: &mut Parser) -> Result<(), Self::Err>;
}

impl Parse for i8 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_i8()
    }

    fn skip(parser: &mut Parser) -> Result<(), ShortBuf> {
        parser.advance(1)
    }
}

impl Parse for u8 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_u8()
    }

    fn skip(parser: &mut Parser) -> Result<(), ShortBuf> {
        parser.advance(1)
    }
}

impl Parse for i16 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_i16()
    }

    fn skip(parser: &mut Parser) -> Result<(), ShortBuf> {
        parser.advance(2)
    }
}

impl Parse for u16 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_u16()
    }

    fn skip(parser: &mut Parser) -> Result<(), ShortBuf> {
        parser.advance(2)
    }
}

impl Parse for i32 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_i32()
    }

    fn skip(parser: &mut Parser) -> Result<(), ShortBuf> {
        parser.advance(4)
    }
}

impl Parse for u32 {
    type Err = ShortBuf;
    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        parser.parse_u32()
    }

    fn skip(parser: &mut Parser) -> Result<(), ShortBuf> {
        parser.advance(4)
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

    fn skip(parser: &mut Parser) -> Result<(), ShortBuf> {
        parser.advance(4)
    }
}

impl Parse for Ipv6Addr {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let mut buf = [0u8; 16];
        parser.parse_buf(&mut buf)?;
        Ok(buf.into())
    }

    fn skip(parser: &mut Parser) -> Result<(), ShortBuf> {
        parser.advance(16)
    }
}


//------------ ParseAll ------------------------------------------------------

/// A type that can extract a value from a given part of a parser.
///
/// This trait is used when the length of a value is known before and the
/// value is expected to stretch over this entire length. There are types
/// that can implement `ParseAll` but not [`Parse`] because they simply take
/// all remaining bytes.
pub trait ParseAll: Sized {
    /// The type returned when parsing fails.
    type Err: From<ShortBuf>;

    /// Parses a value `len` bytes long from the beginning of the parser.
    ///
    /// An implementation must read exactly `len` bytes from the parser or
    /// fail. If it fails, the position of the parser is considered
    /// undefined.
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


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pos_seek_remaining() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.peek(1).unwrap(), b"0");
        assert_eq!(parser.pos(), 0);
        assert_eq!(parser.remaining(), 10);
        assert_eq!(parser.seek(2), Ok(()));
        assert_eq!(parser.pos(), 2);
        assert_eq!(parser.remaining(), 8);
        assert_eq!(parser.peek(1).unwrap(), b"2");
        assert_eq!(parser.seek(10), Ok(()));
        assert_eq!(parser.pos(), 10);
        assert_eq!(parser.remaining(), 0);
        assert_eq!(parser.peek_all(), b"");
        assert_eq!(parser.seek(11), Err(ShortBuf));
        assert_eq!(parser.pos(), 10);
        assert_eq!(parser.remaining(), 0);
    }

    #[test]
    fn peek_check_len() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.peek(2), Ok(b"01".as_ref()));
        assert_eq!(parser.check_len(2), Ok(()));
        assert_eq!(parser.peek(10), Ok(b"0123456789".as_ref()));
        assert_eq!(parser.check_len(10), Ok(()));
        assert_eq!(parser.peek(11), Err(ShortBuf));
        assert_eq!(parser.check_len(11), Err(ShortBuf));
        parser.advance(2).unwrap();
        assert_eq!(parser.peek(2), Ok(b"23".as_ref()));
        assert_eq!(parser.check_len(2), Ok(()));
        assert_eq!(parser.peek(8), Ok(b"23456789".as_ref()));
        assert_eq!(parser.check_len(8), Ok(()));
        assert_eq!(parser.peek(9), Err(ShortBuf));
        assert_eq!(parser.check_len(9), Err(ShortBuf));
    }

    #[test]
    fn peek_all() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.peek_all(), b"0123456789");
        parser.advance(2).unwrap();
        assert_eq!(parser.peek_all(), b"23456789");
    }

    #[test]
    fn advance() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.pos(), 0);
        assert_eq!(parser.peek(1).unwrap(), b"0");
        assert_eq!(parser.advance(2), Ok(()));
        assert_eq!(parser.pos(), 2);
        assert_eq!(parser.peek(1).unwrap(), b"2");
        assert_eq!(parser.advance(9), Err(ShortBuf));
        assert_eq!(parser.advance(8), Ok(()));
        assert_eq!(parser.pos(), 10);
        assert_eq!(parser.peek_all(), b"");
    }

    #[test]
    fn parse_bytes() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.parse_bytes(2).unwrap().as_ref(), b"01");
        assert_eq!(parser.parse_bytes(2).unwrap().as_ref(), b"23");
        assert_eq!(parser.parse_bytes(7), Err(ShortBuf));
        assert_eq!(parser.parse_bytes(6).unwrap().as_ref(), b"456789");
    }

    #[test]
    fn parse_buf() {
        let mut parser = Parser::from_static(b"0123456789");
        let mut buf = [0u8; 2];
        assert_eq!(parser.parse_buf(&mut buf), Ok(()));
        assert_eq!(&buf, b"01");
        assert_eq!(parser.parse_buf(&mut buf), Ok(()));
        assert_eq!(&buf, b"23");
        let mut buf = [0u8; 7];
        assert_eq!(parser.parse_buf(&mut buf), Err(ShortBuf));
        let mut buf = [0u8; 6];
        assert_eq!(parser.parse_buf(&mut buf), Ok(()));
        assert_eq!(&buf, b"456789");
    }

    #[test]
    fn parse_i8() {
        let mut parser = Parser::from_static(b"\x12\xd6");
        assert_eq!(parser.parse_i8(), Ok(0x12));
        assert_eq!(parser.parse_i8(), Ok(-42));
        assert_eq!(parser.parse_i8(), Err(ShortBuf));
    }

    #[test]
    fn parse_u8() {
        let mut parser = Parser::from_static(b"\x12\xd6");
        assert_eq!(parser.parse_u8(), Ok(0x12));
        assert_eq!(parser.parse_u8(), Ok(0xd6));
        assert_eq!(parser.parse_u8(), Err(ShortBuf));
    }

    #[test]
    fn parse_i16() {
        let mut parser = Parser::from_static(b"\x12\x34\xef\x6e\0");
        assert_eq!(parser.parse_i16(), Ok(0x1234));
        assert_eq!(parser.parse_i16(), Ok(-4242));
        assert_eq!(parser.parse_i16(), Err(ShortBuf));
    }

    #[test]
    fn parse_u16() {
        let mut parser = Parser::from_static(b"\x12\x34\xef\x6e\0");
        assert_eq!(parser.parse_u16(), Ok(0x1234));
        assert_eq!(parser.parse_u16(), Ok(0xef6e));
        assert_eq!(parser.parse_u16(), Err(ShortBuf));
    }

    #[test]
    fn parse_i32() {
        let mut parser = Parser::from_static(
            b"\x12\x34\x56\x78\xfd\x78\xa8\x4e\0\0\0");
        assert_eq!(parser.parse_i32(), Ok(0x12345678));
        assert_eq!(parser.parse_i32(), Ok(-42424242));
        assert_eq!(parser.parse_i32(), Err(ShortBuf));
    }

    #[test]
    fn parse_u32() {
        let mut parser = Parser::from_static(
            b"\x12\x34\x56\x78\xfd\x78\xa8\x4e\0\0\0");
        assert_eq!(parser.parse_u32(), Ok(0x12345678));
        assert_eq!(parser.parse_u32(), Ok(0xfd78a84e));
        assert_eq!(parser.parse_u32(), Err(ShortBuf));
    }


}
