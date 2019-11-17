//! Parsing DNS wire-format data.

use core::fmt;
use derive_more::Display;
use crate::net::{Ipv4Addr, Ipv6Addr};
use crate::octets::{OctetsRef, ShortBuf};


//------------ Parser --------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Parser<T> {
    octets: T,
    pos: usize,
    len: usize,
}

impl<T> Parser<T> {
    /// Creates a new parser atop a reference to an octet sequence.
    pub fn from_ref(octets: T) -> Self
    where T: AsRef<[u8]> {
        Parser { pos: 0, len: octets.as_ref().len(), octets }
    }

    /// Returns a reference to the underlying octets sequence.
    pub fn octets_ref(&self) -> T
    where T: Copy {
        self.octets
    }

    /// Extracts the underlying octet sequence from the parser.
    ///
    /// This will be the same sequence the parser was created with. It
    /// will not be modified by parsing at all.
    pub fn into_octets(self) -> T {
        self.octets
    }

    /// Returns the current parse position as an index into the byte slice.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Returns the length of the underlying octet sequence.
    ///
    /// This is _not_ the number of octets left for parsing. Use
    /// [`remaining`] for that.
    ///
    /// [`remaining`]: #method.remaining
    pub fn len(&self) -> usize {
        self.len
    }
}

impl Parser<&'static [u8]> {
    /// Creates a new parser atop a static byte slice.
    ///
    /// This function is most useful for testing.
    pub fn from_static(slice: &'static [u8]) -> Self {
        Self::from_ref(slice)
    }
}

impl<T: AsRef<[u8]>> Parser<T> {
    /// Returns a reference to the underlying octets sequence.
    pub fn as_slice(&self) -> &[u8] {
        self.octets.as_ref()
    }

    /// Returns a mutable reference to the underlying octets sequence.
    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where T: AsMut<[u8]> {
        self.octets.as_mut()
    }

    /// Returns the number of remaining bytes to parse.
    pub fn remaining(&self) -> usize {
        self.len - self.pos
    }

    /// Returns a slice containing the next `len` bytes.
    ///
    /// If less than `len` bytes are left, returns an error.
    pub fn peek(&self, len: usize) -> Result<&[u8], ParseError> {
        self.check_len(len)?;
        Ok(&self.peek_all()[..len])
    }

    /// Returns a byte slice of the data left to parse.
    pub fn peek_all(&self) -> &[u8] {
        &self.octets.as_ref()[self.pos..]
    }

    /// Repositions the parser to the given index.
    ///
    /// If `pos` is larger than the length of the parser, an error is
    /// returned.
    pub fn seek(&mut self, pos: usize) -> Result<(), ParseError> {
        if pos > self.len {
            Err(ParseError::ShortBuf)
        }
        else {
            self.pos = pos;
            Ok(())
        }
    }

    /// Advances the parser‘s position by `len` bytes.
    ///
    /// If this would take the parser beyond its end, an error is returned.
    pub fn advance(&mut self, len: usize) -> Result<(), ParseError> {
        if len > self.remaining() {
            Err(ParseError::ShortBuf)
        }
        else {
            self.pos += len;
            Ok(())
        }
    }

    /// Advances to the end of the parser.
    pub fn advance_to_end(&mut self) {
        self.pos = self.len
    }

    /// Checks that there are `len` bytes left to parse.
    ///
    /// If there aren’t, returns an error.
    pub fn check_len(&self, len: usize) -> Result<(), ParseError> {
        if self.remaining() < len {
            Err(ParseError::ShortBuf)
        }
        else {
            Ok(())
        }
    }
}

impl<T: AsRef<[u8]>> Parser<T> {
    /// Takes and returns the next `len` octets.
    ///
    /// Advances the parser by `len` bytes. If there aren’t enough bytes left,
    /// leaves the parser untouched and returns an error, instead.
    pub fn parse_octets(&mut self, len: usize) -> Result<T::Range, ParseError>
    where T: OctetsRef {
        let end = self.pos + len;
        if end > self.len {
            return Err(ParseError::ShortBuf)
        }
        let res = self.octets.range(self.pos, end);
        self.pos = end;
        Ok(res)
    }

    /// Fills the provided buffer by taking bytes from the parser.
    pub fn parse_buf(&mut self, buf: &mut [u8]) -> Result<(), ParseError> {
        let pos = self.pos;
        self.advance(buf.len())?;
        buf.copy_from_slice(&self.octets.as_ref()[pos..self.pos]);
        Ok(())
    }

    /// Takes an `i8` from the beginning of the parser.
    ///
    /// Advances the parser by one byte. If there aren’t enough bytes left,
    /// leaves the parser untouched and returns an error, instead.
    pub fn parse_i8(&mut self) -> Result<i8, ParseError> {
        let res = self.peek(1)?[0] as i8;
        self.pos += 1;
        Ok(res)
    }

    /// Takes a `u8` from the beginning of the parser.
    ///
    /// Advances the parser by one byte. If there aren’t enough bytes left,
    /// leaves the parser untouched and returns an error, instead.
    pub fn parse_u8(&mut self) -> Result<u8, ParseError> {
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
    pub fn parse_i16(&mut self) -> Result<i16, ParseError> {
        let mut res = [0; 2];
        self.parse_buf(&mut res)?;
        Ok(i16::from_be_bytes(res))
    }

    /// Takes a `u16` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by two bytes. If there
    /// aren’t enough bytes left, leaves the parser untouched and returns an
    /// error, instead.
    pub fn parse_u16(&mut self) -> Result<u16, ParseError> {
        let mut res = [0; 2];
        self.parse_buf(&mut res)?;
        Ok(u16::from_be_bytes(res))
    }

    /// Takes an `i32` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by four bytes. If
    /// there aren’t enough bytes left, leaves the parser untouched and
    /// returns an error, instead.
    pub fn parse_i32(&mut self) -> Result<i32, ParseError> {
        let mut res = [0; 4];
        self.parse_buf(&mut res)?;
        Ok(i32::from_be_bytes(res))
    }

    /// Takes a `u32` from the beginning of the parser.
    ///
    /// The value is converted from network byte order into the system’s own
    /// byte order if necessary. The parser is advanced by four bytes. If
    /// there aren’t enough bytes left, leaves the parser untouched and
    /// returns an error, instead.
    pub fn parse_u32(&mut self) -> Result<u32, ParseError> {
        let mut res = [0; 4];
        self.parse_buf(&mut res)?;
        Ok(u32::from_be_bytes(res))
    }

    /// Parses the next octets through a closure.
    ///
    /// The closure `op` will be allowed to parse up to `limit` octets. If it
    /// does so successfully or returns with a form error, the method returns
    /// its return value. If it returns with a short buffer error, the method
    /// returns a form error. If it returns successfully with less than
    /// `limit` octets parsed, returns a form error indicating trailing data.
    /// If the limit is larger than the remaining number of octets, returns a
    /// `ParseError::ShortBuf`.
    ///
    //  XXX NEEDS TESTS!!!
    pub fn parse_block<F, U>(
        &mut self, limit: usize, op: F
    ) -> Result<U, ParseError>
    where
        F: FnOnce(&mut Self) -> Result<U, ParseError>,
    {
        let end = self.pos + limit;
        if end > self.len {
            return Err(ParseError::ShortBuf);
        }
        let len = self.len;
        self.len = end;
        let res = op(self);
        self.len = len;
        if self.pos != end {
            Err(ParseError::Form(FormError::new("trailing data in field")))
        }
        else if let Err(ParseError::ShortBuf) = res {
            Err(ParseError::Form(FormError::new("short field")))
        }
        else {
            res
        }
    }

}


//------------ Parse ------------------------------------------------------

/// A type that can extract a value from the beginning of a parser.
///
/// If your implementing `Parse` for a type that is generic over an octet
/// sequence, try to provide a specific implementation for a given octet
/// sequence. Typically, this will be via implementing
/// `Parse<T: OctetsRef>` for a type that is then generic over `T::Range`.
/// This will avoid having to provide type annotations when simply calling
/// `parse` for your type.
pub trait Parse<T>: Sized {
    /// Extracts a value from the beginning of `parser`.
    ///
    /// If parsing fails and an error is returned, the parser’s position
    /// should be considered to be undefined. If it supposed to be reused in
    /// this case, you should store the position before attempting to parse
    /// and seek to that position again before continuing.
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError>;

    /// Skips over a value of this type at the beginning of `parser`.
    ///
    /// This function is the same as `parse` but doesn’t return the result.
    /// It can be used to check if the content of `parser` is correct or to
    /// skip over unneeded parts of a message.
    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError>;
}

impl<T: AsRef<[u8]>> Parse<T> for i8 {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        parser.parse_i8().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        parser.advance(1).map_err(Into::into)
    }
}

impl<T: AsRef<[u8]>> Parse<T> for u8 {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        parser.parse_u8().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        parser.advance(1).map_err(Into::into)
    }
}

impl<T: AsRef<[u8]>> Parse<T> for i16 {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        parser.parse_i16().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        parser.advance(2).map_err(Into::into)
    }
}

impl<T: AsRef<[u8]>> Parse<T> for u16 {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        parser.parse_u16().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        parser.advance(2).map_err(Into::into)
    }
}

impl<T: AsRef<[u8]>> Parse<T> for i32 {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        parser.parse_i32().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        parser.advance(4).map_err(Into::into)
    }
}

impl<T: AsRef<[u8]>> Parse<T> for u32 {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        parser.parse_u32().map_err(Into::into)
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        parser.advance(4).map_err(Into::into)
    }
}

impl<T: AsRef<[u8]>> Parse<T> for Ipv4Addr {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        Ok(Self::new(
            u8::parse(parser)?,
            u8::parse(parser)?,
            u8::parse(parser)?,
            u8::parse(parser)?
        ))
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        parser.advance(4).map_err(Into::into)
    }
}

impl<T: AsRef<[u8]>> Parse<T> for Ipv6Addr {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        let mut buf = [0u8; 16];
        parser.parse_buf(&mut buf)?;
        Ok(buf.into())
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        parser.advance(16).map_err(Into::into)
    }
}


//--------- ParseError -------------------------------------------------------

/// An error happened while parsing data.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum ParseError {
    #[display(fmt="unexpected end of buffer")]
    ShortBuf,

    #[display(fmt="{}", _0)]
    Form(FormError)
}

#[cfg(feature = "std")]
impl std::error::Error for ParseError { }

impl From<ShortBuf> for ParseError {
    fn from(_: ShortBuf) -> Self {
        ParseError::ShortBuf
    }
}

impl From<FormError> for ParseError {
    fn from(err: FormError) -> Self {
        ParseError::Form(err)
    }
}


//------------ FormError -----------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormError(&'static str);

impl FormError {
    pub fn new(msg: &'static str) -> Self {
        FormError(msg)
    }
}

impl fmt::Display for FormError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FormError { }


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
        assert_eq!(parser.seek(11), Err(ParseError::ShortBuf));
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
        assert_eq!(parser.peek(11), Err(ParseError::ShortBuf));
        assert_eq!(parser.check_len(11), Err(ParseError::ShortBuf));
        parser.advance(2).unwrap();
        assert_eq!(parser.peek(2), Ok(b"23".as_ref()));
        assert_eq!(parser.check_len(2), Ok(()));
        assert_eq!(parser.peek(8), Ok(b"23456789".as_ref()));
        assert_eq!(parser.check_len(8), Ok(()));
        assert_eq!(parser.peek(9), Err(ParseError::ShortBuf));
        assert_eq!(parser.check_len(9), Err(ParseError::ShortBuf));
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
        assert_eq!(parser.advance(9), Err(ParseError::ShortBuf));
        assert_eq!(parser.advance(8), Ok(()));
        assert_eq!(parser.pos(), 10);
        assert_eq!(parser.peek_all(), b"");
    }

    #[test]
    fn parse_octets() {
        let mut parser = Parser::from_static(b"0123456789");
        assert_eq!(parser.parse_octets(2).unwrap(), b"01");
        assert_eq!(parser.parse_octets(2).unwrap(), b"23");
        assert_eq!(parser.parse_octets(7), Err(ParseError::ShortBuf));
        assert_eq!(parser.parse_octets(6).unwrap(), b"456789");
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
        assert_eq!(parser.parse_buf(&mut buf), Err(ParseError::ShortBuf));
        let mut buf = [0u8; 6];
        assert_eq!(parser.parse_buf(&mut buf), Ok(()));
        assert_eq!(&buf, b"456789");
    }

    #[test]
    fn parse_i8() {
        let mut parser = Parser::from_static(b"\x12\xd6");
        assert_eq!(parser.parse_i8(), Ok(0x12));
        assert_eq!(parser.parse_i8(), Ok(-42));
        assert_eq!(parser.parse_i8(), Err(ParseError::ShortBuf));
    }

    #[test]
    fn parse_u8() {
        let mut parser = Parser::from_static(b"\x12\xd6");
        assert_eq!(parser.parse_u8(), Ok(0x12));
        assert_eq!(parser.parse_u8(), Ok(0xd6));
        assert_eq!(parser.parse_u8(), Err(ParseError::ShortBuf));
    }

    #[test]
    fn parse_i16() {
        let mut parser = Parser::from_static(b"\x12\x34\xef\x6e\0");
        assert_eq!(parser.parse_i16(), Ok(0x1234));
        assert_eq!(parser.parse_i16(), Ok(-4242));
        assert_eq!(parser.parse_i16(), Err(ParseError::ShortBuf));
    }

    #[test]
    fn parse_u16() {
        let mut parser = Parser::from_static(b"\x12\x34\xef\x6e\0");
        assert_eq!(parser.parse_u16(), Ok(0x1234));
        assert_eq!(parser.parse_u16(), Ok(0xef6e));
        assert_eq!(parser.parse_u16(), Err(ParseError::ShortBuf));
    }

    #[test]
    fn parse_i32() {
        let mut parser = Parser::from_static(
            b"\x12\x34\x56\x78\xfd\x78\xa8\x4e\0\0\0");
        assert_eq!(parser.parse_i32(), Ok(0x12345678));
        assert_eq!(parser.parse_i32(), Ok(-42424242));
        assert_eq!(parser.parse_i32(), Err(ParseError::ShortBuf));
    }

    #[test]
    fn parse_u32() {
        let mut parser = Parser::from_static(
            b"\x12\x34\x56\x78\xfd\x78\xa8\x4e\0\0\0");
        assert_eq!(parser.parse_u32(), Ok(0x12345678));
        assert_eq!(parser.parse_u32(), Ok(0xfd78a84e));
        assert_eq!(parser.parse_u32(), Err(ParseError::ShortBuf));
    }
}

