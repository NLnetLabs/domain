//! Parsing of wire-format DNS data.
//!
//! This module contains a trait and two implementations of that trait for
//! parsing wire-format DNS data. Because it simplifies things significantly,
//! all parsing happens on bytes slices. This isn’t a big limitation since
//! the length of a DNS message sent over the network is always known in
//! advance (either by the UDP packet size or through a length prefix in TCP)
//! so receiving a complete message before parsing is simple enough. If raw
//! DNS data is stored in files, a length prefix similar to TCP can be
//! employed.
//!
//! The advantage of the bytes slice underlying a parser is that methods can
//! return references into that slice directly. And indeed, that is what all
//! methods dealing with variable length types do.
//! 
//! The difference between the two implementations is that `SliceParser`
//! expects all domain names to be uncompressed while `ContextParser` can
//! parse compressed domain names. Thus, `SliceParser` can be used on any
//! bytes slice whereas `ContextParser` always needs a full message.
//!
//! # Todo
//!
//! Currently, some operations will leave the parser in a half-progressed
//! state (everything the deconstructs into a sequence of basic parse
//! operations). Either make them fail with the parser backtracking to
//! before them or invalidate the parser entirely. Given that a parse error
//! likely means an invalid message, the latter should be good enough.

use std::mem;
use super::charstr::CharStr;
use super::error::{ParseResult, ParseError};
use super::name::{DName, DNameSlice, PackedDName};
use super::nest::{Nest, NestSlice, PackedNest};
use super::octets::Octets;


//------------ ParseBytes ---------------------------------------------------

/// A trait for parsing simple wire-format DNS data.
pub trait ParseBytes<'a>: Sized + Clone {
    /// Parses a bytes slice of a given length.
    fn parse_bytes(&mut self, len: usize) -> ParseResult<&'a [u8]>;

    /// Skip the next `len` bytes.
    fn skip(&mut self, len: usize) -> ParseResult<()>;

    /// Parses a single octet.
    fn parse_u8(&mut self) -> ParseResult<u8> {
        self.parse_bytes(1).map(|res| res[0])
    }

    /// Parses an unsigned 16-bit word.
    fn parse_u16(&mut self) -> ParseResult<u16> {
        self.parse_bytes(2).map(|res| {
            let res: &[u8; 2] = unsafe { &*(res.as_ptr() as *const [u8; 2]) };
            let res = unsafe { mem::transmute(*res) };
            u16::from_be(res)
        })
    }

    /// Parses an unsigned 32-bit word.
    fn parse_u32(&mut self) -> ParseResult<u32> {
        self.parse_bytes(4).map(|res| {
            let res: &[u8; 4] = unsafe { &*(res.as_ptr() as *const [u8; 4]) };
            let res = unsafe { mem::transmute(*res) };
            u32::from_be(res)
        })
    }

    /// Parses the rest of the parser.
    fn parse_left(&mut self) -> ParseResult<&'a [u8]> {
        let len = self.left();
        self.parse_bytes(len)
    }

    /// Creates a sup-parser starting a the current position.
    ///
    /// XXX This is identical to `clone()`, so maybe we should ditch it?
    fn sub(&self) -> Self;

    /// Creates a sub-parser limited to `len` bytes and advance position.
    fn parse_sub(&mut self, len: usize) -> ParseResult<Self>;

    /// Returns the length of the data we have seen already.
    fn seen(&self) -> usize;

    /// Returns the length of the data left.
    fn left(&self) -> usize;

    /// Parses a domain name.
    fn parse_dname(&mut self) -> ParseResult<DName<'a>>;

    /// Parses a character string.
    fn parse_charstr(&mut self) -> ParseResult<CharStr<'a>> {
        CharStr::parse(self)
    }

    /// Parses a nest.
    fn parse_nest(&mut self, len: usize) -> ParseResult<Nest<'a>>;

    /// Parses arbitrary bytes data.
    fn parse_octets(&mut self, len: usize) -> ParseResult<Octets<'a>> {
        Ok(Octets::from_bytes(try!(self.parse_bytes(len))))
    }
}


//------------ SliceParser --------------------------------------------------

/// A parser that operates on an arbitrary bytes slice.
///
/// This parser assumes that all domain names are complete and no name
/// compression is employed. It will return values of the slice variant
/// of domain names and nests.
#[derive(Clone, Debug)]
pub struct SliceParser<'a> {
    slice: &'a [u8],
    seen: usize,
}

impl<'a> SliceParser<'a> {
    /// Creates a new parser using the given bytes slice.
    pub fn new(slice: &'a [u8]) -> Self {
        SliceParser { slice: slice, seen: 0 }
    }

    /// Checks whether `len` bytes are still left in the parser.
    fn check_len(&self, len: usize) -> ParseResult<()> {
        if len > self.slice.len() {
            Err(ParseError::UnexpectedEnd)
        }
        else {
            Ok(())
        }
    }
}

impl<'a> ParseBytes<'a> for SliceParser<'a> {
    fn parse_bytes(&mut self, len: usize) -> ParseResult<&'a [u8]> {
        try!(self.check_len(len));
        let (l, r) = self.slice.split_at(len);
        self.slice = r;
        self.seen += len;
        Ok(l)
    }

    fn skip(&mut self, len: usize) -> ParseResult<()> {
        try!(self.check_len(len));
        self.slice = &self.slice[len..];
        self.seen += len;
        Ok(())
    }

    fn sub(&self) -> Self {
        SliceParser { slice: self.slice, seen: 0 }
    }

    fn parse_sub(&mut self, len: usize) -> ParseResult<Self> {
        Ok(SliceParser { slice: try!(self.parse_bytes(len)), seen: 0 })
    }

    fn seen(&self) -> usize {
        self.seen
    }

    fn left(&self) -> usize {
        self.slice.len()
    }

    fn parse_dname(&mut self) -> ParseResult<DName<'a>> {
        DNameSlice::parse(self).map(|name| name.into())
    }

    fn parse_nest(&mut self, len: usize) -> ParseResult<Nest<'a>> {
        NestSlice::parse(self, len).map(|nest| nest.into())
    }
}

//------------ ContextParser ------------------------------------------------

/// A parser that operates on an entire DNS message.
///
/// It will return values of the packed variant of domain names and nests.
#[derive(Clone, Debug)]
pub struct ContextParser<'a> {
    parser: SliceParser<'a>,
    context: &'a [u8]
}

impl<'a> ContextParser<'a> {
    /// Creates a new context parser with the given bytes slice.
    ///
    /// This assumes that the positions referenced by compressed domain names
    /// are relative to the beginning of the slice.
    pub fn new(message: &'a [u8]) -> Self {
        ContextParser {
            parser: SliceParser::new(message),
            context: message
        }
    }

    /// Creates a new context parser from a bytes slice and a contest slice.
    ///
    /// This assumes that the positions reference by compressed domai names
    /// are relative to the beginning of the context slice.
    pub fn from_parts(slice: &'a[u8], context: &'a[u8]) -> Self {
        ContextParser {
            parser: SliceParser::new(slice),
            context: context
        }
    }
}

impl<'a> ParseBytes<'a> for ContextParser<'a> {
    fn parse_bytes(&mut self, len: usize) -> ParseResult<&'a [u8]> {
        self.parser.parse_bytes(len)
    }

    fn skip(&mut self, len: usize) -> ParseResult<()> {
        self.parser.skip(len)
    }

    fn sub(&self) -> Self {
        ContextParser {
            parser: self.parser.sub(),
            context: self.context
        }
    }

    fn parse_sub(&mut self, len: usize) -> ParseResult<Self> {
        Ok(ContextParser {
            parser: try!(self.parser.parse_sub(len)),
            context: self.context
        })
    }

    fn seen(&self) -> usize {
        self.parser.seen()
    }

    fn left(&self) -> usize {
        self.parser.left()
    }

    fn parse_dname(&mut self) -> ParseResult<DName<'a>> {
        PackedDName::parse(self, self.context).map(|name| name.into())
    }

    fn parse_nest(&mut self, len: usize) -> ParseResult<Nest<'a>> {
        PackedNest::parse(self, self.context, len).map(|nest| nest.into())
    }
}

//============ Testing ======================================================

#[cfg(test)]
mod test {
    use bits::ParseError;
    use super::*;

    fn check_slice_parser(parser: &SliceParser, seen: usize, left: &[u8]) {
        assert_eq!(parser.seen(), seen);
        assert_eq!(parser.left(), left.len());
        assert_eq!(parser.slice, left)
    }

    #[test]
    fn parse_bytes_ok() {
        let mut parser = SliceParser::new(b"123456"); 
        check_slice_parser(&parser, 0, b"123456");
        assert_eq!(parser.parse_bytes(0).unwrap(), b"");
        check_slice_parser(&parser, 0, b"123456");
        assert_eq!(parser.parse_bytes(4).unwrap(), b"1234");
        check_slice_parser(&parser, 4, b"56");
        assert_eq!(parser.parse_bytes(2).unwrap(), b"56");
        check_slice_parser(&parser, 6, b"");
        assert_eq!(parser.parse_bytes(0).unwrap(), b"");
        check_slice_parser(&parser, 6, b"");
    }

    #[test]
    fn parse_bytes_err() {
        let mut parser = SliceParser::new(b"123456"); 
        check_slice_parser(&parser, 0, b"123456");
        assert_eq!(parser.parse_bytes(8), Err(ParseError::UnexpectedEnd));
        check_slice_parser(&parser, 0, b"123456");
    }

    #[test]
    fn skip() {
        let mut parser = SliceParser::new(b"123456");
        check_slice_parser(&parser, 0, b"123456");
        parser.skip(2).unwrap();
        check_slice_parser(&parser, 2, b"3456");
        assert_eq!(parser.skip(6), Err(ParseError::UnexpectedEnd));
        check_slice_parser(&parser, 2, b"3456");
    }

    #[test]
    fn parse_u8() {
        let mut parser = SliceParser::new(b"123");
        check_slice_parser(&parser, 0, b"123");
        assert_eq!(parser.parse_u8().unwrap(), b'1');
        check_slice_parser(&parser, 1, b"23");
    }

    #[test]
    fn parse_u16() {
        let mut parser = SliceParser::new(b"\x12\x3456");
        check_slice_parser(&parser, 0, b"\x12\x3456");
        assert_eq!(parser.parse_u16().unwrap(), 0x1234);
        check_slice_parser(&parser, 2, b"56");
    }

    #[test]
    fn parse_u32() {
        let mut parser = SliceParser::new(b"\x12\x34\x56\x7890");
        check_slice_parser(&parser, 0, b"\x12\x34\x56\x7890");
        assert_eq!(parser.parse_u32().unwrap(), 0x12345678);
        check_slice_parser(&parser, 4, b"90");
    }

    #[test]
    fn parse_sub() {
        let mut parser = SliceParser::new(b"123456");
        check_slice_parser(&parser, 0, b"123456");
        let sub = parser.parse_sub(4).unwrap();
        check_slice_parser(&parser, 4, b"56");
        check_slice_parser(&sub, 0, b"1234");
        assert_eq!(parser.parse_sub(4).unwrap_err(),
                   ParseError::UnexpectedEnd);
        check_slice_parser(&parser, 4, b"56");
    }

    #[test]
    fn slice_parse_dname() {
        let mut parser = SliceParser::new(b"\x03foo\x03bar\x00foo");
        check_slice_parser(&parser, 0, b"\x03foo\x03bar\x00foo");
        assert_eq!(parser.parse_dname().unwrap().into_cow().unwrap().as_bytes(),
                   b"\x03foo\x03bar\x00");
        check_slice_parser(&parser, 9, b"foo");

        let mut parser = SliceParser::new(b"\x03foo\xC3\x00foo");
        check_slice_parser(&parser, 0, b"\x03foo\xC3\x00foo");
        assert_eq!(parser.parse_dname(), Err(ParseError::CompressedLabel));
        check_slice_parser(&parser, 0, b"\x03foo\xC3\x00foo");

        let mut parser = SliceParser::new(b"\x03foo\x03bar");
        check_slice_parser(&parser, 0, b"\x03foo\x03bar");
        assert_eq!(parser.parse_dname(), Err(ParseError::UnexpectedEnd));
        check_slice_parser(&parser, 0, b"\x03foo\x03bar");
    }

    // context_parse_dname: see bits::name::test.
    
    #[test]
    fn parse_charstr() {
        let mut parser = SliceParser::new(b"\x03foo\x00\x06bar");
        check_slice_parser(&parser, 0, b"\x03foo\x00\x06bar");
        assert_eq!(parser.parse_charstr().unwrap().as_bytes(), b"foo");
        check_slice_parser(&parser, 4, b"\x00\x06bar");
        assert_eq!(parser.parse_charstr().unwrap().as_bytes(), b"");
        check_slice_parser(&parser, 5, b"\x06bar");
        assert_eq!(parser.parse_charstr(), Err(ParseError::UnexpectedEnd));
        // XXX Once fixed: test the parser state after error.
    }

    // XXX TODO parse_nest()

    #[test]
    fn parse_octets() {
        let mut parser = SliceParser::new(b"foobar");
        check_slice_parser(&parser, 0, b"foobar");
        assert_eq!(parser.parse_octets(3).unwrap().as_bytes(), b"foo");
        check_slice_parser(&parser, 3, b"bar");
        assert_eq!(parser.parse_octets(0).unwrap().as_bytes(), b"");
        check_slice_parser(&parser, 3, b"bar");
        assert_eq!(parser.parse_octets(4), Err(ParseError::UnexpectedEnd));
        check_slice_parser(&parser, 3, b"bar");
    }
}

