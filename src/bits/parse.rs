//! Parsing of wire-format DNS data.

use std::mem;
use super::error::{ParseResult, ParseError};
use super::flavor::{Flavor, Owned, Ref, Lazy};
use super::name::{OwnedDName, DNameRef, LazyDName};
use super::nest::{OwnedNest, NestRef, LazyNest};


//------------ Traits -------------------------------------------------------

/// A trait for parsing simple wire-format DNS data.
pub trait ParseBytes<'a>: Sized {
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
            let res: &[u8; 2] = unsafe { mem::transmute(res.as_ptr()) };
            let res = unsafe { mem::transmute(*res) };
            u16::from_be(res)
        })
    }

    /// Parses an unsigned 32-bit word.
    fn parse_u32(&mut self) -> ParseResult<u32> {
        self.parse_bytes(4).map(|res| {
            let res: &[u8; 4] = unsafe { mem::transmute(res.as_ptr()) };
            let res = unsafe { mem::transmute(*res) };
            u32::from_be(res)
        })
    }

    /// Creates a sup-parser starting a the current position.
    fn sub(&self) -> Self;

    /// Creates a sub-parser limited to `len` bytes and advance position.
    fn parse_sub(&mut self, len: usize) -> ParseResult<Self>;

    /// Returns the length of the data we have seen already.
    fn seen(&self) -> usize;

    /// Returns the length of the data left.
    fn left(&self) -> usize;
}

pub trait ParseLazy<'a>: ParseBytes<'a> {
    fn context(&self) -> &'a[u8];
}


/// A trait for parsing wire-format DNS data.
///
/// While the basic types are implemented for every parser through the
/// `ParseBytesSimple` trait, not every parser can parse every kind of
/// domain name. Because of this, parsers may implement the
/// `ParseBytes` trait only for specific flavors.
pub trait ParseFlavor<'a, F: Flavor<'a>>: ParseBytes<'a> {
    fn parse_name(&mut self) -> ParseResult<F::DName>;
    fn parse_nest(&mut self, len: usize) -> ParseResult<F::Nest>;
}

impl<'a, P: ParseBytes<'a>> ParseFlavor<'a, Owned> for P {
    fn parse_name(&mut self) -> ParseResult<OwnedDName> {
        OwnedDName::parse_complete(self)
    }
    
    fn parse_nest(&mut self, len: usize) -> ParseResult<OwnedNest> {
        OwnedNest::parse(self, len)
    }
}

impl<'a, P: ParseBytes<'a>> ParseFlavor<'a, Ref<'a>> for P {
    fn parse_name(&mut self) -> ParseResult<DNameRef<'a>> {
        DNameRef::parse(self)
    }
    
    fn parse_nest(&mut self, len: usize) -> ParseResult<NestRef<'a>> {
        NestRef::parse(self, len)
    }
}

impl<'a> ParseFlavor<'a, Lazy<'a>> for ContextParser<'a> {
    fn parse_name(&mut self) -> ParseResult<LazyDName<'a>> {
        LazyDName::parse(self)
    }

    fn parse_nest(&mut self, len: usize) -> ParseResult<LazyNest<'a>> {
        LazyNest::parse(self, len)
    }
}


//------------ SliceParser --------------------------------------------------

/// A parser that operates on an arbitrary bytes slice.
#[derive(Clone, Debug)]
pub struct SliceParser<'a> {
    slice: &'a [u8],
    seen: usize,
}

impl<'a> SliceParser<'a> {
    pub fn new(slice: &'a [u8]) -> Self {
        SliceParser { slice: slice, seen: 0 }
    }

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
}

//------------ ContextParser ------------------------------------------------

/// A parser that operates on an entire DNS message.
#[derive(Clone, Debug)]
pub struct ContextParser<'a> {
    parser: SliceParser<'a>,
    context: &'a [u8]
}

impl<'a> ContextParser<'a> {
    pub fn new(slice: &'a[u8], context: &'a[u8]) -> Self {
        ContextParser {
            parser: SliceParser::new(slice),
            context: context
        }
    }

    pub fn from_message(message: &'a [u8]) -> Self {
        ContextParser {
            parser: SliceParser::new(message),
            context: message
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
}

impl<'a> ParseLazy<'a> for ContextParser<'a> {
    fn context(&self) -> &'a [u8] {
        self.context
    }
}

