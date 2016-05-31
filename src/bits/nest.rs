//! Arbitrary sequences of embedded DNS data.

use std::borrow::Borrow;
use std::mem;
use std::ops::Deref;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
use super::name::DName;
use super::parse::{ParseBytes, ParsePacked, SliceParser, ContextParser};


//------------ AsNest ------------------------------------------------------

/// A trait for any type that can be expressed as a `Nest` value.
///
/// This is a helper trait for allowing `ComposeBytes::push_nest()` to be
/// generic over all types of nests.
pub trait AsNest {
    fn as_nest(&self) -> Nest;
}


//------------ Nest --------------------------------------------------------

/// A nest.
#[derive(Clone, Debug)]
pub enum Nest<'a> {
    Slice(&'a NestSlice),
    Owned(NestBuf),
    Packed(PackedNest<'a>)
}

impl<'a> Nest<'a> {
    pub fn as_slice(&self) -> &[u8] {
        match *self {
            Nest::Slice(nest) => nest,
            Nest::Owned(ref nest) => nest,
            Nest::Packed(ref nest) => &nest,
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            Nest::Slice(ref nest) => nest.len(),
            Nest::Owned(ref nest) => nest.len(),
            Nest::Packed(ref nest) => nest.len(),
        }
    }

    pub fn parser(&self) -> NestParser {
        match *self {
            Nest::Slice(ref nest) => nest.parser().into(),
            Nest::Owned(ref nest) => nest.parser().into(),
            Nest::Packed(ref nest) => nest.parser().into(),
        }
    }

    pub fn compose<C: ComposeBytes>(&self, c: &mut C) -> ComposeResult<()> {
        match *self {
            Nest::Slice(ref nest) => nest.compose(c),
            Nest::Owned(ref nest) => nest.compose(c),
            Nest::Packed(ref nest) => nest.compose(c)
        }
    }
}

impl<'a> From<&'a NestSlice> for Nest<'a> {
    fn from(nest: &'a NestSlice) -> Nest<'a> {
        Nest::Slice(nest)
    }
}

impl<'a> From<NestBuf> for Nest<'a> {
    fn from(nest: NestBuf) -> Nest<'a> {
        Nest::Owned(nest)
    }
}

impl<'a> From<PackedNest<'a>> for Nest<'a> {
    fn from(nest: PackedNest<'a>) -> Nest<'a> {
        Nest::Packed(nest)
    }
}


//------------ NestSlice ---------------------------------------------------

/// A nest on top of a bytes slice.
#[derive(Debug)]
pub struct NestSlice([u8]);

impl NestSlice {
    pub fn from_bytes(bytes: &[u8]) -> &Self {
        unsafe { mem::transmute(bytes) }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn to_owned(&self) -> NestBuf {
        NestBuf::from_bytes(&self.0)
    }

    pub fn parse<'a, P: ParseBytes<'a>>(parser: &mut P, len: usize)
                                    -> ParseResult<&'a Self> {
        Ok(NestSlice::from_bytes(try!(parser.parse_bytes(len))))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        target.push_bytes(&self.0)
    }

    pub fn parser(&self) -> SliceParser {
        SliceParser::new(&self.0)
    }
}


//--- From

impl<'a> From<&'a [u8]> for &'a NestSlice {
    fn from(bytes: &'a[u8]) -> Self {
        NestSlice::from_bytes(bytes)
    }
}


//--- Deref, Borrow, AsRef

impl Deref for NestSlice {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<[u8]> for NestSlice {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl AsRef<[u8]> for NestSlice {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}


//------------ NestBuf ---------------------------------------------------

/// An owned nest.
///
/// This type derefs to `Vec<u8>` for all bytes slice methods.
#[derive(Clone, Debug)]
pub struct NestBuf(Vec<u8>);

impl NestBuf {
    pub fn new() -> Self {
        NestBuf(Vec::new())
    }

    pub fn from_bytes(slice: &[u8]) -> Self {
        NestBuf(Vec::from(slice))
    }

    pub fn parse<'a, P>(p: &mut P, len: usize) -> ParseResult<Self>
                 where P: ParseBytes<'a> {
        Ok(try!(NestSlice::parse(p, len)).to_owned())
    }
}


//--- From

impl<'a> From<&'a [u8]> for NestBuf {
    fn from(bytes: &'a [u8]) -> Self {
        NestBuf::from_bytes(bytes)
    }
}


//--- Deref, AsRef

impl Deref for NestBuf {
    type Target = NestSlice;

    fn deref(&self) -> &Self::Target {
        NestSlice::from_bytes(&self.0)
    }
}

impl Borrow<NestSlice> for NestBuf {
    fn borrow(&self) -> &NestSlice { self.deref() }
}


//------------ PackedNest ----------------------------------------------------

/// A bytes sequence possibly containing compressed domain names.
///
/// For most purposes, this is identical to a `NestSlice` except that it
/// carries the context for decompressing domain names around.
#[derive(Clone, Debug)]
pub struct PackedNest<'a> {
    bytes: &'a [u8],
    context: &'a [u8]
}

impl<'a> PackedNest<'a> {
    pub fn new(bytes: &'a[u8], context: &'a[u8]) -> Self {
        PackedNest { bytes: bytes, context: context }
    }

    pub fn parse<P: ParsePacked<'a>>(parser: &mut P, len: usize)
                                   -> ParseResult<Self> {
        Ok(PackedNest::new(try!(parser.parse_bytes(len)),
                          parser.context()))
    }

    pub fn to_owned(&self) -> NestBuf {
        NestBuf::from_bytes(self.bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        target.push_bytes(self.bytes)
    }

    pub fn parser(&self) -> ContextParser<'a> {
        ContextParser::new(self.bytes, self.context)
    }
}


//--- Deref

impl<'a> Deref for PackedNest<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}


//------------ NestParser ----------------------------------------------------

/// A parser for any kind of nest.
#[derive(Clone, Debug)]
pub enum NestParser<'a> {
    Slice(SliceParser<'a>),
    Context(ContextParser<'a>)
}

impl<'a> ParseBytes<'a> for NestParser<'a> {
    fn parse_bytes(&mut self, len: usize) -> ParseResult<&'a [u8]> {
        match *self {
            NestParser::Slice(ref mut p) => p.parse_bytes(len),
            NestParser::Context(ref mut p) => p.parse_bytes(len)
        }
    }

    fn skip(&mut self, len: usize) -> ParseResult<()> {
        match *self {
            NestParser::Slice(ref mut p) => p.skip(len),
            NestParser::Context(ref mut p) => p.skip(len)
        }
    }

    fn sub(&self) -> Self {
        match *self {
            NestParser::Slice(ref p) => NestParser::Slice(p.sub()),
            NestParser::Context(ref p) => NestParser::Context(p.sub())
        }
    }

    fn parse_sub(&mut self, len: usize) -> ParseResult<Self> {
        match *self {
            NestParser::Slice(ref mut p)
                => p.parse_sub(len).map(|x| NestParser::Slice(x)),
            NestParser::Context(ref mut p)
                => p.parse_sub(len).map(|x| NestParser::Context(x))
        }
    }

    fn seen(&self) -> usize {
        match *self {
            NestParser::Slice(ref p) => p.seen(),
            NestParser::Context(ref p) => p.seen()
        }
    }

    fn left(&self) -> usize {
        match *self {
            NestParser::Slice(ref p) => p.left(),
            NestParser::Context(ref p) => p.left()
        }
    }

    fn parse_dname(&mut self) -> ParseResult<DName<'a>> {
        match *self {
            NestParser::Slice(ref mut p) => p.parse_dname(),
            NestParser::Context(ref mut p) => p.parse_dname()
        }
    }

    fn parse_nest(&mut self, len: usize) -> ParseResult<Nest<'a>> {
        match *self {
            NestParser::Slice(ref mut p) => p.parse_nest(len),
            NestParser::Context(ref mut p) => p.parse_nest(len)
        }
    }
}

impl<'a> From<SliceParser<'a>> for NestParser<'a> {
    fn from(p: SliceParser<'a>) -> Self {
        NestParser::Slice(p)
    }
}

impl<'a> From<ContextParser<'a>> for NestParser<'a> {
    fn from(p: ContextParser<'a>) -> Self {
        NestParser::Context(p)
    }
}
