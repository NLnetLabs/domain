//! Arbitrary sequences of embedded DNS data.

use std::borrow::Borrow;
use std::fmt::Debug;
use std::ops::Deref;
use super::compose::ComposeBytes;
use super::parse::{ParseBytes, ParseFlavor, ParseLazy, SliceParser,
                   ContextParser};
use super::error::{ComposeResult, ParseResult};
use super::flavor::{self, FlatFlavor};


//------------ Nest --------------------------------------------------------

/// A trait common to all nest types.
pub trait Nest<'a, F: FlatFlavor<'a>>: Sized + Clone + Debug {
    type Parser: ParseFlavor<'a, F> + Clone + Debug;

    fn as_slice<'b: 'a>(&'b self) -> &'a [u8];
    fn len(&self) -> usize();
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()>;
    fn parser(&self) -> Self::Parser;
}


//------------ NestRef -----------------------------------------------------

/// A reference to a nest.
///
/// This is a thin wrapper around an actual `&[u8]` and even derefs to it.
#[derive(Clone, Debug)]
pub struct NestRef<'a> {
    inner: &'a [u8]
}

impl<'a> NestRef<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        NestRef { inner: bytes }
    }

    pub fn as_slice(&self) -> &'a [u8] {
        self.inner
    }

    /*
    pub fn to_owned(&self) -> OwnedNest {
        OwnedNest::from_bytes(self.inner)
    }
    */

    pub fn parse<P: ParseBytes<'a>>(parser: &mut P, len: usize)
                                    -> ParseResult<Self> {
        Ok(NestRef { inner: try!(parser.parse_bytes(len)) })
    }
}


//--- Nest

impl<'a> Nest<'a, flavor::Ref<'a>> for NestRef<'a> {
    type Parser = SliceParser<'a>;

    fn as_slice<'b: 'a>(&'b self) -> &'a [u8] {
        self.inner
    }

    fn len(&self) -> usize {
        self.inner.len()
    }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        target.push_bytes(self.inner)
    }

    fn parser(&self) -> SliceParser<'a> {
        SliceParser::new(&self.inner)
    }
}


//--- From

impl<'a> From<&'a [u8]> for NestRef<'a> {
    fn from(bytes: &'a[u8]) -> NestRef<'a> {
        NestRef::from_bytes(bytes)
    }
}


//--- Deref, Borrow, AsRef

impl<'a> Deref for NestRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.inner
    }
}

impl<'a> Borrow<[u8]> for NestRef<'a> {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl<'a> AsRef<[u8]> for NestRef<'a> {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}

/*
//------------ OwnedNest ---------------------------------------------------

/// An owned nest.
///
/// This type derefs to `Vec<u8>` for all bytes slice methods.
#[derive(Clone, Debug)]
pub struct OwnedNest {
    inner: Vec<u8>
}

impl OwnedNest {
    pub fn new() -> Self {
        OwnedNest { inner: Vec::new() }
    }

    pub fn from_bytes(slice: &[u8]) -> Self {
        OwnedNest { inner: Vec::from(slice) }
    }

    pub fn parse<'a, P>(p: &mut P, len: usize) -> ParseResult<Self>
                 where P: ParseBytes<'a> {
        Ok(try!(NestRef::parse(p, len)).to_owned())
    }

    pub fn as_slice(&self) -> &[u8] {
        self
    }

}


//--- From

impl<'a> From<&'a [u8]> for OwnedNest {
    fn from(bytes: &'a [u8]) -> Self {
        OwnedNest::from_bytes(bytes)
    }
}


//--- Deref, AsRef

impl Deref for OwnedNest {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
*/

//------------ LazyNest ----------------------------------------------------

/// A bytes sequence possibly containing compressed domain names.
///
/// For most purposes, this is identical to `NestRef` except that it
/// carries the context for decompressing domain names around.
#[derive(Clone, Debug)]
pub struct LazyNest<'a> {
    bytes: &'a [u8],
    context: &'a [u8]
}

impl<'a> LazyNest<'a> {
    pub fn new(bytes: &'a[u8], context: &'a[u8]) -> Self {
        LazyNest { bytes: bytes, context: context }
    }

    pub fn parse<P: ParseLazy<'a>>(parser: &mut P, len: usize)
                                   -> ParseResult<Self> {
        Ok(LazyNest::new(try!(parser.parse_bytes(len)),
                          parser.context()))
    }

    /*
    pub fn to_owned(&self) -> OwnedNest {
        OwnedNest::from_bytes(self.bytes)
    }
    */
}


//--- Nest

impl<'a> Nest<'a, flavor::Lazy<'a>> for LazyNest<'a> {
    type Parser = ContextParser<'a>;

    fn as_slice<'b: 'a>(&'b self) -> &'a [u8] {
        self.bytes
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        target.push_bytes(self.bytes)
    }

    fn parser(&self) -> ContextParser<'a> {
        ContextParser::new(self.bytes, self.context)
    }
}


//--- Deref

impl<'a> Deref for LazyNest<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

