//! Arbitrary sequences of embedded DNS data.
//!
//! This module defines the `Nest` type that is being used to include unparsed
//! DNS data in composite data structures. It is mainly used by
//! `GenericRecordData`.

use std::borrow::Borrow;
use std::mem;
use std::ops::Deref;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
use super::name::DName;
use super::parse::{ParseBytes, SliceParser, ContextParser};
use super::bytes::BytesBuf;


//------------ Nest --------------------------------------------------------

/// A sequence of arbitrary unparsed DNS data.
///
/// This type allows storing or referencing DNS data and delay parsing until
/// later. Since such data may contain domain names which may be compressed,
/// the type resembles the `DName` type in that actually contains one of
/// three nest variants: `Nest::Slice` for a slice of DNS data that is known
/// to not contain compressed names, `Nest::Owned` for an owned version of
/// that, and `Nest::Packed` for a slice of DNS data that may in fact
/// contain compressed names and therefore also carries a reference to the
/// entire DNS message.
///
/// The functionality of this type is very limited. The most practical thing
/// to do is to acquire a parser for parse out the data though the `parser()`
/// method. The resulting parser will be able to parse names correctly for
/// each underyling type.
#[derive(Clone, Debug)]
pub enum Nest<'a> {
    Slice(&'a NestSlice),
    Owned(NestBuf),
    Packed(PackedNest<'a>)
}

impl<'a> Nest<'a> {
    /// Returns the bytes slice with the nest’s data.
    ///
    /// If the nest is of the packed variant, this data may contain
    /// compressed domain names and therefore may not be useful on its own.
    pub fn as_bytes(&self) -> &[u8] {
        match *self {
            Nest::Slice(nest) => nest,
            Nest::Owned(ref nest) => nest,
            Nest::Packed(ref nest) => nest,
        }
    }

    /// Returns the size in bytes of the nest.
    pub fn len(&self) -> usize {
        match *self {
            Nest::Slice(nest) => nest.len(),
            Nest::Owned(ref nest) => nest.len(),
            Nest::Packed(ref nest) => nest.len(),
        }
    }

    /// Returns whether the nest is empty.
    pub fn is_empty(&self) -> bool {
        match *self {
            Nest::Slice(nest) => nest.is_empty(),
            Nest::Owned(ref nest) => nest.is_empty(),
            Nest::Packed(ref nest) => nest.is_empty(),
        }
    }

    /// Returns a parser for the data of the nest.
    ///
    /// The returned parser can correctly deal with domain names embedded in
    /// the data. That is, for the slice and owned variants it will fail if
    /// it encounters compressed names, whereas for the packed variant it
    /// happily returns the packed variant of `DName`.
    pub fn parser(&self) -> NestParser {
        match *self {
            Nest::Slice(nest) => nest.parser().into(),
            Nest::Owned(ref nest) => nest.parser().into(),
            Nest::Packed(ref nest) => nest.parser().into(),
        }
    }

    /// Appends the nest to the end of the compose target.
    ///
    /// Note that using this method for the packed variant will result in a
    /// corrupt message if the nest’s data contains compressed domain names.
    /// Use with care!
    ///
    /// XXX Because of this, perhaps the method should be removed?
    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        match *self {
            Nest::Slice(nest) => nest.compose(target),
            Nest::Owned(ref nest) => nest.compose(target),
            Nest::Packed(ref nest) => nest.compose(target)
        }
    }
}


//--- From

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
///
/// This type is a very thin wrapper on top of the underlying bytes slice.
/// It even derefs into it, so you get to use all of a bytes slice’s
/// methods.
#[derive(Debug)]
pub struct NestSlice([u8]);

impl NestSlice {
    /// Creates a new nest slice from a bytes slice.
    pub fn from_bytes(bytes: &[u8]) -> &Self {
        unsafe { mem::transmute(bytes) }
    }

    /// Returns a reference underlying bytes slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Clones an owned nest from the nest slice.
    pub fn to_owned(&self) -> NestBuf {
        NestBuf::from_bytes(&self.0)
    }

    /// Parses a nest slice of `len` bytes length.
    pub fn parse<'a, P: ParseBytes<'a>>(parser: &mut P, len: usize)
                                    -> ParseResult<&'a Self> {
        Ok(NestSlice::from_bytes(try!(parser.parse_bytes(len))))
    }

    /// Returns the size of the nest in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the nest is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Appends the nest’s data to the end of the compose target.
    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        target.push_bytes(&self.0)
    }

    /// Returns a parser for the nest’s data.
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

impl AsRef<NestSlice> for NestSlice {
    fn as_ref(&self) -> &Self { self }
}

//--- ToOwned

impl ToOwned for NestSlice {
    type Owned = NestBuf;

    fn to_owned(&self) -> Self::Owned { self.to_owned() }
}


//------------ NestBuf ---------------------------------------------------

/// An owned nest.
///
/// This is a thin wrapper over a bytes vector. It does, however, deref
/// into a `NestSlice` in order to support `Cow<NestSlice>`. A subset of
/// `Vec`’s methods is available, though.
///
/// XXX Actually, it isn’t right now. We’ll add them as needed.
#[derive(Clone, Debug, Default)]
pub struct NestBuf(Vec<u8>);

impl NestBuf {
    /// Creates a new empty owned nest.
    pub fn new() -> Self {
        NestBuf(Vec::new())
    }

    /// Creates an owned nest as a copy of the given bytes slice.
    pub fn from_bytes(slice: &[u8]) -> Self {
        NestBuf(Vec::from(slice))
    }

    /// Creates an owned nest from the given vec.
    pub fn from_vec(vec: Vec<u8>) -> Self {
        NestBuf(vec)
    }

    /// Returns a mutable reference to the nest’s content.
    pub fn as_mut_vec(&mut self) -> &mut Vec<u8> { &mut self.0 }

    /// Parses an owned nest.
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


//--- Deref, Borrow, and AsRef

impl Deref for NestBuf {
    type Target = NestSlice;

    fn deref(&self) -> &Self::Target {
        NestSlice::from_bytes(&self.0)
    }
}

impl Borrow<NestSlice> for NestBuf {
    fn borrow(&self) -> &NestSlice { self.deref() }
}

impl AsRef<NestSlice> for NestBuf {
    fn as_ref(&self) -> &NestSlice { self }
}


//--- BytesBuf

impl BytesBuf for NestBuf {
    fn reserve(&mut self, additional: usize) { self.0.reserve(additional) }
    fn push_bytes(&mut self, data: &[u8]) {
        self.0.push_bytes(data)
    }
}


//------------ PackedNest ----------------------------------------------------

/// A bytes sequence possibly containing compressed domain names.
///
/// For most purposes, this is identical to a `&NestSlice` except that it
/// carries the context for decompressing domain names around.
#[derive(Clone, Debug)]
pub struct PackedNest<'a> {
    bytes: &'a [u8],
    context: &'a [u8]
}

impl<'a> PackedNest<'a> {
    /// Creates a new packed nest from data and context.
    pub fn new(bytes: &'a[u8], context: &'a[u8]) -> Self {
        PackedNest { bytes: bytes, context: context }
    }

    /// Parses a packed nest.
    pub fn parse<P: ParseBytes<'a>>(parser: &mut P, context: &'a [u8],
                                    len: usize) -> ParseResult<Self> {
        Ok(PackedNest::new(try!(parser.parse_bytes(len)), context))
    }

    /// Returns the data of the packed nest.
    ///
    /// Note that using this data for parsing may result in parse errors if
    /// it does contain compressed domain names.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes
    }

    /// Returns the size in bytes of the nest’s data.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the nest is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Append the nest’s data to the end of the compose target.
    ///
    /// Note that the resulting message will be corrupt if the nest does
    /// contain compressed names. Use with care!
    ///
    /// XXX Perhaps we should not allow composing packed nests at all?
    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        target.push_bytes(self.bytes)
    }

    /// Returns a parser for the nest’s data.
    pub fn parser(&self) -> ContextParser<'a> {
        ContextParser::from_parts(self.bytes, self.context)
    }
}


//--- Deref

impl<'a> Deref for PackedNest<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.bytes
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
                => p.parse_sub(len).map(NestParser::Slice),
            NestParser::Context(ref mut p)
                => p.parse_sub(len).map(NestParser::Context)
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


//============ Testing ======================================================

#[cfg(test)]
mod test {
}
