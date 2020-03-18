//! Helper types and traits for dealing with generic octet sequences.

use core::{borrow, hash, fmt};
use core::cmp::Ordering;
use core::convert::TryFrom;
#[cfg(feature = "std")] use std::borrow::Cow;
#[cfg(feature = "std")] use std::vec::Vec;
#[cfg(feature = "bytes")] use bytes::{Bytes, BytesMut};
#[cfg(feature = "smallvec")] use smallvec::{Array, SmallVec};
use derive_more::Display;
use crate::name::ToDname;
use crate::net::{Ipv4Addr, Ipv6Addr};


//------------ OctetsExt -----------------------------------------------------

pub trait OctetsExt: AsRef<[u8]> {
    fn truncate(&mut self, len: usize);
}

impl<'a> OctetsExt for &'a [u8] {
    fn truncate(&mut self, len: usize) {
        if len < self.len() {
            *self = &self[..len]
        }
    }
}

#[cfg(feature = "std")]
impl<'a> OctetsExt for Cow<'a, [u8]> {
    fn truncate(&mut self, len: usize) {
        match *self {
            Cow::Borrowed(ref mut slice) => {
                *slice = &slice[..len]
            }
            Cow::Owned(ref mut vec) => vec.truncate(len)
        }
    }
}

impl OctetsExt for Vec<u8> {
    fn truncate(&mut self, len: usize) {
        self.truncate(len)
    }
}

#[cfg(feature = "bytes")]
impl OctetsExt for Bytes {
    fn truncate(&mut self, len: usize) {
        self.truncate(len)
    }
}

#[cfg(feature = "smallvec")]
impl<A: Array<Item = u8>> OctetsExt for SmallVec<A> {
    fn truncate(&mut self, len: usize) {
        self.truncate(len)
    }
}


//------------ OctetsRef -----------------------------------------------------

pub trait OctetsRef: AsRef<[u8]> + Copy + Sized {
    type Range: AsRef<[u8]>;

    fn range(self, start: usize, end: usize) -> Self::Range;

    fn range_from(self, start: usize) -> Self::Range {
        self.range(start, self.as_ref().len())
    }

    fn range_to(self, end: usize) -> Self::Range {
        self.range(0, end)
    }

    fn range_all(self) -> Self::Range {
        self.range(0, self.as_ref().len())
    }
}

impl<'a, T: OctetsRef> OctetsRef for &'a T {
    type Range = T::Range;

    fn range(self, start: usize, end: usize) -> Self::Range {
        (*self).range(start, end)
    }
}

impl<'a> OctetsRef for &'a [u8] {
    type Range = &'a [u8];

    fn range(self, start: usize, end: usize) -> Self::Range {
        &self[start..end]
    }
}

#[cfg(feature = "std")]
impl<'a, 's> OctetsRef for &'a Cow<'s, [u8]> {
    type Range = &'a [u8];

    fn range(self, start: usize, end: usize) -> Self::Range {
        &self.as_ref()[start..end]
    }
}

impl<'a> OctetsRef for &'a Vec<u8> {
    type Range = &'a [u8];

    fn range(self, start: usize, end: usize) -> Self::Range {
        &self[start..end]
    }
}

#[cfg(feature = "bytes")]
impl<'a> OctetsRef for &'a Bytes  {
    type Range = Bytes;

    fn range(self, start: usize, end: usize) -> Self::Range {
        self.slice(start..end)
    }
}

#[cfg(feature = "smallvec")]
impl<'a, A: Array<Item = u8>> OctetsRef for &'a SmallVec<A> {
    type Range = &'a [u8];

    fn range(self, start: usize, end: usize) -> Self::Range {
        &self.as_slice()[start..end]
    }
}


//------------ OctetsBuilder -------------------------------------------------

pub trait OctetsBuilder: AsRef<[u8]> + AsMut<[u8]> + Sized {

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf>;
    fn truncate(&mut self, len: usize);

    fn len(&self) -> usize {
        self.as_ref().len()
    }

    fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }

    fn append_all<F>(&mut self, op: F) -> Result<(), ShortBuf>
    where F: FnOnce(&mut Self) -> Result<(), ShortBuf> {
        let pos = self.len();
        match op(self) {
            Ok(_) => Ok(()),
            Err(_) => {
                self.truncate(pos);
                Err(ShortBuf)
            }
        }
    }

    fn append_compressed_dname<N: ToDname>(
        &mut self,
        name: &N
    ) -> Result<(), ShortBuf> {
        if let Some(slice) = name.as_flat_slice() {
            self.append_slice(slice)
        }
        else {
            self.append_all(|target| {
                for label in name.iter_labels() {
                    label.build(target)?;
                }
                Ok(())
            })
        }
    }

    fn len_prefixed<F>(&mut self, op: F) -> Result<(), ShortBuf>
    where F: FnOnce(&mut Self) -> Result<(), ShortBuf> {
        let pos = self.len();
        self.append_slice(&[0; 2])?;
        match op(self) {
            Ok(_) => {
                let len = self.len() - pos - 2;
                if len > usize::from(u16::max_value()) {
                    self.truncate(pos);
                    Err(ShortBuf)
                }
                else {
                    self.as_mut()[pos..pos + 2].copy_from_slice(
                        &(len as u16).to_be_bytes()
                    );
                    Ok(())
                }
            }
            Err(_) => {
                self.truncate(pos);
                Err(ShortBuf)
            }
        }
    }
}

#[cfg(feature = "std")]
impl OctetsBuilder for Vec<u8> {
    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        self.extend_from_slice(slice);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        Vec::truncate(self, len)
    }
}

#[cfg(feature="bytes")]
impl OctetsBuilder for BytesMut {
    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        self.extend_from_slice(slice);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        BytesMut::truncate(self, len)
    }

}

#[cfg(feature = "smallvec")]
impl<A: Array<Item = u8>> OctetsBuilder for SmallVec<A> {
    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        self.extend_from_slice(slice);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        SmallVec::truncate(self, len)
    }
}


//------------ EmptyBuilder --------------------------------------------------

pub trait EmptyBuilder {
    fn empty() -> Self;

    fn with_capacity(capacity: usize) -> Self;
}

#[cfg(feature = "std")]
impl EmptyBuilder for Vec<u8> {
    fn empty() -> Self {
        Vec::new()
    }

    fn with_capacity(capacity: usize) -> Self {
        Vec::with_capacity(capacity)
    }
}

#[cfg(feature="bytes")]
impl EmptyBuilder for BytesMut {
    fn empty() -> Self {
        BytesMut::new()
    }

    fn with_capacity(capacity: usize) -> Self {
        BytesMut::with_capacity(capacity)
    }
}

#[cfg(feature = "smallvec")]
impl<A: Array<Item = u8>> EmptyBuilder for SmallVec<A> {
    fn empty() -> Self {
        SmallVec::new()
    }

    fn with_capacity(capacity: usize) -> Self {
        SmallVec::with_capacity(capacity)
    }
}


//------------ IntoOctets ----------------------------------------------------

pub trait IntoOctets {
    type Octets: AsRef<[u8]>;

    fn into_octets(self) -> Self::Octets;
}

#[cfg(feature = "std")]
impl IntoOctets for Vec<u8> {
    type Octets = Self;

    fn into_octets(self) -> Self::Octets {
        self
    }
}

#[cfg(feature="bytes")]
impl IntoOctets for BytesMut {
    type Octets = Bytes;

    fn into_octets(self) -> Self::Octets {
        self.freeze()
    }
}

#[cfg(feature = "smallvec")]
impl<A: Array<Item = u8>> IntoOctets for SmallVec<A> {
    type Octets = Self;

    fn into_octets(self) -> Self::Octets {
        self
    }
}


//------------ IntoBuilder ---------------------------------------------------

pub trait IntoBuilder {
    type Builder: OctetsBuilder;

    fn into_builder(self) -> Self::Builder;
}

#[cfg(feature = "std")]
impl IntoBuilder for Vec<u8> {
    type Builder = Self;

    fn into_builder(self) -> Self::Builder {
        self
    }
}

#[cfg(feature = "std")]
impl<'a> IntoBuilder for &'a [u8] {
    type Builder = Vec<u8>;

    fn into_builder(self) -> Self::Builder {
        self.into()
    }
}

#[cfg(feature = "std")]
impl<'a> IntoBuilder for Cow<'a, [u8]> {
    type Builder = Vec<u8>;

    fn into_builder(self) -> Self::Builder {
        self.into_owned()
    }
}

#[cfg(feature="bytes")]
impl IntoBuilder for Bytes {
    type Builder = BytesMut;

    fn into_builder(self) -> Self::Builder {
        // XXX Currently, we need to copy to do this. If bytes gains a way
        //     to convert from Bytes to BytesMut for non-shared data without
        //     copying, we should change this.
        BytesMut::from(self.as_ref())
    }
}

#[cfg(feature = "smallvec")]
impl<A: Array<Item = u8>> IntoBuilder for SmallVec<A> {
    type Builder = Self;

    fn into_builder(self) -> Self::Builder {
        self
    }
}


//------------ FromBuilder ---------------------------------------------------

pub trait FromBuilder: AsRef<[u8]> + Sized {
    type Builder: OctetsBuilder + IntoOctets<Octets = Self>;

    fn from_builder(builder: Self::Builder) -> Self;
}

#[cfg(feature = "std")]
impl FromBuilder for Vec<u8> {
    type Builder = Self;

    fn from_builder(builder: Self) -> Self {
        builder
    }
}

#[cfg(feature="bytes")]
impl FromBuilder for Bytes {
    type Builder = BytesMut;

    fn from_builder(builder: Self::Builder) -> Self {
        builder.freeze()
    }
}

#[cfg(feature = "smallvec")]
impl<A: Array<Item = u8>> FromBuilder for SmallVec<A> {
    type Builder = Self;

    fn from_builder(builder: Self) -> Self {
        builder
    }
}


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

    /// Returns whether the underlying octets sequence is empty.
    ///
    /// This does _not_ return whether there are no more octets left to parse.
    pub fn is_empty(&self) -> bool {
        self.len == 0
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


//------------ Compose -------------------------------------------------------

/// A type that knows how to compose itself.
///
/// The term ‘composing’ refers to the process of creating a DNS wire-format
/// representation of a value’s data.
pub trait Compose {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf>;

    fn compose_canonical<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        self.compose(target)
    }
}

impl<'a, C: Compose + ?Sized> Compose for &'a C {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        (*self).compose(target)
    }

    fn compose_canonical<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        (*self).compose_canonical(target)
    }
}

impl Compose for i8 {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(&[*self as u8])
    }
}

impl Compose for u8 {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(&[*self])
    }
}

impl Compose for i16 {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for u16 {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for i32 {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for u32 {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.to_be_bytes())
    }
}

impl Compose for Ipv4Addr {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.octets())
    }
}

impl Compose for Ipv6Addr {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.octets())
    }
}

//------------ octets_array --------------------------------------------------

#[macro_export]
macro_rules! octets_array {
    ( $vis:vis $name:ident => $len:expr) => {
        #[derive(Clone)]
        $vis struct $name {
            octets: [u8; $len],
            len: usize
        }

        impl $name {
            pub fn new() -> Self {
                Default::default()
            }

            pub fn as_slice(&self) -> &[u8] {
                &self.octets[..self.len]
            }

            pub fn as_slice_mut(&mut self) -> &mut [u8] {
                &mut self.octets[..self.len]
            }
        }

        impl Default for $name {
            fn default() -> Self {
                $name {
                    octets: [0; $len],
                    len: 0
                }
            }
        }

        impl<'a> TryFrom<&'a [u8]> for $name {
            type Error = ShortBuf;

            fn try_from(src: &'a [u8]) -> Result<Self, ShortBuf> {
                let len = src.len();
                if len > $len {
                    Err(ShortBuf)
                }
                else {
                    let mut res = Self::default();
                    res.octets[..len].copy_from_slice(src);
                    res.len = len;
                    Ok(res)
                }
            }
        }

        impl core::ops::Deref for $name {
            type Target = [u8];

            fn deref(&self) -> &[u8] {
                self.as_slice()
            }
        }

        impl core::ops::DerefMut for $name {
            fn deref_mut(&mut self) -> &mut [u8] {
                self.as_slice_mut()
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                self.as_slice()
            }
        }

        impl AsMut<[u8]> for $name {
            fn as_mut(&mut self) -> &mut [u8] {
                self.as_slice_mut()
            }
        }

        impl borrow::Borrow<[u8]> for $name {
            fn borrow(&self) -> &[u8] {
                self.as_slice()
            }
        }

        impl borrow::BorrowMut<[u8]> for $name {
            fn borrow_mut(&mut self) -> &mut [u8] {
                self.as_slice_mut()
            }
        }

        impl $crate::octets::OctetsBuilder for $name {
            fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
                if slice.len() > $len - self.len {
                    Err(ShortBuf)
                }
                else {
                    let end = self.len + slice.len();
                    self.octets[self.len..end].copy_from_slice(slice);
                    self.len = end;
                    Ok(())
                }
            }

            fn truncate(&mut self, len: usize) {
                if len < self.len {
                    self.len = len
                }
            }
        }

        impl $crate::octets::EmptyBuilder for $name {
            fn empty() -> Self {
                $name {
                    octets: [0; $len],
                    len: 0
                }
            }

            fn with_capacity(_capacity: usize) -> Self {
                Self::empty()
            }
        }

        impl $crate::octets::IntoBuilder for $name {
            type Builder = Self;

            fn into_builder(self) -> Self::Builder {
                self
            }
        }

        impl $crate::octets::FromBuilder for $name {
            type Builder = Self;

            fn from_builder(builder: Self::Builder) -> Self {
                builder
            }
        }

        impl $crate::octets::IntoOctets for $name {
            type Octets = Self;

            fn into_octets(self) -> Self::Octets {
                self
            }
        }

        impl<T: AsRef<[u8]>> PartialEq<T> for $name {
            fn eq(&self, other: &T) -> bool {
                self.as_slice().eq(other.as_ref())
            }
        }

        impl Eq for $name { }

        impl<T: AsRef<[u8]>> PartialOrd<T> for $name {
            fn partial_cmp(&self, other: &T) -> Option<Ordering> {
                self.as_slice().partial_cmp(other.as_ref())
            }
        }

        impl Ord for $name {
            fn cmp(&self, other: &Self) -> Ordering {
                self.as_slice().cmp(other.as_slice())
            }
        }

        impl hash::Hash for $name {
            fn hash<H: hash::Hasher>(&self, state: &mut H) {
                self.as_slice().hash(state)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.debug_tuple(stringify!($name))
                    .field(&self.as_slice())
                    .finish()
            }
        }
    }
}

octets_array!(pub Octets32 => 32);
octets_array!(pub Octets64 => 64);
octets_array!(pub Octets128 => 128);
octets_array!(pub Octets256 => 256);
octets_array!(pub Octets512 => 512);
octets_array!(pub Octets1024 => 1024);
octets_array!(pub Octets2048 => 2048);
octets_array!(pub Octets4096 => 4096);


#[cfg(feature = "smallvec")]
pub type OctetsVec = SmallVec<[u8; 24]>;


//------------ ShortBuf ------------------------------------------------------

/// An attempt was made to go beyond the end of a buffer.
#[derive(Clone, Debug, Display, Eq, PartialEq)]
#[display(fmt="unexpected end of buffer")]
pub struct ShortBuf;

#[cfg(feature = "std")]
impl std::error::Error for ShortBuf { }


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

