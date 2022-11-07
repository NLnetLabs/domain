//! Character strings.
//!
//! The somewhat ill-named `<character-string>` is defined in [RFC 1035] as
//! binary information of up to 255 octets. As such, it doesn’t necessarily
//! contain (ASCII-) characters nor is it a string in a Rust-sense.
//!
//! An existing, immutable character string is represented by the type
//! [`CharStr`]. The type [`CharStrBuilder`] allows constructing a character
//! string from individual octets or octets slices.
//!
//! In wire-format, character strings are encoded as one octet giving the
//! length followed by the actual data in that many octets. The length octet
//! is not part of the content wrapped by [`CharStr`], it contains the data
//! only.
//!
//! A [`CharStr`] can be constructed from a string via the `FromStr`
//! trait. In this case, the string must consist only of printable ASCII
//! characters. Space and double quote are allowed and will be accepted with
//! their ASCII value. Other values need to be escaped via a backslash
//! followed by the three-digit decimal representation of the value. In
//! addition, a backslash followed by a non-digit printable ASCII character
//! is accepted, too, with the ASCII value of this character used.
//!
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use super::cmp::CanonicalOrd;
use super::octets::{
    Compose, EmptyBuilder, FromBuilder, IntoBuilder, OctetsBuilder,
    OctetsFrom, OctetsRef, Parse, ParseError, Parser, ShortBuf,
};
#[cfg(feature = "serde")]
use super::octets::{DeserializeOctets, SerializeOctets};
use super::scan::{BadSymbol, Scan, Scanner, Symbol, SymbolCharsError};
#[cfg(feature = "bytes")]
use bytes::{Bytes, BytesMut};
use core::{cmp, fmt, hash, ops, str};
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ CharStr -------------------------------------------------------

/// The content of a DNS character string.
///
/// A character string consists of up to 255 octets of binary data. This type
/// wraps a octets value. It is guaranteed to always be at most 255 octets in
/// length. It derefs into the underlying octets for working with the content
/// in a familiar way.
///
/// As per [RFC 1035], character strings compare ignoring ASCII case.
/// `CharStr`’s implementations of the `std::cmp` traits act accordingly.
///
/// [RFC 1035]: https://tools.ietf.org/html/rfc1035
#[derive(Clone)]
pub struct CharStr<Octets: ?Sized>(Octets);

impl<Octets: ?Sized> CharStr<Octets> {
    /// Creates a new empty character string.
    pub fn empty() -> Self
    where
        Octets: From<&'static [u8]>,
    {
        CharStr(b"".as_ref().into())
    }

    /// Creates a new character string from an octets value.
    ///
    /// Returns succesfully if `octets` can indeed be used as a
    /// character string, i.e., it is not longer than 255 bytes.
    pub fn from_octets(octets: Octets) -> Result<Self, CharStrError>
    where
        Octets: AsRef<[u8]> + Sized,
    {
        if octets.as_ref().len() > 255 {
            Err(CharStrError)
        } else {
            Ok(unsafe { Self::from_octets_unchecked(octets) })
        }
    }

    /// Creates a character string from octets without length check.
    ///
    /// # Safety
    ///
    /// The caller has to make sure that `octets` is at most 255 octets
    /// long. Otherwise, the behaviour is undefined.
    pub unsafe fn from_octets_unchecked(octets: Octets) -> Self
    where
        Octets: Sized,
    {
        CharStr(octets)
    }

    /// Creates a new empty builder for this character string type.
    pub fn builder() -> CharStrBuilder<Octets::Builder>
    where
        Octets: IntoBuilder,
        Octets::Builder: EmptyBuilder,
    {
        CharStrBuilder::new()
    }

    /// Converts the character string into a builder.
    pub fn into_builder(self) -> CharStrBuilder<Octets::Builder>
    where
        Octets: IntoBuilder + Sized,
    {
        unsafe {
            CharStrBuilder::from_builder_unchecked(IntoBuilder::into_builder(
                self.0,
            ))
        }
    }

    /// Converts the character string into its underlying octets value.
    pub fn into_octets(self) -> Octets
    where
        Octets: Sized,
    {
        self.0
    }

    /// Returns a character string atop a slice of the content.
    pub fn for_slice(&self) -> CharStr<&[u8]>
    where
        Octets: AsRef<[u8]>,
    {
        unsafe { CharStr::from_octets_unchecked(self.0.as_ref()) }
    }

    /// Returns a character string atop a mutable slice of the content.
    pub fn for_slice_mut(&mut self) -> CharStr<&mut [u8]>
    where
        Octets: AsMut<[u8]>,
    {
        unsafe { CharStr::from_octets_unchecked(self.0.as_mut()) }
    }

    /// Returns a reference to a slice of the character string’s data.
    pub fn as_slice(&self) -> &[u8]
    where
        Octets: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    /// Returns a reference to a mutable slice of the character string’s data.
    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where
        Octets: AsMut<[u8]>,
    {
        self.0.as_mut()
    }
}

#[cfg(feature = "bytes")]
#[cfg_attr(docsrs, doc(cfg(feature = "bytes")))]
impl CharStr<Bytes> {
    /// Creates a new character string from a bytes value.
    ///
    /// Returns succesfully if the bytes slice can indeed be used as a
    /// character string, i.e., it is not longer than 255 bytes.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, CharStrError> {
        if bytes.len() > 255 {
            Err(CharStrError)
        } else {
            Ok(unsafe { Self::from_octets_unchecked(bytes) })
        }
    }
}

impl CharStr<[u8]> {
    /// Creates a new character string from an octet slice.
    ///
    /// If the byte slice is longer than 255 bytes, the function will return
    /// an error.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, CharStrError> {
        if slice.len() > 255 {
            Err(CharStrError)
        } else {
            Ok(unsafe { &*(slice as *const [u8] as *const CharStr<[u8]>) })
        }
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets> OctetsFrom<CharStr<SrcOctets>> for CharStr<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: CharStr<SrcOctets>) -> Result<Self, ShortBuf> {
        Octets::octets_from(source.0)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

//--- FromStr

impl<Octets> str::FromStr for CharStr<Octets>
where
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder:
        OctetsBuilder<Octets = Octets> + EmptyBuilder,
{
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Most likely, everything is ASCII so take `s`’s length as capacity.
        let mut builder =
            CharStrBuilder::<<Octets as FromBuilder>::Builder>::with_capacity(
                s.len(),
            );
        let mut chars = s.chars();
        while let Some(symbol) = Symbol::from_chars(&mut chars)? {
            if builder.len() == 255 {
                return Err(FromStrError::LongString);
            }
            builder.append_slice(&[symbol.into_octet()?])?
        }
        Ok(builder.finish())
    }
}

//--- Deref and AsRef

impl<Octets: ?Sized> ops::Deref for CharStr<Octets> {
    type Target = Octets;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Octets: ?Sized> ops::DerefMut for CharStr<Octets> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<Octets: AsRef<U> + ?Sized, U: ?Sized> AsRef<U> for CharStr<Octets> {
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}

impl<Octets: AsMut<U> + ?Sized, U: ?Sized> AsMut<U> for CharStr<Octets> {
    fn as_mut(&mut self) -> &mut U {
        self.0.as_mut()
    }
}

//--- PartialEq and Eq

impl<T, U> PartialEq<U> for CharStr<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn eq(&self, other: &U) -> bool {
        self.as_slice().eq_ignore_ascii_case(other.as_ref())
    }
}

impl<T: AsRef<[u8]> + ?Sized> Eq for CharStr<T> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<T, U> PartialOrd<U> for CharStr<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn partial_cmp(&self, other: &U) -> Option<cmp::Ordering> {
        self.0
            .as_ref()
            .iter()
            .map(u8::to_ascii_lowercase)
            .partial_cmp(other.as_ref().iter().map(u8::to_ascii_lowercase))
    }
}

impl<T: AsRef<[u8]> + ?Sized> Ord for CharStr<T> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0
            .as_ref()
            .iter()
            .map(u8::to_ascii_lowercase)
            .cmp(other.0.as_ref().iter().map(u8::to_ascii_lowercase))
    }
}

impl<T, U> CanonicalOrd<CharStr<U>> for CharStr<T>
where
    T: AsRef<[u8]> + ?Sized,
    U: AsRef<[u8]> + ?Sized,
{
    fn canonical_cmp(&self, other: &CharStr<U>) -> cmp::Ordering {
        match self.0.as_ref().len().cmp(&other.0.as_ref().len()) {
            cmp::Ordering::Equal => {}
            other => return other,
        }
        self.as_slice().cmp(other.as_slice())
    }
}

//--- Hash

impl<T: AsRef<[u8]> + ?Sized> hash::Hash for CharStr<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0
            .as_ref()
            .iter()
            .map(u8::to_ascii_lowercase)
            .for_each(|ch| ch.hash(state))
    }
}

//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for CharStr<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = parser.parse_u8()? as usize;
        parser
            .parse_octets(len)
            .map(|bytes| unsafe { Self::from_octets_unchecked(bytes) })
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        let len = parser.parse_u8()? as usize;
        parser.advance(len)
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> Compose for CharStr<Octets> {
    fn compose<Target: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut Target,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            (self.as_ref().len() as u8).compose(target)?;
            target.append_slice(self.as_ref())
        })
    }
}

//--- Scan and Display

impl<Octets, S: Scanner<Octets = Octets>> Scan<S> for CharStr<Octets> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        scanner.scan_charstr()
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for CharStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.as_ref() {
            fmt::Display::fmt(&Symbol::from_octet(ch), f)?;
        }
        Ok(())
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::LowerHex for CharStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.0.as_ref() {
            write!(f, "{:02x}", ch)?;
        }
        Ok(())
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::UpperHex for CharStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.0.as_ref() {
            write!(f, "{:02X}", ch)?;
        }
        Ok(())
    }
}

//--- IntoIterator

impl<T: AsRef<[u8]>> IntoIterator for CharStr<T> {
    type Item = u8;
    type IntoIter = IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        IntoIter::new(self.0)
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized + 'a> IntoIterator for &'a CharStr<T> {
    type Item = u8;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Iter::new(self.0.as_ref())
    }
}

//--- Debug

impl<T: AsRef<[u8]> + ?Sized> fmt::Debug for CharStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_tuple("CharStr")
            .field(&format_args!("{}", self))
            .finish()
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<T: AsRef<[u8]> + SerializeOctets> serde::Serialize for CharStr<T> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct(
                "CharStr",
                &format_args!("{}", self),
            )
        } else {
            serializer.serialize_newtype_struct(
                "CharStr",
                &self.0.as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octets> serde::Deserialize<'de> for CharStr<Octets>
where
    Octets: FromBuilder + DeserializeOctets<'de>,
    <Octets as FromBuilder>::Builder:
        OctetsBuilder<Octets = Octets> + EmptyBuilder,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;
        use core::str::FromStr;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octets> serde::de::Visitor<'de> for InnerVisitor<'de, Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder,
        {
            type Value = CharStr<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a character string")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                CharStr::from_str(v).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    CharStr::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    CharStr::from_octets(octets).map_err(E::custom)
                })
            }
        }

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octets> serde::de::Visitor<'de> for NewtypeVisitor<Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder,
        {
            type Value = CharStr<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a character string")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octets::visitor()))
                } else {
                    Octets::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octets::visitor()),
                    )
                }
            }
        }

        deserializer.deserialize_newtype_struct(
            "CharStr",
            NewtypeVisitor(PhantomData),
        )
    }
}

//------------ CharStrBuilder ------------------------------------------------

/// A builder for a character string.
///
/// This type wraps an [`OctetsBuilder`] and in turn implements the
/// [`OctetsBuilder`] trait, making sure that the content cannot grow beyond
/// the 255 octet limit of a character string.
#[derive(Clone)]
pub struct CharStrBuilder<Builder>(Builder);

impl<Builder: EmptyBuilder> CharStrBuilder<Builder> {
    /// Creates a new empty builder with default capacity.
    pub fn new() -> Self {
        CharStrBuilder(Builder::empty())
    }

    /// Creates a new empty builder with the given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        CharStrBuilder(Builder::with_capacity(capacity))
    }
}

impl<Builder: OctetsBuilder> CharStrBuilder<Builder> {
    /// Creates a character string builder from an octet sequence unchecked.
    ///
    /// Since the buffer may already be longer than it is allowed to be, this
    /// is unsafe.
    unsafe fn from_builder_unchecked(builder: Builder) -> Self {
        CharStrBuilder(builder)
    }

    /// Creates a character string builder from an octet sequence.
    ///
    /// If the octet sequence is longer than 255 octets, an error is
    /// returned.
    pub fn from_builder(builder: Builder) -> Result<Self, CharStrError> {
        if builder.len() > 255 {
            Err(CharStrError)
        } else {
            Ok(unsafe { Self::from_builder_unchecked(builder) })
        }
    }
}

#[cfg(feature = "std")]
impl CharStrBuilder<Vec<u8>> {
    /// Creates a new empty characater string builder atop an octets vec.
    pub fn new_vec() -> Self {
        Self::new()
    }

    /// Creates a new empty builder atop an octets vec with a given capacity.
    pub fn vec_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

#[cfg(feature = "bytes")]
impl CharStrBuilder<BytesMut> {
    /// Creates a new empty builder for a bytes value.
    pub fn new_bytes() -> Self {
        Self::new()
    }

    /// Creates a new empty builder for a bytes value with a given capacity.
    pub fn bytes_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

impl<Builder: OctetsBuilder> CharStrBuilder<Builder> {
    /// Returns an octet slice of the string assembled so far.
    pub fn as_slice(&self) -> &[u8]
    where
        Builder: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    /// Converts the builder into an imutable character string.
    pub fn finish(self) -> CharStr<Builder::Octets> {
        unsafe { CharStr::from_octets_unchecked(self.0.freeze()) }
    }
}

//--- Default

impl<Builder: EmptyBuilder> Default for CharStrBuilder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}

//--- OctetsBuilder

impl<Builder: OctetsBuilder> OctetsBuilder for CharStrBuilder<Builder> {
    type Octets = Builder::Octets;

    fn append_slice(&mut self, slice: &[u8]) -> Result<(), ShortBuf> {
        if self.0.len() + slice.len() > 255 {
            return Err(ShortBuf);
        }
        self.0.append_slice(slice)
    }

    fn truncate(&mut self, len: usize) {
        self.0.truncate(len)
    }

    fn freeze(self) -> Self::Octets {
        self.0.freeze()
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

//--- Deref and DerefMut

impl<Builder: AsRef<[u8]>> ops::Deref for CharStrBuilder<Builder> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<Builder> ops::DerefMut for CharStrBuilder<Builder>
where
    Builder: AsRef<[u8]> + AsMut<[u8]>,
{
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

//--- AsRef and AsMut

impl<Builder: AsRef<[u8]>> AsRef<[u8]> for CharStrBuilder<Builder> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<Builder: AsMut<[u8]>> AsMut<[u8]> for CharStrBuilder<Builder> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

//------------ IntoIter ------------------------------------------------------

/// The iterator type for `IntoIterator` for a character string itself.
pub struct IntoIter<T> {
    octets: T,
    len: usize,
    pos: usize,
}

impl<T: AsRef<[u8]>> IntoIter<T> {
    pub(crate) fn new(octets: T) -> Self {
        IntoIter {
            len: octets.as_ref().len(),
            octets,
            pos: 0,
        }
    }
}

impl<T: AsRef<[u8]>> Iterator for IntoIter<T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.len {
            None
        } else {
            let res = self.octets.as_ref()[self.pos];
            self.pos += 1;
            Some(res)
        }
    }
}

//------------ Iter ----------------------------------------------------------

/// The iterator type for `IntoIterator` for a reference to a character string.
pub struct Iter<'a> {
    octets: &'a [u8],
}

impl<'a> Iter<'a> {
    pub(crate) fn new(octets: &'a [u8]) -> Self {
        Iter { octets }
    }
}

impl<'a> Iterator for Iter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let (res, octets) = self.octets.split_first()?;
        self.octets = octets;
        Some(*res)
    }
}

//============ Error Types ===================================================

//------------ CharStrError --------------------------------------------------

/// A byte sequence does not represent a valid character string.
///
/// This can only mean that the sequence is longer than 255 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CharStrError;

impl fmt::Display for CharStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("illegal character string")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CharStrError {}

//------------ FromStrError --------------------------------------------

/// An error happened when converting a Rust string to a DNS character string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FromStrError {
    /// A character string has more than 255 octets.
    LongString,

    SymbolChars(SymbolCharsError),

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    BadSymbol(BadSymbol),

    /// The octet builder’s buffer was too short for the data.
    ShortBuf,
}

//--- From

impl From<SymbolCharsError> for FromStrError {
    fn from(err: SymbolCharsError) -> FromStrError {
        FromStrError::SymbolChars(err)
    }
}

impl From<BadSymbol> for FromStrError {
    fn from(err: BadSymbol) -> FromStrError {
        FromStrError::BadSymbol(err)
    }
}

impl From<ShortBuf> for FromStrError {
    fn from(_: ShortBuf) -> FromStrError {
        FromStrError::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FromStrError::LongString => {
                f.write_str("character string with more than 255 octets")
            }
            FromStrError::SymbolChars(ref err) => err.fmt(f),
            FromStrError::BadSymbol(ref err) => err.fmt(f),
            FromStrError::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromStrError {}

//============ Testing ======================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;
    use std::vec::Vec;

    type CharStrRef<'a> = CharStr<&'a [u8]>;

    #[test]
    fn from_slice() {
        assert_eq!(
            CharStr::from_slice(b"01234").unwrap().as_slice(),
            b"01234"
        );
        assert_eq!(CharStr::from_slice(b"").unwrap().as_slice(), b"");
        assert!(CharStr::from_slice(&vec![0; 255]).is_ok());
        assert!(CharStr::from_slice(&vec![0; 256]).is_err());
    }

    #[test]
    #[cfg(feature = "bytes")]
    fn from_bytes() {
        assert_eq!(
            CharStr::from_bytes(bytes::Bytes::from_static(b"01234"))
                .unwrap()
                .as_slice(),
            b"01234"
        );
        assert_eq!(
            CharStr::from_bytes(bytes::Bytes::from_static(b""))
                .unwrap()
                .as_slice(),
            b""
        );
        assert!(CharStr::from_bytes(vec![0; 255].into()).is_ok());
        assert!(CharStr::from_bytes(vec![0; 256].into()).is_err());
    }

    #[test]
    fn from_str() {
        use std::str::FromStr;

        type Cs = CharStr<Vec<u8>>;

        assert_eq!(Cs::from_str("foo").unwrap().as_slice(), b"foo");
        assert_eq!(Cs::from_str("f\\oo").unwrap().as_slice(), b"foo");
        assert_eq!(Cs::from_str("foo\\112").unwrap().as_slice(), b"foo\x70");
        assert_eq!(
            Cs::from_str("\"foo\\\"2\"").unwrap().as_slice(),
            b"\"foo\"2\""
        );
        assert_eq!(Cs::from_str("06 dii").unwrap().as_slice(), b"06 dii");
        assert!(Cs::from_str("0\\").is_err());
        assert!(Cs::from_str("0\\2").is_err());
        assert!(Cs::from_str("0\\2a").is_err());
        assert!(Cs::from_str("ö").is_err());
        assert!(Cs::from_str("\x06").is_err());
    }

    #[test]
    fn parse() {
        let mut parser = Parser::from_static(b"12\x03foo\x02bartail");
        parser.advance(2).unwrap();
        let foo = CharStrRef::parse(&mut parser).unwrap();
        let bar = CharStrRef::parse(&mut parser).unwrap();
        assert_eq!(foo.as_slice(), b"foo");
        assert_eq!(bar.as_slice(), b"ba");
        assert_eq!(parser.peek_all(), b"rtail");

        assert!(
            CharStrRef::parse(&mut Parser::from_static(b"\x04foo")).is_err(),
        )
    }

    #[test]
    fn compose() {
        use crate::base::octets::Compose;

        let mut target = Vec::new();
        let val = CharStr::from_slice(b"foo").unwrap();
        val.compose(&mut target).unwrap();
        assert_eq!(target, b"\x03foo".as_ref());

        let mut target = Vec::new();
        let val = CharStr::from_slice(b"").unwrap();
        val.compose(&mut target).unwrap();
        assert_eq!(target, &b"\x00"[..]);
    }

    fn are_eq(l: &[u8], r: &[u8]) -> bool {
        CharStr::from_slice(l).unwrap() == CharStr::from_slice(r).unwrap()
    }

    #[test]
    fn eq() {
        assert!(are_eq(b"abc", b"abc"));
        assert!(!are_eq(b"abc", b"def"));
        assert!(!are_eq(b"abc", b"ab"));
        assert!(!are_eq(b"abc", b"abcd"));
        assert!(are_eq(b"ABC", b"abc"));
        assert!(!are_eq(b"ABC", b"def"));
        assert!(!are_eq(b"ABC", b"ab"));
        assert!(!are_eq(b"ABC", b"abcd"));
        assert!(are_eq(b"", b""));
        assert!(!are_eq(b"", b"A"));
    }

    fn is_ord(l: &[u8], r: &[u8], order: cmp::Ordering) {
        assert_eq!(
            CharStr::from_slice(l)
                .unwrap()
                .cmp(CharStr::from_slice(r).unwrap()),
            order
        )
    }

    #[test]
    fn ord() {
        use std::cmp::Ordering::*;

        is_ord(b"abc", b"ABC", Equal);
        is_ord(b"abc", b"a", Greater);
        is_ord(b"abc", b"A", Greater);
        is_ord(b"a", b"BC", Less);
    }

    #[test]
    fn append_slice() {
        let mut o = CharStrBuilder::new_vec();
        o.append_slice(b"foo").unwrap();
        assert_eq!(o.finish().as_slice(), b"foo");

        let mut o = CharStrBuilder::from_builder(vec![0; 254]).unwrap();
        o.append_slice(b"f").unwrap();
        assert_eq!(o.len(), 255);
        assert!(o.append_slice(b"f").is_err());

        let mut o =
            CharStrBuilder::from_builder(vec![b'f', b'o', b'o']).unwrap();
        o.append_slice(b"bar").unwrap();
        assert_eq!(o.as_ref(), b"foobar");
        assert!(o.append_slice(&[0u8; 250][..]).is_err());
        o.append_slice(&[0u8; 249][..]).unwrap();
        assert_eq!(o.len(), 255);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn ser_de() {
        use serde_test::{assert_tokens, Configure, Token};

        assert_tokens(
            &CharStr::from_octets(vec![b'f', b'o', 0x12])
                .unwrap()
                .compact(),
            &[
                Token::NewtypeStruct { name: "CharStr" },
                Token::ByteBuf(b"fo\x12"),
            ],
        );

        assert_tokens(
            &CharStr::from_octets(vec![b'f', b'o', 0x12])
                .unwrap()
                .readable(),
            &[
                Token::NewtypeStruct { name: "CharStr" },
                Token::Str("fo\\018"),
            ],
        );
    }
}
