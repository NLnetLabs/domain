//! Character strings.
//!
//! The somewhat ill-named `<character-string>` is defined in [RFC 1035] as
//! binary information of up to 255 octets. As such, it doesn’t necessarily
//! contain (ASCII-) characters nor is it a string in a Rust-sense.
//!
//! An existing, immutable character string is represented by the type
//! [`CharStr`]. The type [`CharStrMut`] allows constructing a character
//! string from individual octets or byte slices.
//!
//! In wire-format, character strings are encoded as one octet giving the
//! length followed by the actual data in that many octets. The length octet
//! is not part of the content wrapped by these two types.
//!
//! A `CharStr` can be constructed from a string slice via the `FromStr`
//! trait. In this case, the string must consist only of printable ASCII
//! characters. Space and double quote are allowed and will be accepted with
//! their ASCII value. Other values need to be escaped via a backslash
//! followed by the three-digit decimal representation of the value. In
//! addition, a backslash followed by a non-digit printable ASCII character
//! is accepted, too, with the ASCII value of this character used.
//!
//! [`CharStr`]: struct.CharStr.html
//! [`CharStrMut`]: struct.CharStrMut.html
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use core::{cmp, fmt, hash, ops, str};
#[cfg(feature = "std")] use std::vec::Vec;
#[cfg(feature = "bytes")] use bytes::{Bytes, BytesMut};
use derive_more::Display;
use crate::cmp::CanonicalOrd;
#[cfg(feature="bytes")] use crate::master::scan::{
    CharSource, Scan, Scanner, ScanError, SyntaxError
};
use crate::str::{BadSymbol, Symbol, SymbolError};
use crate::octets::{
    Compose, EmptyBuilder, FromBuilder, IntoBuilder, IntoOctets,
    OctetsBuilder, OctetsRef, Parse, ParseError, Parser, ShortBuf
};


//------------ CharStr -------------------------------------------------------

/// The content of a DNS character string.
///
/// A character string consists of up to 255 bytes of binary data. This type
/// wraps a bytes value enforcing the length limitation. It derefs into the
/// underlying bytes value for working with the actual content in a familiar
/// way.
///
/// As per [RFC 1035], character strings compare ignoring ASCII case.
/// `CharStr`’s implementations of the `std::cmp` traits act accordingly.
#[derive(Clone)]
pub struct CharStr<Octets: ?Sized>(Octets);

impl<Octets> CharStr<Octets> {
    /// Creates a new empty character string.
    pub fn empty() -> Self
    where Octets: From<&'static [u8]> {
        CharStr(b"".as_ref().into())
    }

    /// Creates a character string from octets without length check.
    ///
    /// As this can break the guarantees made by the type, it is unsafe.
    unsafe fn from_octets_unchecked(octets: Octets) -> Self {
        CharStr(octets)
    }

    /// Converts the character string into a builder.
    pub fn into_builder(self) -> CharStrBuilder<Octets::Builder>
    where Octets: IntoBuilder {
        unsafe {
            CharStrBuilder::from_builder_unchecked(
                IntoBuilder::into_builder(self.0)
            )
        }
    }

    pub fn into_octets(self) -> Octets {
        self.0
    }
}

impl<T: AsRef<[u8]> + ?Sized> CharStr<T> {
    /// Creates a new character string from some octets. 
    ///
    /// Returns succesfully if `octets` can indeed be used as a
    /// character string, i.e., it is not longer than 255 bytes.
    pub fn from_octets(octets: T) -> Result<Self, CharStrError>
    where T: Sized {
        if octets.as_ref().len() > 255 { Err(CharStrError) }
        else { Ok(unsafe { Self::from_octets_unchecked(octets) })}
    }

    /// Returns a reference to a byte slice of the character string’s data.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Displays a character string as a word in hexadecimal digits.
    pub fn display_hex(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self.0.as_ref() {
            write!(f, "{:02X}", ch)?;
        }
        Ok(())
    }
}

#[cfg(feature="bytes")]
impl CharStr<Bytes> {
    /// Creates a new character string from a bytes value.
    ///
    /// Returns succesfully if the bytes slice can indeed be used as a
    /// character string, i.e., it is not longer than 255 bytes.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, CharStrError> {
        if bytes.len() > 255 { Err(CharStrError) }
        else { Ok(unsafe { Self::from_octets_unchecked(bytes) })}
    }

    /// Scans a character string given as a word of hexadecimal digits.
    pub fn scan_hex<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        scanner.scan_hex_word(|b| unsafe {
            Ok(CharStr::from_octets_unchecked(b))
        })
    }
}

impl CharStr<[u8]> {
    /// Creates a new character string from an octet slice.
    ///
    /// If the byte slice is longer than 255 bytes, the function will return
    /// an error.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, CharStrError> {
        if slice.len() > 255 { Err(CharStrError) }
        else { 
            Ok(unsafe {
                &*(slice as *const [u8] as *const CharStr<[u8]>)
            })
        }
    }
}

impl<Octets: AsRef<[u8]>> CharStr<Octets> {
    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
}


//--- FromStr

impl<Octets> str::FromStr for CharStr<Octets>
where
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder:
        OctetsBuilder + EmptyBuilder + IntoOctets<Octets = Octets>,
{
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Most likely, everything is ASCII so take `s`’s length as capacity.
        let mut builder = 
            CharStrBuilder::<<Octets as FromBuilder>::Builder>
            ::with_capacity(s.len());
        builder.push_str(s)?;
        Ok(builder.finish())
    }
}


//--- Deref and AsRef

impl<T: ?Sized> ops::Deref for CharStr<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: AsRef<U> + ?Sized, U: ?Sized> AsRef<U> for CharStr<T> {
    fn as_ref(&self) -> &U {
        self.0.as_ref()
    }
}


//--- PartialEq and Eq

impl<T, U> PartialEq<U> for CharStr<T>
where T: AsRef<[u8]> + ?Sized, U: AsRef<[u8]> + ?Sized {
    fn eq(&self, other: &U) -> bool {
        self.as_slice().eq_ignore_ascii_case(other.as_ref())
    }
}

impl<T: AsRef<[u8]> + ?Sized> Eq for CharStr<T> { }


//--- PartialOrd, Ord, and CanonicalOrd

impl<T, U> PartialOrd<U> for CharStr<T>
where T: AsRef<[u8]> + ?Sized, U: AsRef<[u8]> + ?Sized {
    fn partial_cmp(&self, other: &U) -> Option<cmp::Ordering> {
        self.0.as_ref().iter().map(
            u8::to_ascii_lowercase
        ).partial_cmp(
            other.as_ref().iter().map(u8::to_ascii_lowercase)
        )
    }
}

impl<T: AsRef<[u8]> + ?Sized> Ord for CharStr<T> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.as_ref().iter().map(u8::to_ascii_lowercase)
            .cmp(other.0.as_ref().iter().map(u8::to_ascii_lowercase))
    }
}

impl<T, U> CanonicalOrd<CharStr<U>> for CharStr<T>
where T: AsRef<[u8]> + ?Sized, U: AsRef<[u8]> + ?Sized {
    fn canonical_cmp(&self, other: &CharStr<U>) -> cmp::Ordering {
        match self.0.as_ref().len().cmp(&other.0.as_ref().len()) {
            cmp::Ordering::Equal => { }
            other => return other
        }
        self.as_slice().cmp(other.as_slice())
    }
}


//--- Hash

impl<T: AsRef<[u8]> + ?Sized> hash::Hash for CharStr<T> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().iter().map(u8::to_ascii_lowercase)
            .for_each(|ch| ch.hash(state))
    }
}



//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for CharStr<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = parser.parse_u8()? as usize;
        parser.parse_octets(len).map(|bytes| {
            unsafe { Self::from_octets_unchecked(bytes) }
        })
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        let len = parser.parse_u8()? as usize;
        parser.advance(len)
    }
}

impl<T: AsRef<[u8]> + ?Sized> Compose for CharStr<T> {
    fn compose<Target: OctetsBuilder>(
        &self,
        target: &mut Target
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            (self.as_ref().len() as u8).compose(target)?;
            target.append_slice(self.as_ref())
        })
    }
}

//--- Scan and Display

#[cfg(feature="bytes")]
impl Scan for CharStr<Bytes> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_byte_phrase(|res| {
            if res.len() > 255 {
                Err(SyntaxError::LongCharStr)
            }
            else {
                Ok(unsafe { CharStr::from_octets_unchecked(res) })
            }
        })
    }
}

impl<T: AsRef<[u8]> + ?Sized> fmt::Display for CharStr<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.as_ref() {
            fmt::Display::fmt(&Symbol::from_byte(ch), f)?;
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
        write!(f, "CharStr(\"{:?}\")", self.0.as_ref())
    }
}


//------------ CharStrBuilder ------------------------------------------------

#[derive(Clone)]
pub struct CharStrBuilder<Builder>(Builder);

impl<Builder: EmptyBuilder> CharStrBuilder<Builder> {
    pub fn new() -> Self {
        CharStrBuilder(Builder::empty())
    }

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
        if builder.as_ref().len() > 255 {
            Err(CharStrError)
        }
        else {
            Ok(unsafe { Self::from_builder_unchecked(builder) })
        }
    }
}

#[cfg(feature = "std")]
impl CharStrBuilder<Vec<u8>> {
    pub fn new_vec() -> Self {
        Self::new()
    }

    pub fn vec_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

#[cfg(feature="bytes")]
impl CharStrBuilder<BytesMut> {
    pub fn new_bytes() -> Self {
        Self::new()
    }

    pub fn bytes_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}


impl<Builder: OctetsBuilder> CharStrBuilder<Builder> {
    /// Returns the octet slice of the string assembled so far.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    /// Turns the builder into an imutable character string.
    pub fn finish(self) -> CharStr<Builder::Octets>
    where Builder: IntoOctets {
        unsafe { CharStr::from_octets_unchecked(self.0.into_octets()) }
    }

    /// Pushes a byte to the end of the character string.
    ///
    /// If this would result in a string longer than the allowed 255 bytes,
    /// returns an error and leaves the string be.
    pub fn push(&mut self, ch: u8) -> Result<(), PushError> {
        if self.len() == 255 {
            Err(PushError)
        }
        else {
            self.0.append_slice(&[ch]).map_err(Into::into)
        }
    }

    /// Pushes the content of a byte slice to the end of the character string.
    ///
    /// If this would result in a string longer than the allowed 255 bytes,
    /// returns an error and leaves the string be.
    pub fn extend_from_slice(
        &mut self, extend: &[u8]
    ) -> Result<(), PushError> {
        if self.len() + extend.len() > 255 {
            Err(PushError)
        }
        else {
            self.0.append_slice(extend).map_err(Into::into)
        }
    }

    pub fn push_str(&mut self, s: &str) -> Result<(), FromStrError> {
        let mut chars = s.chars();
        while let Some(symbol) = Symbol::from_chars(&mut chars)? {
            self.push(symbol.into_byte()?)?
        }
        Ok(())
    }
}


//--- Default

impl<Builder: EmptyBuilder> Default for CharStrBuilder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}


//--- Deref and DerefMut

impl<Builder: OctetsBuilder> ops::Deref for CharStrBuilder<Builder> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<Builder: OctetsBuilder> ops::DerefMut for CharStrBuilder<Builder> {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}


//--- AsRef and AsMut

impl<Builder: OctetsBuilder> AsRef<[u8]> for CharStrBuilder<Builder> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<Builder: OctetsBuilder> AsMut<[u8]> for CharStrBuilder<Builder> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}


//------------ IntoIter ------------------------------------------------------

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
            pos: 0
        }
    }
}

impl<T: AsRef<[u8]>> Iterator for IntoIter<T> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.len {
            None
        }
        else {
            let res = self.octets.as_ref()[self.pos];
            self.pos += 1;
            Some(res)
        }
    }
}


//------------ Iter ----------------------------------------------------------

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


//------------ CharStrError --------------------------------------------------

/// A byte sequence does not represent a valid character string.
///
/// This can only mean that the sequence is longer than 255 bytes.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="illegal character string")]
pub struct CharStrError;

#[cfg(feature = "std")]
impl std::error::Error for CharStrError { }


//------------ FromStrError --------------------------------------------

/// An error happened when converting a Rust string to a DNS character string.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    #[display(fmt="unexpected end of input")]
    ShortInput,

    /// A character string has more than 255 octets.
    #[display(fmt="character string with more than 255 octets")]
    LongString,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    #[display(fmt="illegal escape sequence")]
    BadEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    #[display(fmt="illegal character '{}'", _0)]
    BadSymbol(Symbol),
}

#[cfg(feature = "std")]
impl std::error::Error for FromStrError { }


//--- From

impl From<SymbolError> for FromStrError {
    fn from(err: SymbolError) -> FromStrError {
        match err {
            SymbolError::BadEscape => FromStrError::BadEscape,
            SymbolError::ShortInput => FromStrError::ShortInput,
        }
    }
}

impl From<BadSymbol> for FromStrError {
    fn from(err: BadSymbol) -> FromStrError {
        FromStrError::BadSymbol(err.0)
    }
}

impl From<PushError> for FromStrError {
    fn from(_: PushError) -> FromStrError {
        FromStrError::LongString
    }
}


//------------ PushError -----------------------------------------------------

/// An error happened while adding data to a [`CharStrMut`].
///
/// The only error possible is that the resulting character string would have
/// exceeded the length limit of 255 octets.
///
/// [`CharStrMut`]: ../struct.CharStrMut.html
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="adding bytes would exceed the size limit")]
pub struct PushError;

impl From<ShortBuf> for PushError {
    fn from(_: ShortBuf) -> PushError {
        PushError
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PushError { }


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use unwrap::unwrap;
    use std::vec::Vec;
    use super::*;

    type CharStrRef<'a> = CharStr<&'a [u8]>;

    #[test]
    fn from_slice() {
        assert_eq!(
            unwrap!(CharStr::from_slice(b"01234")).as_slice(),
            b"01234"
        );
        assert_eq!(unwrap!(CharStr::from_slice(b"")).as_slice(), b"");
        assert!(CharStr::from_slice(&vec![0; 255]).is_ok());
        assert!(CharStr::from_slice(&vec![0; 256]).is_err());
    }

    #[test]
    #[cfg(feature="bytes")]
    fn from_bytes() {
        assert_eq!(
            unwrap!(CharStr::from_bytes(
                Bytes::from_static(b"01234")
            )) .as_slice(),
            b"01234"
        );
        assert_eq!(
            unwrap!(CharStr::from_bytes(Bytes::from_static(b""))).as_slice(),
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
        assert_eq!(Cs::from_str("0\\"), Err(FromStrError::ShortInput));
        assert_eq!(Cs::from_str("0\\2"), Err(FromStrError::ShortInput));
        assert_eq!(Cs::from_str("0\\2a"), Err(FromStrError::BadEscape));
        assert_eq!(
            Cs::from_str("ö"),
            Err(FromStrError::BadSymbol(Symbol::Char('ö')))
        );
        assert_eq!(
            Cs::from_str("\x06"),
            Err(FromStrError::BadSymbol(Symbol::Char('\x06')))
        );
    }

    #[test]
    fn parse() {
        let mut parser = Parser::from_static(b"12\x03foo\x02bartail");
        unwrap!(parser.advance(2));
        let foo = unwrap!(CharStrRef::parse(&mut parser));
        let bar = unwrap!(CharStrRef::parse(&mut parser));
        assert_eq!(foo.as_slice(), b"foo");
        assert_eq!(bar.as_slice(), b"ba");
        assert_eq!(parser.peek_all(), b"rtail");

        assert_eq!(
            CharStrRef::parse(&mut Parser::from_static(b"\x04foo")),
            Err(ParseError::ShortBuf)
        )
    }

    #[test]
    fn compose() {
        use crate::octets::Compose;

        let mut target = Vec::new();
        let val = unwrap!(CharStr::from_slice(b"foo"));
        unwrap!(val.compose(&mut target));
        assert_eq!(target, b"\x03foo".as_ref());

        let mut target = Vec::new();
        let val = unwrap!(CharStr::from_slice(b""));
        unwrap!(val.compose(&mut target));
        assert_eq!(target, &b"\x00"[..]);
    }

    fn are_eq(l: &[u8], r: &[u8]) -> bool {
        unwrap!(CharStr::from_slice(l)) == unwrap!(CharStr::from_slice(r))
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
            unwrap!(CharStr::from_slice(l)).cmp(
                &unwrap!(CharStr::from_slice(r))
            ),
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
    fn push() {
        let mut o = CharStrBuilder::new_vec();
        unwrap!(o.push(b'f'));
        unwrap!(o.push(b'o'));
        unwrap!(o.push(b'o'));
        assert_eq!(o.finish().as_slice(), b"foo");

        let mut o = unwrap!(CharStrBuilder::from_builder(vec![0; 254]));
        unwrap!(o.push(b'f'));
        assert_eq!(o.len(), 255);
        assert!(o.push(b'f').is_err());
    }

    #[test]
    fn extend_from_slice() {
        let mut o = unwrap!(
            CharStrBuilder::from_builder(vec![b'f', b'o', b'o'])
        );
        unwrap!(o.extend_from_slice(b"bar"));
        assert_eq!(o.as_ref(), b"foobar");
        assert!(o.extend_from_slice(&[0u8; 250][..]).is_err());
        unwrap!(o.extend_from_slice(&[0u8; 249][..]));
        assert_eq!(o.len(), 255);
    }
}

