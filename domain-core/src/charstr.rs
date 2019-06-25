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

use std::{cmp, fmt, hash, ops, str};
use bytes::{BufMut, Bytes, BytesMut};
use crate::compose::Compose;
use crate::master::scan::{
    BadSymbol, CharSource, Scan, Scanner, ScanError, Symbol, SymbolError,
    SyntaxError
};
use crate::parse::{ParseAll, ParseAllError, Parse, Parser, ShortBuf};


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
pub struct CharStr {
    /// The underlying bytes slice.
    inner: Bytes
}


/// # Creation and Conversion
///
impl CharStr {
    /// Creates a new empty character string.
    pub fn empty() -> Self {
        CharStr { inner: Bytes::from_static(b"") }
    }

    /// Creates a character string from a bytes value without length check.
    ///
    /// As this can break the guarantees made by the type, it is unsafe.
    unsafe fn from_bytes_unchecked(bytes: Bytes) -> Self {
        CharStr { inner: bytes }
    }

    /// Creates a new character string from a bytes value.
    ///
    /// Returns succesfully if the bytes slice can indeed be used as a
    /// character string, i.e., it is not longer than 255 bytes.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, CharStrError> {
        if bytes.len() > 255 { Err(CharStrError) }
        else { Ok(unsafe { Self::from_bytes_unchecked(bytes) })}
    }

    /// Creates a new character string from a byte slice.
    ///
    /// The function will create a new bytes value and copy the slice’s
    /// content.
    ///
    /// If the byte slice is longer than 255 bytes, the function will return
    /// an error.
    pub fn from_slice(slice: &[u8]) -> Result<Self, CharStrError> {
        if slice.len() > 255 { Err(CharStrError) }
        else { Ok(unsafe { Self::from_bytes_unchecked(slice.into()) })}
    }

    /// Converts the value into its underlying bytes value.
    pub fn into_bytes(self) -> Bytes {
        self.inner
    }

    /// Returns a reference to the underlying bytes value.
    pub fn as_bytes(&self) -> &Bytes {
        &self.inner
    }

    /// Returns a reference to a byte slice of the character string’s data.
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_ref()
    }

    /// Attempts to make the character string mutable.
    ///
    /// This will only succeed if the underlying bytes value has unique
    /// access to its memory. If this fails, you’ll simply get `self` back
    /// for further consideration.
    ///
    /// See [`into_mut`](#method.into_mut) for a variation that copies the
    /// data if necessary.
    pub fn try_into_mut(self) -> Result<CharStrMut, Self> {
        self.inner.try_mut()
            .map(|b| unsafe { CharStrMut::from_bytes_unchecked(b) })
            .map_err(|b| unsafe { CharStr::from_bytes_unchecked(b) })
    }

    /// Provides a mutable version of the character string.
    ///
    /// If the underlying bytes value has exclusive access to its memory,
    /// the function will reuse the bytes value. Otherwise, it will create
    /// a new buffer and copy `self`’s content into it.
    pub fn into_mut(self) -> CharStrMut {
        unsafe { CharStrMut::from_bytes_unchecked(self.inner.into()) }
    }

    /// Scans a character string given as a word of hexadecimal digits.
    pub fn scan_hex<C: CharSource>(
        scanner: &mut Scanner<C>
    ) -> Result<Self, ScanError> {
        scanner.scan_hex_word(|b| unsafe {
            Ok(CharStr::from_bytes_unchecked(b))
        })
    }

    /// Displays a character string as a word in hexadecimal digits.
    pub fn display_hex(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in self {
            write!(f, "{:02X}", ch)?;
        }
        Ok(())
    }
}


//--- FromStr

impl str::FromStr for CharStr {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Most likely, everything is ASCII so take `s`’s length as capacity.
        let mut res = CharStrMut::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(symbol) = Symbol::from_chars(&mut chars)? {
            res.push(symbol.into_byte()?)?
        }
        Ok(res.freeze())
    }
}



//--- Parse, ParseAll, and Compose

impl Parse for CharStr {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let len = parser.parse_u8()? as usize;
        parser.parse_bytes(len).map(|bytes| {
            unsafe { Self::from_bytes_unchecked(bytes) }
        })
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        let len = parser.parse_u8()? as usize;
        parser.advance(len)
    }
}

impl ParseAll for CharStr {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let char_len = parser.parse_u8()? as usize;
        ParseAllError::check(char_len + 1, len)?;
        parser.parse_bytes(char_len).map_err(Into::into).map(|bytes| {
            unsafe { Self::from_bytes_unchecked(bytes) }
        })
    }
}

impl Compose for CharStr {
    fn compose_len(&self) -> usize {
        self.len() + 1
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self.as_ref());
    }
}


//--- Scan and Display

impl Scan for CharStr {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_byte_phrase(|res| {
            if res.len() > 255 {
                Err(SyntaxError::LongCharStr)
            }
            else {
                Ok(unsafe { CharStr::from_bytes_unchecked(res) })
            }
        })
    }
}

impl fmt::Display for CharStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for ch in &self.inner {
            fmt::Display::fmt(&Symbol::from_byte(ch), f)?
        }
        Ok(())
    }
}


//--- Deref and AsRef

impl ops::Deref for CharStr {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AsRef<Bytes> for CharStr {
    fn as_ref(&self) -> &Bytes {
        &self.inner
    }
}

impl AsRef<[u8]> for CharStr {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}


//--- IntoIterator

impl IntoIterator for CharStr {
    type Item = u8;
    type IntoIter = ::bytes::buf::Iter<::std::io::Cursor<Bytes>>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}

impl<'a> IntoIterator for &'a CharStr {
    type Item = u8;
    type IntoIter = ::bytes::buf::Iter<::std::io::Cursor<&'a Bytes>>;

    fn into_iter(self) -> Self::IntoIter {
        (&self.inner).into_iter()
    }
}


//--- PartialEq, Eq

impl<T: AsRef<[u8]>> PartialEq<T> for CharStr {
    fn eq(&self, other: &T) -> bool {
        self.as_slice().eq_ignore_ascii_case(other.as_ref())
    }
}

impl Eq for CharStr { }


//--- PartialOrd, Ord

impl<T: AsRef<[u8]>> PartialOrd<T> for CharStr {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.iter().map(u8::to_ascii_lowercase)
            .partial_cmp(other.as_ref().iter()
                              .map(u8::to_ascii_lowercase))
    }
}

impl Ord for CharStr {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter().map(u8::to_ascii_lowercase)
            .cmp(other.iter().map(u8::to_ascii_lowercase))
    }
}


//--- Hash

impl hash::Hash for CharStr {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.iter().map(u8::to_ascii_lowercase)
            .for_each(|ch| ch.hash(state))
    }
}


//--- Debug

impl fmt::Debug for CharStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!("CharStr(\"".fmt(f));
        try!(fmt::Display::fmt(self, f));
        "\")".fmt(f)
    }
}


//------------ CharStrMut ----------------------------------------------------

/// A mutable DNS character string.
///
/// This type is solely intended to be used when constructing a character
/// string from individual bytes or byte slices. It derefs directly to
/// `[u8]` to allow you to manipulate the acutal content but not to extend
/// it other than through the methods provided by itself.
#[derive(Default)]
pub struct CharStrMut {
    bytes: BytesMut,
}


impl CharStrMut {
    /// Creates a new value from a bytes buffer unchecked.
    ///
    /// Since the buffer may already be longer than it is allowed to be, this
    /// is unsafe.
    unsafe fn from_bytes_unchecked(bytes: BytesMut) -> Self {
        CharStrMut { bytes }
    }

    /// Creates a new mutable character string from a given bytes buffer.
    ///
    /// If `bytes` is longer than 255 bytes, an error is returned.
    pub fn from_bytes(bytes: BytesMut) -> Result<Self, CharStrError> {
        if bytes.len() > 255 {
            Err(CharStrError)
        }
        else {
            Ok(unsafe { Self::from_bytes_unchecked(bytes) })
        }
    }

    /// Creates a new mutable character string with the given capacity.
    ///
    /// The capacity may be larger than the allowed size of a character
    /// string.
    pub fn with_capacity(capacity: usize) -> Self {
        unsafe {
            CharStrMut::from_bytes_unchecked(BytesMut::with_capacity(capacity))
        }
    }

    /// Creates a new mutable character string with a default capacity.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the length of the character string assembled so far.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether the character string is still empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Returns the current capacity of the bytes buffer used for building.
    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    /// Turns the value into an imutable character string.
    pub fn freeze(self) -> CharStr {
        unsafe { CharStr::from_bytes_unchecked(self.bytes.freeze()) }
    }
}

/// # Manipulations
///
impl CharStrMut {
    /// Reserves an `additional` bytes of capacity.
    ///
    /// The resulting capacity may be larger than the allowed size of a
    /// character string.
    pub fn reserve(&mut self, additional: usize) {
        self.bytes.reserve(additional)
    }

    /// Pushes a byte to the end of the character string.
    ///
    /// If this would result in a string longer than the allowed 255 bytes,
    /// returns an error and leaves the string be.
    pub fn push(&mut self, ch: u8) -> Result<(), PushError> {
        self.extend_from_slice(&[ch])
    }

    /// Pushes the content of a byte slice to the end of the character string.
    ///
    /// If this would result in a string longer than the allowed 255 bytes,
    /// returns an error and leaves the string be.
    pub fn extend_from_slice(&mut self, extend: &[u8])
                             -> Result<(), PushError> {
        if self.bytes.len() + extend.len() > 255 {
            Err(PushError)
        }
        else {
            self.bytes.extend_from_slice(extend);
            Ok(())
        }
    }
}


//--- Deref and DerefMut

impl ops::Deref for CharStrMut {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl ops::DerefMut for CharStrMut {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.bytes.as_mut()
    }
}


//--- AsRef and AsMut

impl AsRef<[u8]> for CharStrMut {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

impl AsMut<[u8]> for CharStrMut {
    fn as_mut(&mut self) -> &mut [u8] {
        self.bytes.as_mut()
    }
}


//------------ CharStrError --------------------------------------------------

/// A byte sequence does not represent a valid character string.
///
/// This can only mean that the sequence is longer than 255 bytes.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="illegal character string")]
pub struct CharStrError;


//------------ FromStrError --------------------------------------------

/// An error happened when converting a Rust string to a DNS character string.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    #[fail(display="unexpected end of input")]
    ShortInput,

    /// A character string has more than 255 octets.
    #[fail(display="character string with more than 255 octets")]
    LongString,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    #[fail(display="illegal escape sequence")]
    BadEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    #[fail(display="illegal character '{}'", _0)]
    BadSymbol(Symbol),
}


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
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="adding bytes would exceed the size limit")]
pub struct PushError;


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use super::*;
    use ::master::scan::Symbol;

    #[test]
    fn from_slice() {
        assert_eq!(CharStr::from_slice(b"01234").unwrap().as_slice(),
                   b"01234");
        assert_eq!(CharStr::from_slice(b"").unwrap().as_slice(), b"");
        assert!(CharStr::from_slice(&vec![0; 255]).is_ok());
        assert!(CharStr::from_slice(&vec![0; 256]).is_err());
    }

    #[test]
    fn from_bytes() {
        assert_eq!(CharStr::from_bytes(Bytes::from_static(b"01234"))
                           .unwrap() .as_slice(),
                   b"01234");
        assert_eq!(CharStr::from_bytes(Bytes::from_static(b""))
                           .unwrap().as_slice(),
                   b"");
        assert!(CharStr::from_bytes(vec![0; 255].into()).is_ok());
        assert!(CharStr::from_bytes(vec![0; 256].into()).is_err());
    }

    #[test]
    fn from_str() {
        use std::str::FromStr;

        assert_eq!(CharStr::from_str("foo").unwrap().as_slice(),
                   b"foo");
        assert_eq!(CharStr::from_str("f\\oo").unwrap().as_slice(),
                   b"foo");
        assert_eq!(CharStr::from_str("foo\\112").unwrap().as_slice(),
                   b"foo\x70");
        assert_eq!(CharStr::from_str("\"foo\\\"2\"").unwrap().as_slice(),
                   b"\"foo\"2\"");
        assert_eq!(CharStr::from_str("06 dii").unwrap().as_slice(),
                   b"06 dii");
        assert_eq!(CharStr::from_str("0\\"), Err(FromStrError::ShortInput));
        assert_eq!(CharStr::from_str("0\\2"), Err(FromStrError::ShortInput));
        assert_eq!(CharStr::from_str("0\\2a"),
                   Err(FromStrError::BadEscape));
        assert_eq!(CharStr::from_str("ö"),
                   Err(FromStrError::BadSymbol(Symbol::Char('ö'))));
        assert_eq!(CharStr::from_str("\x06"),
                   Err(FromStrError::BadSymbol(Symbol::Char('\x06'))));
    }

    #[test]
    fn parse() {
        use crate::parse::{Parse, Parser, ShortBuf};

        let mut parser = Parser::from_static(b"12\x03foo\x02bartail");
        parser.advance(2).unwrap();
        let foo = CharStr::parse(&mut parser).unwrap();
        let bar = CharStr::parse(&mut parser).unwrap();
        assert_eq!(foo.as_slice(), b"foo");
        assert_eq!(bar.as_slice(), b"ba");
        assert_eq!(parser.peek_all(), b"rtail");

        assert_eq!(CharStr::parse(&mut Parser::from_static(b"\x04foo")),
                   Err(ShortBuf))
    }

    #[test]
    fn parse_all() {
        use crate::parse::{ParseAll, ParseAllError, Parser};

        let mut parser = Parser::from_static(b"12\x03foo12");
        parser.advance(2).unwrap();
        assert_eq!(CharStr::parse_all(&mut parser.clone(), 5),
                   Err(ParseAllError::TrailingData));
        assert_eq!(CharStr::parse_all(&mut parser.clone(), 2),
                   Err(ParseAllError::ShortField));
        let foo = CharStr::parse_all(&mut parser, 4).unwrap();
        let bar = u8::parse_all(&mut parser, 1).unwrap();
        assert_eq!(foo.as_slice(), b"foo");
        assert_eq!(bar, b'1');
        assert_eq!(parser.peek_all(), b"2");
        
        assert_eq!(CharStr::parse_all(&mut Parser::from_static(b"\x04foo"), 5),
                   Err(ParseAllError::ShortBuf));
    }

    #[test]
    fn compose() {
        use bytes::BytesMut;
        use crate::compose::Compose;

        let mut buf = BytesMut::with_capacity(10);
        let val = CharStr::from_bytes(Bytes::from_static(b"foo")).unwrap();
        assert_eq!(val.compose_len(), 4);
        val.compose(&mut buf);
        assert_eq!(buf, &b"\x03foo"[..]);

        let mut buf = BytesMut::with_capacity(10);
        let val = CharStr::from_bytes(Bytes::from_static(b"")).unwrap();
        assert_eq!(val.compose_len(), 1);
        val.compose(&mut buf);
        assert_eq!(buf, &b"\x00"[..]);
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
        assert_eq!(CharStr::from_slice(l)
                           .unwrap().cmp(&CharStr::from_slice(r).unwrap()),
                   order)
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
        let mut o = CharStrMut::new();
        o.push(b'f').unwrap();
        o.push(b'o').unwrap();
        o.push(b'o').unwrap();
        assert_eq!(o.freeze().as_slice(), b"foo");

        let mut o = CharStrMut::from_bytes(vec![0; 254].into()).unwrap();
        o.push(b'f').unwrap();
        assert_eq!(o.len(), 255);
        assert!(o.push(b'f').is_err());
    }

    #[test]
    fn extend_from_slice() {
        let mut o = CharStrMut::from_bytes(vec![b'f', b'o', b'o'].into())
                               .unwrap();
        o.extend_from_slice(b"bar").unwrap();
        assert_eq!(o.as_ref(), b"foobar");
        assert!(o.extend_from_slice(&[0u8; 250][..]).is_err());
        o.extend_from_slice(&[0u8; 249][..]).unwrap();
        assert_eq!(o.len(), 255);
    }
}

