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
//! [`CharStr`]: struct.CharStr.html
//! [`CharStrMut`]: struct.CharStrMut.html
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use std::{cmp, fmt, hash, ops, io};
use std::ascii::AsciiExt;
use bytes::{BufMut, Bytes, BytesMut};
use ::master::error::{ScanError, SyntaxError};
use ::master::print::{Print, Printer};
use ::master::scan::{CharSource, Scan, Scanner};
use super::compose::Compose;
use super::error::ShortBuf;
use super::parse::{ParseAll, ParseAllError, Parse, Parser};


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
}


//--- FromStr


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


//--- Scan and Print

impl Scan for CharStr {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_byte_phrase(|res| {
            if res.len() > 255 {
                Err(SyntaxError::LongCharStr)
            }
            else
            {
                Ok(unsafe { CharStr::from_bytes_unchecked(res) })
            }
        })
    }
}

impl Print for CharStr {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        let mut wr = printer.item()?;
        for ch in &self.inner {
            wr.print_byte(ch)?
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
        self.iter().map(AsciiExt::to_ascii_lowercase)
            .partial_cmp(other.as_ref().iter()
                              .map(AsciiExt::to_ascii_lowercase))
    }
}

impl Ord for CharStr {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter().map(AsciiExt::to_ascii_lowercase)
            .cmp(other.iter().map(AsciiExt::to_ascii_lowercase))
    }
}


//--- Hash

impl hash::Hash for CharStr {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.iter().map(AsciiExt::to_ascii_lowercase)
            .for_each(|ch| ch.hash(state))
    }
}


//--- Display, Debug

impl fmt::Display for CharStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.inner.iter() {
            if ch == b' ' || ch == b'\\' {
                try!(write!(f, "\\{}", ch as char));
            }
            else if ch < b' ' || ch >= 0x7F {
                try!(write!(f, "\\{:03}", ch));
            }
            else {
                try!((ch as char).fmt(f));
            }
        }
        Ok(())
    }
}

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
/// string from individual bytes or byte slices.
pub struct CharStrMut {
    bytes: BytesMut,
}


impl CharStrMut {
    unsafe fn from_bytes_unchecked(bytes: BytesMut) -> Self {
        CharStrMut { bytes }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        unsafe {
            CharStrMut::from_bytes_unchecked(BytesMut::with_capacity(capacity))
        }
    }

    pub fn new() -> Self {
        unsafe {
            CharStrMut::from_bytes_unchecked(BytesMut::new())
        }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.bytes.capacity()
    }

    pub fn freeze(self) -> CharStr {
        unsafe { CharStr::from_bytes_unchecked(self.bytes.freeze()) }
    }
}

/// # Manipulations
///
impl CharStrMut {
    pub fn reserve(&mut self, additional: usize) {
        self.bytes.reserve(additional)
    }

    pub fn push(&mut self, ch: u8) -> Result<(), PushError> {
        self.extend_from_slice(&[ch])
    }

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



//------------ CharStrError --------------------------------------------------

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
    UnexpectedEnd,

    /// A character string has more than 255 octets.
    #[fail(display="character string with more than 255 octets")]
    LongString,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    #[fail(display="illegal escape sequence")]
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    #[fail(display="illegal character")]
    IllegalCharacter,
}


//--- From

impl From<PushError> for FromStrError {
    fn from(_: PushError) -> FromStrError {
        FromStrError::LongString
    }
}


//------------ PushError -----------------------------------------------------

/// An error happened while adding data to a [`CharStrBuf`].
///
/// The only error possible is that the resulting character string would have
/// exceeded the length limit of 255 octets.
///
/// [`CharStrBuf`]: ../struct.CharStrBuf.html
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
#[fail(display="adding bytes would exceed the size limit")]
pub struct PushError;


//============ Internal Helpers =============================================

/*
/// Parses the content of an escape sequence from the beginning of `chars`.
///
/// XXX Move to the zonefile modules once they exist.
fn parse_escape(chars: &mut str::Chars) -> Result<u8, FromStrError> {
    let ch = try!(chars.next().ok_or(FromStrError::UnexpectedEnd));
    if ch == '0' || ch == '1' || ch == '2' {
        let v = ch.to_digit(10).unwrap() * 100
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)))
                     * 10
              + try!(chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape)));
        Ok(v as u8)
    }
    else { Ok(ch as u8) }
}
*/


//============ Testing ======================================================

#[cfg(test)]
mod test {
    use super::*;
    use std::cmp;

    #[test]
    fn from_bytes() {
        assert_eq!(CharStr::from_bytes(b"01234").unwrap().as_bytes(),
                   b"01234");
        assert_eq!(CharStr::from_bytes(b"").unwrap().as_bytes(), b"");
        assert!(CharStr::from_bytes(&vec![0; 255]).is_some());
        assert!(CharStr::from_bytes(&vec![0; 256]).is_none());
    }

    #[test]
    fn parse_and_compose() {
        use bits::{Parser, Composer, ComposeMode}; 

        let mut p = Parser::new(b"\x03foo\x02bar");
        let foo = CharStr::parse(&mut p).unwrap();
        assert_eq!(foo.as_bytes(), b"foo");
        let ba = CharStr::parse(&mut p).unwrap();
        assert_eq!(ba.as_bytes(), b"ba");
        assert_eq!(p.remaining(), 1);
        assert!(CharStr::parse(&mut p).is_err());

        let mut c = Composer::new(ComposeMode::Unlimited, false);
        foo.compose(&mut c).unwrap();
        ba.compose(&mut c).unwrap();
        assert_eq!(c.finish(), b"\x03foo\x02ba");
    }

    fn are_eq(l: &[u8], r: &[u8]) -> bool {
        CharStr::from_bytes(l).unwrap() == CharStr::from_bytes(r).unwrap()
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
        assert_eq!(CharStr::from_bytes(l).unwrap().cmp(
                        CharStr::from_bytes(r).unwrap()),
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
        let mut o = CharStrBuf::new();
        o.push(b'f').unwrap();
        o.push(b'o').unwrap();
        o.push(b'o').unwrap();
        assert_eq!(o.as_bytes(), b"foo");

        let mut o = CharStrBuf::from_vec(vec![0; 254]).unwrap();
        o.push(b'f').unwrap();
        assert_eq!(o.len(), 255);
        assert!(o.push(b'f').is_err());
    }

    #[test]
    fn extend_from_slice() {
        let mut o = CharStrBuf::from_vec(vec![b'f', b'o', b'o']).unwrap();
        o.extend_from_slice(CharStr::from_bytes(b"bar").unwrap()).unwrap();
        assert_eq!(o.as_bytes(), b"foobar");
        assert!(o.clone().extend_from_slice(&[0u8; 250][..]).is_err());
        o.extend_from_slice(&[0u8; 249][..]).unwrap();
        assert_eq!(o.len(), 255);
    }

    #[test]
    fn from_str() {
        use std::str::FromStr;

        assert_eq!(CharStrBuf::from_str("foo").unwrap().as_bytes(),
                   b"foo");
        assert_eq!(CharStrBuf::from_str("f\\oo").unwrap().as_bytes(),
                   b"foo");
        assert_eq!(CharStrBuf::from_str("foo\\112").unwrap().as_bytes(),
                   b"foo\x70");
        assert_eq!(CharStrBuf::from_str("\"foo\\\"2\"").unwrap().as_bytes(),
                   b"foo\"2");
        assert!(CharStrBuf::from_str("ö").is_err());
        assert!(CharStrBuf::from_str("\x06").is_err());
        assert!(CharStrBuf::from_str("06 dii").is_err());
    }
}

