//! Character strings.
//!
//! The somewhat ill-named `<character-string>` is defined in [RFC 1035] as
//! binary information of up to 255 bytes. As such, it doesn’t necessarily
//! contain (ASCII-) characters nor is it a string in the Rust-sense.
//! Character string  are encoded as one octet giving the length followed by
//! the actual data in that many octets.
//!
//! The type [`CharStr`] defined in this module wraps a bytes slice making
//! sure it always adheres to the length limit. It is an unsized type and
//! is typically used as a reference. Its owned companion is [`CharStrBuf`].
//!
//! When defining types that contain character strings, it is best to make
//! them generic over `AsRef<CharStr>` so that they can be used both with
//! `&'a CharStr` for borrowed data and `CharStrBuf` for owned data.
//!
//! [`CharStr`]: struct.CharStr.html
//! [`CharStrBuf`]: struct.CharStrBuf.html
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

use std::{cmp, error, fmt, hash, ops, str};
use bytes::{BufMut, Bytes};
use super::compose::Composable;
use super::error::ShortBuf;
use super::parse::{Parseable, Parser};
/*
use ::master::{Scanner, ScanResult};
use super::{Composer, ComposeResult, Parser, ParseResult};
*/


//------------ CharStr -------------------------------------------------------

/// A slice of a DNS character string.
///
/// A character string consists of up to 255 bytes of binary data. This type
/// wraps a bytes slice enforcing the length limitation. It derefs into the
/// underlying slice allowing both read-only and mutable access to it.
///
/// As per [RFC 1035], character strings compare ignoring ASCII case.
/// `CharStr`’s implementations of the `std::cmp` act accordingly.
///
/// This is an usized type and needs to be used behind a pointer such as
/// a reference or box.
#[derive(Clone)]
pub struct CharStr {
    /// The underlying bytes slice.
    inner: Bytes
}


/// # Creation and Conversion
///
impl CharStr {
    /// Creates a character string reference from a bytes slice.
    ///
    /// This function doesn’t check the length of the slice and therefore is
    /// unsafe.
    unsafe fn from_bytes_unchecked(bytes: Bytes) -> Self {
        CharStr { inner: bytes }
    }

    /// Creates a new character string from the bytes slice.
    ///
    /// Returns `Some(_)` if the bytes slice can indeed be used as a
    /// character string, ie., it is not longer than 255 bytes, or `None`
    /// otherwise.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, CharStrError> {
        if bytes.len() > 255 { Err(CharStrError) }
        else { Ok(unsafe { Self::from_bytes_unchecked(bytes) })}
    }

    pub fn as_bytes(&self) -> &Bytes {
        &self.inner
    }

    /// Returns a reference to the character string’s data.
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_ref()
    }
}


//--- Parseable and Composable

impl Parseable for CharStr {
    type Err = ShortBuf;

    fn parse(parser: &mut Parser) -> Result<Self, ShortBuf> {
        let len = parser.parse_u8()? as usize;
        parser.parse_bytes(len).map(|bytes| {
            unsafe { Self::from_bytes_unchecked(bytes) }
        })
    }
}

impl Composable for CharStr {
    fn compose_len(&self) -> usize {
        self.len() + 1
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_u8(self.len() as u8);
        buf.put_slice(self.as_ref());
    }
}


//--- Deref, DerefMut, Borrow, AsRef

impl ops::Deref for CharStr {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ops::DerefMut for CharStr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
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


//--- PartialEq, Eq

impl<T: AsRef<[u8]>> PartialEq<T> for CharStr {
    fn eq(&self, other: &T) -> bool {
        self.inner.as_ref().eq(other.as_ref())
    }
}

impl Eq for CharStr { }


//--- PartialOrd, Ord

impl<T: AsRef<[u8]>> PartialOrd<T> for CharStr {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.inner.as_ref().partial_cmp(other.as_ref())
    }
}

impl Ord for CharStr {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.inner.as_ref().cmp(other.inner.as_ref())
    }
}


//--- Hash

impl hash::Hash for CharStr {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.inner.hash(state)
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


//------------ CharStrError --------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CharStrError;

impl error::Error for CharStrError {
    fn description(&self) -> &str {
        "illegal character string"
    }
}

impl fmt::Display for CharStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("illegal character string")
    }
}

//------------ FromStrError --------------------------------------------

/// An error happened when converting a Rust string to a DNS character string.
#[derive(Clone, Debug)]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    UnexpectedEnd,

    /// A character string has more than 255 octets.
    LongString,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    IllegalCharacter,
}


//--- From

impl From<PushError> for FromStrError {
    fn from(_: PushError) -> FromStrError {
        FromStrError::LongString
    }
}


//--- Error

impl error::Error for FromStrError {
    fn description(&self) -> &str {
        use self::FromStrError::*;

        match *self {
            UnexpectedEnd => "unexpected end of input",
            LongString => "character string with more than 255 octets",
            IllegalEscape => "illegal escape sequence",
            IllegalCharacter => "illegal character",
        }
    }
}


//--- Display

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


//------------ PushError -----------------------------------------------------

/// An error happened while adding data to a [`CharStrBuf`].
///
/// The only error possible is that the resulting character string would have
/// exceeded the length limit of 255 octets.
///
/// [`CharStrBuf`]: ../struct.CharStrBuf.html
#[derive(Clone, Copy)]
pub struct PushError;

impl error::Error for PushError {
    fn description(&self) -> &str {
        "adding bytes would exceed the size limit"
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

impl fmt::Debug for PushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "PushError".fmt(f)
    }
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "adding bytes would exceed the size limit".fmt(f)
    }
}


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

