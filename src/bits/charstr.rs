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

use std::{borrow, cmp, error, fmt, hash, mem, ops, str};
use std::ascii::AsciiExt;
use std::ops::Deref;
use ::master::{Scanner, ScanResult};
use super::{Composer, ComposeResult, Parser, ParseResult};


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
pub struct CharStr {
    /// The underlying bytes slice.
    inner: [u8]
}


/// # Creation and Conversion
///
impl CharStr {
    /// Creates a character string reference from a bytes slice.
    ///
    /// This function doesn’t check the length of the slice and therefore is
    /// unsafe.
    unsafe fn from_bytes_unsafe(bytes: &[u8]) -> &Self {
        mem::transmute(bytes)
    }

    /// Creates a mutable character string reference from a bytes slice.
    ///
    /// This function doesn’t check the length of the slice and therefore is
    /// unsafe.
    unsafe fn from_bytes_mut_unsafe(bytes: &mut [u8]) -> &mut Self {
        mem::transmute(bytes)
    }

    /// Creates a new character string from the bytes slice.
    ///
    /// Returns `Some(_)` if the bytes slice can indeed be used as a
    /// character string, ie., it is not longer than 255 bytes, or `None`
    /// otherwise.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() > 255 { None }
        else { Some(unsafe { Self::from_bytes_unsafe(bytes) })}
    }

    /// Returns a reference to the character string’s data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Returns an owned version of the character string.
    pub fn to_owned(&self) -> CharStrBuf {
        unsafe { CharStrBuf::from_vec_unsafe(self.inner.into()) }
    }
}


/// # Properties
///
impl CharStr {
    /// Returns the length of the character string’s data in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns whether the character string’s data is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}


/// # Parsing and Composing
///
impl CharStr {
    /// Parses a character string.
    ///
    /// If successful, the returned character string will be a reference into
    /// the parser’s data.
    pub fn parse<'a>(parser: &mut Parser<'a>) -> ParseResult<&'a Self> {
        let len = try!(parser.parse_u8()) as usize;
        parser.parse_bytes(len)
              .map(|bytes| unsafe { CharStr::from_bytes_unsafe(bytes) })
    }

    /// Composes a character string.
    pub fn compose<C: AsMut<Composer>>(&self, mut target: C)
                                       -> ComposeResult<()> {
        assert!(self.inner.len() < 256);
        try!(target.as_mut().compose_u8(self.inner.len() as u8));
        target.as_mut().compose_bytes(&self.inner)
    }
}


//--- Deref, DerefMut, Borrow, AsRef

impl ops::Deref for CharStr {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl ops::DerefMut for CharStr {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl borrow::Borrow<[u8]> for CharStr {
    fn borrow(&self) -> &[u8] {
        &self.inner
    }
}

impl AsRef<CharStr> for CharStr {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl AsRef<[u8]> for CharStr {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}


//--- PartialEq, Eq

impl PartialEq for CharStr {
    fn eq(&self, other: &Self) -> bool {
        self.inner.eq_ignore_ascii_case(&other.inner)
    }
}

impl<C: AsRef<CharStr>> PartialEq<C> for CharStr {
    fn eq(&self, other: &C) -> bool {
        self.eq(other.as_ref())
    }
}

impl Eq for CharStr { }


//--- PartialOrd, Ord

impl PartialOrd for CharStr {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<C: AsRef<CharStr>> PartialOrd<C> for CharStr {
    fn partial_cmp(&self, other: &C) -> Option<cmp::Ordering> {
        Some(self.cmp(other.as_ref()))
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
        for c in self.iter() {
            state.write_u8(c.to_ascii_lowercase())
        }
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


//------------ CharStrBuf ----------------------------------------------------

/// An owned, mutable DNS character string.
///
/// This type adds the methods [`push()`], [`extend_from_slice()`], and
/// [`extend_from_str()`] to the methods from [`CharStr`] and `[u8]` to
/// which it derefs (transitively). Note that the `Extend` trait is not
/// implemented since adding data to a character string may fail if the
/// string would become too long.
///
/// In addition through the usual suspects, values can be created from
/// strings via the `FromStr` trait as well as by parsing from master
/// file data through the [`scan()`] function.
///
/// [`push()`]: #method.push
/// [`extend_from_slice()`]: #method.extend_from_slice
/// [`extend_from_str()`]: #method.extend_from_str
/// [`scan()`]: #method.scan
/// [`CharStr`]: ../struct.CharStr.html
#[derive(Clone, Default)]
pub struct CharStrBuf {
    /// The underlying bytes vec.
    inner: Vec<u8>
}


/// # Creation and Conversion
///
impl CharStrBuf {
    /// Creates a new character string using the given vec without checking.
    unsafe fn from_vec_unsafe(vec: Vec<u8>) -> Self {
        CharStrBuf{inner: vec}
    }

    /// Creates a new character string using the given vec.
    ///
    /// Returns `Some(_)` if the vector was at most 255 long or `None`
    /// otherwise.
    pub fn from_vec(vec: Vec<u8>) -> Option<Self> {
        if vec.len() > 255 { None }
        else { Some(unsafe { Self::from_vec_unsafe(vec) }) }
    }

    /// Creates a new empty character string.
    pub fn new() -> Self {
        unsafe { Self::from_vec_unsafe(Vec::new()) }
    }

    /// Scans a new character string from master data.
    pub fn scan<S: Scanner>(scanner: &mut S) -> ScanResult<Self> {
        scanner.scan_charstr()
    }

    /// Trades the character string for its raw bytes vector.
    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }
}


/// # Manipulations.
///
impl CharStrBuf {
    /// Appends an octet to the end of the character string.
    ///
    /// The method will fail if there isn’t room for additional data.
    pub fn push(&mut self, ch: u8) -> Result<(), PushError> {
        if self.inner.len() >= 255 { Err(PushError) }
        else {
            self.inner.push(ch);
            Ok(())
        }
    }

    /// Extends the character string with the contents of a bytes slice.
    ///
    /// The method will fail if there isn’t room for adding the complete
    /// contents of the slice.
    pub fn extend_from_slice<B: AsRef<[u8]>>(&mut self, bytes: B)
                                             -> Result<(), PushError> {
        let bytes = bytes.as_ref();                               
        if self.inner.len() + bytes.len() > 255 { Err(PushError) }
        else {
            self.inner.extend_from_slice(bytes);
            Ok(())
        }
    }

    /// Extends the character string with the contents of a Rust string.
    ///
    /// The string must contain the master data representation of a
    /// character string either as a regular word without white-space or
    /// a single quoted entity. If the string cannot be converted, the
    /// function fails with the appropriate error. If adding the resulting
    /// data would exceed the length limit of the character string, the
    /// method fails with `FromStrError::LongString`.
    pub fn extend_from_str(&mut self, s: &str) -> Result<(), FromStrError> {
        match s.chars().next() {
            Some('"') => self.extend_from_quoted(s),
            Some(_) => self.extend_from_word(s),
            None => Ok(())
        }
    }

    /// Extends the character string with a quoted string.
    ///
    /// The string should still contain the opening `'"'`.
    fn extend_from_quoted(&mut self, s: &str) -> Result<(), FromStrError> {
        let mut chars = s.chars();
        chars.next(); // Skip '"'.
        while let Some(c) = chars.next() {
            match c {
                '"' => return Ok(()),
                '\\' => try!(self.push(try!(parse_escape(&mut chars)))),
                ' ' ... '[' | ']' ... '~' => {
                    try!(self.push(c as u8))
                }
                _ => return Err(FromStrError::IllegalCharacter)
            }
        }
        Err(FromStrError::UnexpectedEnd)
    }

    /// Extends the character string from a string containing a single word.
    ///
    /// Specifically, this fails if there is unescaped white space.
    fn extend_from_word(&mut self, s: &str) -> Result<(), FromStrError> {
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            match c {
                '\\' => try!(self.push(try!(parse_escape(&mut chars)))),
                '!' ... '[' | ']' ... '~' => {
                    try!(self.push(c as u8))
                }
                _ => return Err(FromStrError::IllegalCharacter)
            }
        }
        Ok(())
    }
}


//--- From

impl<'a> From<&'a CharStr> for CharStrBuf {
    fn from(c: &'a CharStr) -> Self {
        c.to_owned()
    }
}


//--- FromStr

impl str::FromStr for CharStrBuf {
    type Err = FromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut res = CharStrBuf::new();
        try!(res.extend_from_str(s));
        Ok(res)
    }
}


//--- Deref, DerefMut, Borrow, AsRef

impl ops::Deref for CharStrBuf {
    type Target = CharStr;

    fn deref(&self) -> &Self::Target {
        unsafe { CharStr::from_bytes_unsafe(&self.inner) }
    }
}

impl ops::DerefMut for CharStrBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { CharStr::from_bytes_mut_unsafe(&mut self.inner) }
    }
}

impl borrow::Borrow<CharStr> for CharStrBuf {
    fn borrow(&self) -> &CharStr {
        self
    }
}

impl borrow::Borrow<[u8]> for CharStrBuf {
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl AsRef<CharStr> for CharStrBuf {
    fn as_ref(&self) -> &CharStr {
        self
    }
}

impl AsRef<[u8]> for CharStrBuf {
    fn as_ref(&self) -> &[u8] {
        self
    }
}


//--- PartialEq, Eq

impl<C: AsRef<CharStr>> PartialEq<C> for CharStrBuf {
    fn eq(&self, other: &C) -> bool {
        self.deref().eq(other)
    }
}

impl Eq for CharStrBuf { }


//--- PartialOrd, Ord

impl<C: AsRef<CharStr>> PartialOrd<C> for CharStrBuf {
    fn partial_cmp(&self, other: &C) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other)
    }
}

impl Ord for CharStrBuf {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}


//--- Hash

impl hash::Hash for CharStrBuf {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


//--- Display, Debug

impl fmt::Display for CharStrBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(ops::Deref::deref(self), f)
    }
}

impl fmt::Debug for CharStrBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        try!("CharStrBuf(\"".fmt(f));
        try!(fmt::Display::fmt(self, f));
        "\")".fmt(f)
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

