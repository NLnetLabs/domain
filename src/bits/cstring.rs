//! Character strings.
//!
//! In DNS wire format, character strings are length prefixed byte strings.
//! The length value is a byte itself, so these strings can never be longer
//! than 255 bytes.
//!
//! This module defines the two types `CStringRef` and `OwnedCString` for
//! a character string slice and an owned character string, respectively.
//! They both deref into a bytes slice. The `CStringRef` type serves both
//! for the `Ref` and `Lazy` flavors.
//!
//! In addition, there is a `CString` trait for building composite data
//! structures generic over the various flavors.
//!
//! As a side node, the term `CString` for character string may be slightly
//! unfortunate since these things aren’t strings by Rust’s definition nor
//! do they have anything to do with C. However, they are called strings in
//! DNS terminology and `CharString` seemed both too long and even less
//! correct.

use std::borrow::Borrow;
use std::cmp;
use std::fmt;
use std::hash;
use std::ops::Deref;
use std::str;
use super::compose::ComposeBytes;
use super::error::{ComposeError, ComposeResult, FromStrError, FromStrResult,
                   ParseResult};
use super::parse::ParseBytes;


//------------ CString ------------------------------------------------------

/// A trait for types usable as DNS character strings.
pub trait CString: fmt::Display + Sized {

    /// Appends the character string to the end of a composed message.
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()>;
}


//------------ CStringRef ---------------------------------------------------

/// A reference to a DNS character string.
///
/// This type is used by the `Ref` and `Lazy` flavors. It derefs to a
/// regular bytes slice.
#[derive(Clone, Debug)]
pub struct CStringRef<'a> {
    /// The underlying bytes slice.
    inner: &'a [u8]
}


/// # Creation and Conversion
/// 
impl <'a> CStringRef<'a> {
    /// Creates a character string reference from a bytes slice.
    ///
    /// This does not check that the slice is not too long and therefore is
    /// unsafe.
    unsafe fn from_bytes(bytes: &'a [u8]) -> Self {
        CStringRef { inner: bytes }
    }

    /// Parses a character string reference.
    pub fn parse<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        let len = try!(parser.parse_u8()) as usize;
        parser.parse_bytes(len)
              .map(|bytes| unsafe {CStringRef::from_bytes(bytes) })
    }

    /// Returns a bytes slice of the data.
    pub fn as_slice(&self) -> &[u8] {
        self.inner
    }

    /// Converts the reference into an owned character string.
    pub fn to_owned(&self) -> OwnedCString {
        unsafe { OwnedCString::from_bytes(self.inner) }
    }

}


//--- CString

impl<'a> CString for CStringRef<'a> {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        assert!(self.inner.len() < 256);
        try!(target.push_u8(self.inner.len() as u8));
        try!(target.push_bytes(self.inner));
        Ok(())
    }
}


//--- Deref, Borrow, AsRef

impl<'a> Deref for CStringRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl<'a> Borrow<[u8]> for CStringRef<'a> {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl<'a> AsRef<[u8]> for CStringRef<'a> {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}


//--- PartialEq, Eq

impl<'a, T: AsRef<[u8]>> PartialEq<T> for CStringRef<'a> {
    fn eq(&self, other: &T) -> bool {
        self.deref().eq(other.as_ref())
    }
}

impl<'a> Eq for CStringRef<'a> { }


//--- PartialOrd, Ord

impl<'a, T: AsRef<[u8]>> PartialOrd<T> for CStringRef<'a> {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other.as_ref())
    }
}

impl<'a> Ord for CStringRef<'a> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}


//--- Hash

impl<'a> hash::Hash for CStringRef<'a> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


//--- Display

impl<'a> fmt::Display for CStringRef<'a> {
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


//------------ OwnedCString -------------------------------------------------

/// An owned DNS character string.
///
/// This type is used by the `Owned` flavor. It derefs into an ordinary bytes
/// slice.
#[derive(Clone, Debug)]
pub struct OwnedCString {
    /// The vector holding the data.
    inner: Vec<u8>
}


/// # Creation and Conversion.
///
impl OwnedCString {
    /// Creates an owned character string from a bytes slice.
    ///
    /// This method does not check that the slice isn’t too long and therefore
    /// is unsafe.
    unsafe fn from_bytes(bytes: &[u8]) -> Self {
        OwnedCString { inner: Vec::from(bytes) }
    }

    /// Creates a new empty owned character string.
    pub fn new() -> Self {
        OwnedCString { inner: Vec::new() }
    }

    /// Creates an owned character string from a Rust string.
    ///
    /// The string must be encoded in zonefile format. It must only consist
    /// of printable ASCII characters. Byte values outside this range must
    /// be escaped using a backslash followed by three decimal digits
    /// encoding the byte value. Any other sequence of a backslash and a
    /// printable ASCII character is treated as that other character.
    pub fn from_str(s: &str) -> FromStrResult<Self> {
        let mut res = OwnedCString::new();
        let mut chars = s.chars();
        loop {
            match chars.next() {
                Some(c) => {
                    match c {
                        '\\' => res.inner.push(try!(parse_escape(&mut chars))),
                        ' ' ... '[' | ']' ... '~' => {
                            res.inner.push(c as u8);
                        }
                        _ => return Err(FromStrError::IllegalCharacter)
                    }
                }
                None => break
            }
        }
        if res.len() > 255 { Err(FromStrError::LongString) }
        else { Ok(res) }
    }

    /// Parses a character string into an owned value.
    pub fn parse<'a, P: ParseBytes<'a>>(parser: &mut P)
                                        -> ParseResult<Self> {
        Ok(try!(CStringRef::parse(parser)).to_owned())
    }

    /// Returns a bytes slice of the character string’s data.
    pub fn as_slice(&self) -> &[u8] {
        self
    }
}


/// # Manipulations.
///
impl OwnedCString {
    /// Appends the byte `ch` to the end of the character string.
    ///
    /// If there is no more room for additional characters, returns
    /// `Err(ComposeError::SizeExceeded)`.
    pub fn push(&mut self, ch: u8) -> ComposeResult<()> {
        if self.inner.len() >= 255 { Err(ComposeError::SizeExceeded) }
        else {
            self.inner.push(ch);
            Ok(())
        }
    }
}


//--- CString

impl CString for OwnedCString {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        assert!(self.inner.len() < 256);
        try!(target.push_u8(self.inner.len() as u8));
        try!(target.push_bytes(&self.inner));
        Ok(())
    }
}


//--- FromStr

impl str::FromStr for OwnedCString {
    type Err = FromStrError;
    fn from_str(s: &str) -> FromStrResult<Self> {
        OwnedCString::from_str(s)
    }
}


//--- Deref, Borrow, AsRef

impl Deref for OwnedCString {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.inner.deref()
    }
}

impl Borrow<[u8]> for OwnedCString {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl AsRef<[u8]> for OwnedCString {
    fn as_ref(&self) -> &[u8] {
        self
    }
}


//--- PartialEq and Eq

impl<T: AsRef<[u8]>> PartialEq<T> for OwnedCString {
    fn eq(&self, other: &T) -> bool {
        self.deref().eq(other.as_ref())
    }
}

impl Eq for OwnedCString { }


//--- PartialOrd and Ord

impl<T: AsRef<[u8]>> PartialOrd<T> for OwnedCString {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other.as_ref())
    }
}

impl Ord for OwnedCString {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}


//--- Hash

impl hash::Hash for OwnedCString {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


//--- Display

impl fmt::Display for OwnedCString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe { CStringRef::from_bytes(&self.inner) }.fmt(f)
    }
}


//------------ Internal Helpers ---------------------------------------------

/// Parses the content of an escape sequence from the beginning of `chars`.
fn parse_escape(chars: &mut str::Chars) -> FromStrResult<u8> {
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

    #[test]
    fn parse_and_compose() {
        use bits::parse::{ParseBytes, SliceParser};
        use bits::compose::ComposeVec;
        
        let mut p = SliceParser::new(b"\x03foo\x03baroo");
        let r = CStringRef::parse(&mut p).unwrap();
        assert_eq!(r.as_slice(), &b"foo"[..]);
        let o = OwnedCString::parse(&mut p).unwrap();
        assert_eq!(o.as_slice(), &b"bar"[..]);
        assert_eq!(p.left(), 2);

        let mut c = ComposeVec::new(None, false);
        r.compose(&mut c).unwrap();
        o.compose(&mut c).unwrap();
        assert_eq!(c.finish(), b"\x03foo\x03bar");
    }

    #[test]
    fn push() {
        use bits::error::ComposeError;

        let mut o = OwnedCString::new();
        o.push(b'f').unwrap(); 
        o.push(b'o').unwrap(); 
        o.push(b'o').unwrap(); 
        assert_eq!(o.as_slice(), b"foo");

        let s = [0u8; 255];
        let mut o = unsafe { OwnedCString::from_bytes(&s) };

        assert_eq!(o.push(0), Err(ComposeError::SizeExceeded));
    }

    #[test]
    fn from_str() {
        assert_eq!(OwnedCString::from_str("foo").unwrap().as_slice(),
                   b"foo");
        assert_eq!(OwnedCString::from_str("f\\oo").unwrap().as_slice(),
                   b"foo");
        assert_eq!(OwnedCString::from_str("foo\\112").unwrap().as_slice(),
                   b"foo\x70");
        assert!(OwnedCString::from_str("ö").is_err());
        assert!(OwnedCString::from_str("\x06").is_err());
    }
}

