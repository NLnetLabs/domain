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

use std::borrow::{Borrow, Cow};
use std::cmp;
use std::fmt;
use std::hash;
use std::ops::Deref;
use std::str;
use super::compose::ComposeBytes;
use super::error::{ComposeError, ComposeResult, FromStrError, FromStrResult,
                   ParseResult};
use super::parse::ParseBytes;


//------------ CharStr ------------------------------------------------------

/// A type for DNS character strings.
#[derive(Clone, Debug)]
pub struct CharStr<'a>(Cow<'a, [u8]>);

/// # Creation and Conversion
/// 
impl<'a> CharStr<'a> {
    /// Creates a character string reference from a bytes slice.
    ///
    /// This does not check that the slice is not too long and therefore is
    /// unsafe.
    unsafe fn from_bytes(bytes: &'a [u8]) -> Self {
        CharStr(Cow::Borrowed(bytes))
    }

    /// Creates a new empty owned character string.
    pub fn new() -> Self {
        CharStr(Cow::Owned(Vec::new()))
    }

    /// Creates a new borrowed character string with `s`.
    ///
    /// If `s` is longer than 255 bytes, returns 
    /// `Err(ComposeError::SizeExceeded)`.
    ///
    /// XXX Maybe this should return an `Option<Self>` instead?
    pub fn borrowed(s: &'a [u8]) -> ComposeResult<Self> {
        if s.len() > 256 { Err(ComposeError::SizeExceeded) }
        else { Ok(unsafe { CharStr::from_bytes(s) }) }
    }

    /// Creates a new owned character string using `s`.
    ///
    /// If `s` is longer than 255 bytes, returns 
    /// `Err(ComposeError::SizeExceeded)`.
    ///
    /// XXX Maybe this should return an `Option<Self>` instead?
    pub fn owned(s: Vec<u8>) -> ComposeResult<Self> {
        if s.len() > 256 { Err(ComposeError::SizeExceeded) }
        else { Ok(CharStr(Cow::Owned(s))) }
    }

    /// Creates an owned character string from a Rust string.
    ///
    /// The string must be encoded in zonefile format. It must only consist
    /// of printable ASCII characters. Byte values outside this range must
    /// be escaped using a backslash followed by three decimal digits
    /// encoding the byte value. Any other sequence of a backslash and a
    /// printable ASCII character is treated as that other character.
    pub fn from_str(s: &str) -> FromStrResult<Self> {
        let mut res = CharStr::new();
        try!(res.extend_str(s));
        Ok(res)
    }

    /// Returns a bytes slice of the data.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Converts the reference into a bytes vector.
    pub fn into_owned(self) -> Vec<u8> {
        self.0.into_owned()
    }

}


/// # Manipulations.
///
impl<'a> CharStr<'a> {
    /// Appends the byte `ch` to the end of the character string.
    ///
    /// If there is no more room for additional characters, returns
    /// `Err(ComposeError::SizeExceeded)`.
    pub fn push(&mut self, ch: u8) -> ComposeResult<()> {
        if self.0.len() >= 255 { Err(ComposeError::SizeExceeded) }
        else {
            self.0.to_mut().push(ch);
            Ok(())
        }
    }

    /// Extends the character string with a Rust string.
    ///
    /// The string must be in zonefile encoding.
    pub fn extend_str(&mut self, s: &str) -> FromStrResult<()> {
        let mut chars = s.chars();
        loop {
            match chars.next() {
                Some(c) => match c {
                    '\\' => try!(self.push(try!(parse_escape(&mut chars)))
                                     .map_err(|_| FromStrError::LongString)),
                    ' ' ... '[' | ']' ... '~' => {
                        try!(self.push(c as u8)
                             .map_err(|_| FromStrError::LongString))
                    }
                    _ => return Err(FromStrError::IllegalCharacter)
                },
                None => break
            }
        }
        Ok(())
    }
}


/// # Parsing and Composing
///
impl<'a> CharStr<'a> {
    /// Parses a character string reference.
    pub fn parse<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        let len = try!(parser.parse_u8()) as usize;
        parser.parse_bytes(len)
              .map(|bytes| unsafe { CharStr::from_bytes(bytes) })
    }

    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        assert!(self.0.len() < 256);
        try!(target.push_u8(self.0.len() as u8));
        try!(target.push_bytes(&self.0));
        Ok(())
    }
}


//--- FromStr

impl<'a> str::FromStr for CharStr<'a> {
    type Err = FromStrError;
    fn from_str(s: &str) -> FromStrResult<Self> {
        CharStr::from_str(s)
    }
}


//--- Deref, Borrow, AsRef

impl<'a> Deref for CharStr<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<'a> Borrow<[u8]> for CharStr<'a> {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl<'a> AsRef<[u8]> for CharStr<'a> {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}


//--- PartialEq, Eq

impl<'a, T: AsRef<[u8]>> PartialEq<T> for CharStr<'a> {
    fn eq(&self, other: &T) -> bool {
        self.deref().eq(other.as_ref())
    }
}

impl<'a> Eq for CharStr<'a> { }


//--- PartialOrd, Ord

impl<'a, T: AsRef<[u8]>> PartialOrd<T> for CharStr<'a> {
    fn partial_cmp(&self, other: &T) -> Option<cmp::Ordering> {
        self.deref().partial_cmp(other.as_ref())
    }
}

impl<'a> Ord for CharStr<'a> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.deref().cmp(other.deref())
    }
}


//--- Hash

impl<'a> hash::Hash for CharStr<'a> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}


//--- Display

impl<'a> fmt::Display for CharStr<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.iter() {
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
        let r = CharStr::parse(&mut p).unwrap();
        assert_eq!(r.as_slice(), &b"foo"[..]);
        let o = CharStr::parse(&mut p).unwrap();
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

        let mut o = CharStr::new();
        o.push(b'f').unwrap(); 
        o.push(b'o').unwrap(); 
        o.push(b'o').unwrap(); 
        assert_eq!(o.as_slice(), b"foo");

        let s = [0u8; 255];
        let mut o = unsafe { CharStr::from_bytes(&s) };

        assert_eq!(o.push(0), Err(ComposeError::SizeExceeded));
    }

    #[test]
    fn from_str() {
        assert_eq!(CharStr::from_str("foo").unwrap().as_slice(),
                   b"foo");
        assert_eq!(CharStr::from_str("f\\oo").unwrap().as_slice(),
                   b"foo");
        assert_eq!(CharStr::from_str("foo\\112").unwrap().as_slice(),
                   b"foo\x70");
        assert!(CharStr::from_str("ö").is_err());
        assert!(CharStr::from_str("\x06").is_err());
    }
}

