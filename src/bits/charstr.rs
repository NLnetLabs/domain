//! Character strings.
//!
//! This module provides the `CharStr` type which represents DNS character
//! strings.

use std::borrow::{Borrow, Cow};
use std::error;
use std::fmt;
use std::ops::Deref;
use std::str;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, FromStrError, FromStrResult, ParseResult};
use super::parse::ParseBytes;


//------------ CharStr ------------------------------------------------------

/// A DNS character string.
///
/// In DNS wire format, character strings are length prefixed byte strings.
/// The length value is a byte itself, so these strings can never be longer
/// than 255 bytes. All values of this type adhere to this limitation.
///
/// This type behaves similar to a `Cow<[u8]>`. In particular, it derefs
/// into a bytes slice. It can be constructed from a bytes slice or a bytes
/// vec.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

    /// Creates a new borrowed character string from a bytes slice.
    ///
    /// If `s` is longer than 255 bytes, returns `Err(CharStrError)`.
    pub fn borrowed(s: &'a [u8]) -> Result<Self, CharStrError> {
        if s.len() > 256 { Err(CharStrError) }
        else { Ok(unsafe { CharStr::from_bytes(s) }) }
    }

    /// Creates a new owned character string from a bytes vec.
    ///
    /// If `s` is longer than 255 bytes, returns `Err(CharStrError)`.
    pub fn owned(s: Vec<u8>) -> Result<Self, CharStrError> {
        if s.len() > 256 { Err(CharStrError) }
        else { Ok(CharStr(Cow::Owned(s))) }
    }

    /// Returns a bytes slice of the data.
    pub fn as_bytes(&self) -> &[u8] {
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
    /// If the data is not already owned, clones the data.
    ///
    /// If there is no more room for additional characters, returns
    /// `Err(CharStrError)`.
    pub fn push(&mut self, ch: u8) -> Result<(), CharStrError> {
        if self.0.len() >= 255 { Err(CharStrError) }
        else {
            self.0.to_mut().push(ch);
            Ok(())
        }
    }

    /// Extends the character string with the contents of the bytes slice.
    ///
    /// If the data is not already owned, it will be cloned.
    ///
    /// If there is no more room for additional characters, returns
    /// `Err(CharStrError)`. Because of this, we can’t simply implement
    /// `Extend`.
    pub fn extend(&mut self, bytes: &[u8]) -> Result<(), CharStrError> {
        if self.0.len() + bytes.len() > 255 { Err(CharStrError) }
        else {
            self.0.to_mut().extend_from_slice(bytes);
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
                    '\\' => try!(self.push(try!(parse_escape(&mut chars)))),
                    ' ' ... '[' | ']' ... '~' => {
                        try!(self.push(c as u8))
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
    ///
    /// If successful, the result will be a borrowed character string.
    pub fn parse<P: ParseBytes<'a>>(parser: &mut P) -> ParseResult<Self> {
        let len = try!(parser.parse_u8()) as usize;
        parser.parse_bytes(len)
              .map(|bytes| unsafe { CharStr::from_bytes(bytes) })
    }

    /// Pushes the character string to the end of the target.
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

    /// Creates an owned character string from a Rust string.
    ///
    /// The string must be encoded in zonefile format. It must only consist
    /// of printable ASCII characters. Byte values outside this range must
    /// be escaped using a backslash followed by three decimal digits
    /// encoding the byte value. Any other sequence of a backslash and a
    /// printable ASCII character is treated as that other character.
    fn from_str(s: &str) -> FromStrResult<Self> {
        let mut res = CharStr::new();
        try!(res.extend_str(s));
        Ok(res)
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


//------------ CharStrError -------------------------------------------------

/// An error returned from creating a `CharStr`.
///
/// The only error that can happen is that the passed bytes values is too
/// long.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CharStrError;


//--- Error and Display

impl error::Error for CharStrError {
    fn description(&self) -> &str {
        "character string exceeds maximum size of 255 bytes"
    }
}

impl fmt::Display for CharStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;

        self.description().fmt(f)
    }
}


//--- From for FromStrError

impl From<CharStrError> for FromStrError {
    fn from(_: CharStrError) -> FromStrError {
        FromStrError::LongString
    }
}


//============ Internal Helpers =============================================

/// Parses the content of an escape sequence from the beginning of `chars`.
///
/// XXX Move to the zonefile modules once they exist.
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
        use bits::compose::ComposeBuf;
        
        let mut p = SliceParser::new(b"\x03foo\x03baroo");
        let r = CharStr::parse(&mut p).unwrap();
        assert_eq!(r.as_bytes(), &b"foo"[..]);
        let o = CharStr::parse(&mut p).unwrap();
        assert_eq!(o.as_bytes(), &b"bar"[..]);
        assert_eq!(p.left(), 2);

        let mut c = ComposeBuf::new(None, false);
        r.compose(&mut c).unwrap();
        o.compose(&mut c).unwrap();
        assert_eq!(c.finish(), b"\x03foo\x03bar");
    }

    #[test]
    fn push() {
        let mut o = CharStr::new();
        o.push(b'f').unwrap(); 
        o.push(b'o').unwrap(); 
        o.push(b'o').unwrap(); 
        assert_eq!(o.as_bytes(), b"foo");

        let s = [0u8; 254];
        let mut o = unsafe { CharStr::from_bytes(&s) };
        o.push(0).unwrap();
        assert_eq!(o.len(), 255);

        assert_eq!(o.push(0), Err(CharStrError));
    }

    #[test]
    fn extend() {
        let mut o = CharStr::borrowed(b"foo").unwrap();
        o.extend(b"bar").unwrap();
        assert_eq!(o.as_bytes(), b"foobar");
        assert!(o.clone().extend(&[0u8; 250]).is_err());
        o.extend(&[0u8; 249]).unwrap();
        assert_eq!(o.len(), 255);
    }

    #[test]
    fn from_str() {
        use std::str::FromStr;

        assert_eq!(CharStr::from_str("foo").unwrap().as_bytes(),
                   b"foo");
        assert_eq!(CharStr::from_str("f\\oo").unwrap().as_bytes(),
                   b"foo");
        assert_eq!(CharStr::from_str("foo\\112").unwrap().as_bytes(),
                   b"foo\x70");
        assert!(CharStr::from_str("ö").is_err());
        assert!(CharStr::from_str("\x06").is_err());
    }
}

