//! Character strings.

use std::borrow;
use std::error;
use std::fmt;
use std::mem;
use std::ops::{self, Deref};
use std::str;
use ::master::{Scanner, ScanResult};
use super::{Composer, ComposeResult, Parser, ParseResult};


//------------ CharStr -------------------------------------------------------

#[derive(Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CharStr {
    inner: [u8]
}


/// Creation and Conversion
///
impl CharStr {
    unsafe fn from_bytes_unsafe(bytes: &[u8]) -> &Self {
        mem::transmute(bytes)
    }

    unsafe fn from_bytes_mut_unsafe(bytes: &mut [u8]) -> &mut Self {
        mem::transmute(bytes)
    }

    /// Creates a new character string from the bytes slice if it is valid.
    pub fn from_bytes(bytes: &[u8]) -> Option<&Self> {
        if bytes.len() > 255 { None }
        else { Some(unsafe { Self::from_bytes_unsafe(bytes) })}
    }

    /// Returns a bytes slices of the data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Returns an owned version of the character string.
    pub fn to_owned(&self) -> CharStrBuf {
        unsafe { CharStrBuf::from_vec_unsafe(self.inner.into()) }
    }
}


/// Parsing and Composing
///
impl CharStr {
    /// Parses a character string.
    pub fn parse<'a>(parser: &mut Parser<'a>) -> ParseResult<&'a Self> {
        let len = try!(parser.parse_u8()) as usize;
        parser.parse_bytes(len)
              .map(|bytes| unsafe { CharStr::from_bytes_unsafe(bytes) })
    }

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

#[derive(Clone, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CharStrBuf {
    inner: Vec<u8>
}


/// # Creation and Conversion
///
impl CharStrBuf {
    /// Creates a new character string using the given vec without checking.
    unsafe fn from_vec_unsafe(vec: Vec<u8>) -> Self {
        CharStrBuf{inner: vec}
    }

    /// Creates a new character string using the given vec if it is valid.
    pub fn from_vec(vec: Vec<u8>) -> Option<Self> {
        if vec.len() > 255 { None }
        else { Some(unsafe { Self::from_vec_unsafe(vec) }) }
    }

    /// Creates a new empty character string.
    pub fn new() -> Self {
        unsafe { Self::from_vec_unsafe(Vec::new()) }
    }

    pub fn scan<S: Scanner>(scanner: &mut S) -> ScanResult<Self> {
        scanner.scan_charstr()
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }
}


/// # Manipulations.
///
impl CharStrBuf {
    pub fn push(&mut self, ch: u8) -> Result<(), PushError> {
        if self.inner.len() >= 255 { Err(PushError) }
        else {
            self.inner.push(ch);
            Ok(())
        }
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8])
                             -> Result<(), PushError> {
        if self.inner.len() + bytes.len() > 255 { Err(PushError) }
        else {
            self.inner.extend_from_slice(bytes);
            Ok(())
        }
    }

    pub fn extend_from_str(&mut self, s: &str) -> Result<(), FromStrError> {
        match s.chars().next() {
            Some('"') => self.extend_from_quoted(s),
            Some(_) => self.extend_from_word(s),
            None => Ok(())
        }
    }

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


//--- Display, Debug

impl fmt::Display for CharStrBuf {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self.deref(), f)
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

impl From<PushError> for FromStrError {
    fn from(_: PushError) -> FromStrError {
        FromStrError::LongString
    }
}

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

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        error::Error::description(self).fmt(f)
    }
}


//------------ PushError -----------------------------------------------------

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



