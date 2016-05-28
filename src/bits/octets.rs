//! Arbitrary bytes data.

use std::borrow::{Borrow, Cow};
use std::fmt;
use std::ops::Deref;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
use super::parse::{ParseBytes, SliceParser};


//------------ Octets --------------------------------------------------------

/// Arbitrary bytes data.
#[derive(Clone, Debug, PartialEq)]
pub struct Octets<'a>(Cow<'a, [u8]>);

impl<'a> Octets<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Octets(Cow::Borrowed(bytes))
    }

    pub fn new() -> Self {
        Octets(Cow::Owned(Vec::new()))
    }

    pub fn into_owned(self) -> Vec<u8> {
        self.0.into_owned()
    }

    pub fn parse<P: ParseBytes<'a>>(parser: &mut P, len: usize)
                                    -> ParseResult<Self> {
        Ok(Octets::from_bytes(try!(parser.parse_bytes(len))))
    }

    pub fn parser(&self) -> SliceParser {
        SliceParser::new(self)
    }

    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        target.push_bytes(self)
    }
}


//--- Deref, Borrow, AsRef

impl<'a> Deref for Octets<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> Borrow<[u8]> for Octets<'a> {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl<'a> AsRef<[u8]> for Octets<'a> {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}


//--- Display

impl<'a> fmt::Display for Octets<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.0.iter() {
            if ch == b' ' || ch == b'\\' {
                try!(write!(f, "\\{}", ch as char));
            }
            else if ch < b' ' || ch >= 0x7F {
                try!(write!(f, "\\{:03}", ch));
            }
            else {
                try!(fmt::Display::fmt(&(ch as char), f));
            }
        }
        Ok(())
    }
} 


