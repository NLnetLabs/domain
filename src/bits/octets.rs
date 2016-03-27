//! Arbitrary bytes data.

use std::borrow::Borrow;
use std::fmt::{self, Debug};
use std::ops::Deref;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
use super::parse::{ParseBytes, SliceParser};

//------------ Octets --------------------------------------------------------

/// A trait common to all bytes types.
pub trait Octets: Deref<Target=[u8]> + Sized + Clone + Debug {
    fn parser(&self) -> SliceParser;
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()>;
}


//------------ OctetsRef -----------------------------------------------------

/// A bytes reference.
#[derive(Clone, Debug)]
pub struct OctetsRef<'a> {
    inner: &'a [u8]
}

impl<'a> OctetsRef<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        OctetsRef { inner: bytes }
    }

    pub fn to_owned(&self) -> OwnedOctets {
        OwnedOctets::from_bytes(self.inner)
    }

    pub fn parse<P: ParseBytes<'a>>(parser: &mut P, len: usize)
                                    -> ParseResult<Self> {
        Ok(OctetsRef { inner: try!(parser.parse_bytes(len)) })
    }
}


//--- Octets

impl<'a> Octets for OctetsRef<'a> {
    fn parser(&self) -> SliceParser {
        SliceParser::new(self.inner)
    }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        target.push_bytes(self.inner)
    }
}


//--- Deref, Borrow, AsRef

impl<'a> Deref for OctetsRef<'a> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.inner
    }
}

impl<'a> Borrow<[u8]> for OctetsRef<'a> {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl<'a> AsRef<[u8]> for OctetsRef<'a> {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}


//--- Display

impl<'a> fmt::Display for OctetsRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &ch in self.inner.iter() {
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

//------------ OwnedOctets ---------------------------------------------------

/// An owned bytes.
#[derive(Clone, Debug)]
pub struct OwnedOctets {
    inner: Vec<u8>
}

impl OwnedOctets {
    pub fn new() -> Self {
        OwnedOctets { inner: Vec::new() }
    }

    pub fn from_bytes(slice: &[u8]) -> Self {
        OwnedOctets { inner: Vec::from(slice) }
    }

    pub fn parse<'a, P>(p: &mut P, len: usize) -> ParseResult<Self>
                 where P: ParseBytes<'a> {
        Ok(OwnedOctets::from_bytes(try!(p.parse_bytes(len))))
    }
}


//--- Octets

impl Octets for OwnedOctets {
    fn parser(&self) -> SliceParser {
        SliceParser::new(&self.inner)
    }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        target.push_bytes(&self.inner)
    }
}


//--- Deref, Borrow, AsRef

impl Deref for OwnedOctets {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.inner
    }
}

impl Borrow<[u8]> for OwnedOctets {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl AsRef<[u8]> for OwnedOctets {
    fn as_ref(&self) -> &[u8] {
        self.deref()
    }
}


//--- Display

impl fmt::Display for OwnedOctets {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&OctetsRef::from_bytes(&self.inner), f)
    }
}

