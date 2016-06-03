//! Arbitrary bytes data.
//!
//! This module defines the type `Octets` for an arbitrary sequence of bytes.

use std::borrow::{Borrow, Cow};
use std::fmt;
use std::ops::Deref;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
use super::parse::ParseBytes;


//------------ Octets --------------------------------------------------------

/// Arbitrary bytes data.
///
/// This type can be used to refer an arbitrary sequence of bytes in DNS data.
/// Such a sequence is often used by record data definitions and cover the
/// remainder of the record data. Under the hood, this type is actually a
/// `Cow<[u8]>` and derefs into one, giving you all of `Cow`’s methods and,
/// transitively, all of bytes slice’s methods.
///
/// # Note
///
/// While we could have used a `Cow<[u8]>` directly, having a separate type
/// will come in handy once we do all the zonefile stuff where we will have
/// to parse from the format employed for binary data in zonefiles and
/// assemble these formats. We might later decide to actually split this
/// type up for the different formats.
#[derive(Clone, Debug, PartialEq)]
pub struct Octets<'a>(Cow<'a, [u8]>);

/// # Construction
///
impl<'a> Octets<'a> {
    /// Creates an octets value borrowing the bytes slice `bytes`.
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Octets(Cow::Borrowed(bytes))
    }

    /// Creates an owned octets value using the given bytes vector.
    pub fn from_vec(vec: Vec<u8>) -> Self {
        Octets(Cow::Owned(vec))
    }

    /// Creates an owned octets value by cloning the bytes slice.
    pub fn clone_bytes(bytes: &[u8]) -> Self {
        Octets::from_vec(bytes.to_owned())
    }
}

/// # Parsing and Composing
///
impl<'a> Octets<'a> {
    /// Parses `len` bytes of data as an octets value.
    ///
    /// This uses `parser.parse_octets()`. For most parsers the result will
    /// be an owned variant but a specific parser is free to return owned
    /// data.
    pub fn parse<P: ParseBytes<'a>>(parser: &mut P, len: usize)
                                    -> ParseResult<Self> {
        parser.parse_octets(len)
    }

    /// Pushes the content to the end of the compose target.
    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        target.push_bytes(self)
    }
}


//--- Deref, Borrow, AsRef

impl<'a> Deref for Octets<'a> {
    type Target = Cow<'a, [u8]>;

    fn deref(&self) -> &Cow<'a, [u8]> {
        &self.0
    }
}

impl<'a> Borrow<Cow<'a, [u8]>> for Octets<'a> {
    fn borrow(&self) -> &Cow<'a, [u8]> {
        self
    }
}

impl<'a> Borrow<[u8]> for Octets<'a> {
    fn borrow(&self) -> &[u8] {
        self
    }
}

impl<'a> AsRef<Cow<'a, [u8]>> for Octets<'a> {
    fn as_ref(&self) -> &Cow<'a, [u8]> {
        self
    }
}

impl<'a> AsRef<[u8]> for Octets<'a> {
    fn as_ref(&self) -> &[u8] {
        self
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


