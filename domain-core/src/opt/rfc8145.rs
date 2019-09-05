//! EDNS Options from RFC 8145.

use bytes::{BigEndian, ByteOrder};
use crate::compose::{Compose, ComposeTarget};
use crate::iana::OptionCode;
// XXX use crate::message_builder::OptBuilder;
use crate::parse::{ParseAll, ParseAllError, Parser, ParseSource};
use super::CodeOptData;


//------------ KeyTag -------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyTag<Octets> {
    octets: Octets,
}

impl<Octets> KeyTag<Octets> {
    pub fn new(octets: Octets) -> Self {
        KeyTag { octets }
    }

    /* XXX
    pub fn push(builder: &mut OptBuilder, tags: &[u16])
                -> Result<(), ShortBuf> {
        let len = tags.len() * 2;
        assert!(len <= ::std::u16::MAX as usize);
        builder.build(OptionCode::KeyTag, len as u16, |buf| {
            for tag in tags {
                buf.compose(&tag)?
            }
            Ok(())
        })
    }
    */

    pub fn iter(&self) -> KeyTagIter
    where Octets: AsRef<[u8]> {
        KeyTagIter(self.octets.as_ref())
    }
}


//--- ParseAll and Compose

impl<Octets: ParseSource> ParseAll<Octets> for KeyTag<Octets> {
    type Err = ParseAllError;

    fn parse_all(
        parser: &mut Parser<Octets>,
        len: usize
    ) -> Result<Self, Self::Err> {
        if len % 2 == 1 {
            Err(ParseAllError::TrailingData)
        }
        else {
            Ok(Self::new(parser.parse_octets(len)?))
        }
    }
}

impl<Octets: AsRef<[u8]>> Compose for KeyTag<Octets> {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(self.octets.as_ref())
    }
}


//--- CodeOptData

impl<Octets> CodeOptData for KeyTag<Octets> {
    const CODE: OptionCode = OptionCode::KeyTag;
}


//--- IntoIterator

impl<'a, Octets: AsRef<[u8]>> IntoIterator for &'a KeyTag<Octets> {
    type Item = u16;
    type IntoIter = KeyTagIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ KeyTagIter ----------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct KeyTagIter<'a>(&'a [u8]);

impl<'a> Iterator for KeyTagIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < 2 {
            None
        }
        else {
            let (item, tail) = self.0.split_at(2);
            self.0 = tail;
            Some(BigEndian::read_u16(item))
        }
    }
}

