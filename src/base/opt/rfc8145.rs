//! EDNS Options from RFC 8145.

use core::convert::TryInto;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, Composer, FormError, Octets, Parse, ParseError,
    Parser, ShortBuf
};
use super::{CodeOptData, ComposeOptData};
use octseq::builder::OctetsBuilder;


//------------ KeyTag -------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyTag<Octs> {
    octets: Octs,
}

impl<Octs> KeyTag<Octs> {
    pub fn new(octets: Octs) -> Self {
        KeyTag { octets }
    }

    pub fn push<Target: Composer>(
        builder: &mut OptBuilder<Target>,
        tags: &[u16]
    ) -> Result<(), ShortBuf> {
        let len = tags.len() * 2;
        assert!(len <= core::u16::MAX as usize);
        builder.push_raw_option(OptionCode::KeyTag, |target| {
            for tag in tags {
                tag.compose(target)?;
            }
            Ok(())
        })
    }

    pub fn iter(&self) -> KeyTagIter
    where Octs: AsRef<[u8]> {
        KeyTagIter(self.octets.as_ref())
    }
}


//--- ParseAll

impl<'a, Octs: Octets> Parse<'a, Octs> for KeyTag<Octs::Range<'a>> {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let len = parser.remaining();
        if len % 2 == 1 {
            Err(FormError::new("invalid keytag length").into())
        }
        else {
            Ok(Self::new(parser.parse_octets(len)?))
        }
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        if parser.remaining() % 2 == 1 {
            Err(FormError::new("invalid keytag length").into())
        }
        else {
            parser.advance_to_end();
            Ok(())
        }
    }
}


//--- CodeOptData and ComposeOptData

impl<Octs> CodeOptData for KeyTag<Octs> {
    const CODE: OptionCode = OptionCode::KeyTag;
}

impl<Octs: AsRef<[u8]>> ComposeOptData for KeyTag<Octs> {
    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.octets.as_ref())
    }
}


//--- IntoIterator

impl<'a, Octs: AsRef<[u8]>> IntoIterator for &'a KeyTag<Octs> {
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
            Some(u16::from_be_bytes(item.try_into().unwrap()))
        }
    }
}

