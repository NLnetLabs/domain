//! EDNS Options from RFC 8145.

use core::convert::TryInto;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, Composer, FormError, Octets, ParseError, Parser,
};
use super::{OptData, ComposeOptData, ParseOptData};
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

    pub fn iter(&self) -> KeyTagIter
    where Octs: AsRef<[u8]> {
        KeyTagIter(self.octets.as_ref())
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        let len = parser.remaining();
        if len % 2 == 1 {
            Err(FormError::new("invalid keytag length").into())
        }
        else {
            Ok(Self::new(parser.parse_octets(len)?))
        }
    }
}


//--- OptData

impl<Octs> OptData for KeyTag<Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::KeyTag
    }
}

impl<'a, Octs: Octets> ParseOptData<'a, Octs> for KeyTag<Octs::Range<'a>> {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::KeyTag {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeOptData for KeyTag<Octs> {
    fn compose_len(&self) -> u16 {
        self.octets.as_ref().len().try_into().expect("long option data")
    }

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


//------------ OptBuilder ----------------------------------------------------

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn key_tag(
        &mut self, tags: &impl AsRef<[u16]>
    ) -> Result<(), Target::AppendError> {
        self.push_raw_option(
            OptionCode::KeyTag,
            u16::try_from(
                tags.as_ref().len().checked_mul(2).expect("long option data")
            ).expect("long option data"),
            |target| {
                for tag in tags.as_ref() {
                    tag.compose(target)?;
                }
                Ok(())
            }
        )
    }
}

