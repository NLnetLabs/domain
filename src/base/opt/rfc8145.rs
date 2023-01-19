//! EDNS Options from RFC 8145.

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Compose, Composer, FormError, ParseError};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::octets::Octets;
use octseq::parse::Parser;
use core::{borrow, fmt, hash};
use core::cmp::Ordering;
use core::convert::TryInto;


//------------ KeyTag -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct KeyTag<Octs> {
    octets: Octs,
}

impl<Octs> KeyTag<Octs> {
    pub fn new(octets: Octs) -> Self {
        KeyTag { octets }
    }

    pub fn as_octets(&self) -> &Octs {
        &self.octets
    }

    pub fn into_octets(self) -> Octs {
        self.octets
    }

    pub fn as_slice(&self) -> &[u8]
    where Octs: AsRef<[u8]> {
        self.octets.as_ref()
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8]
    where Octs: AsMut<[u8]> {
        self.octets.as_mut()
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

//--- AsRef, AsMut, Borrow, BorrowMut

impl<Octs: AsRef<[u8]>> AsRef<[u8]> for KeyTag<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs: AsMut<[u8]>> AsMut<[u8]> for KeyTag<Octs> {
    fn as_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
    }
}

impl<Octs: AsRef<[u8]>> borrow::Borrow<[u8]> for KeyTag<Octs> {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs: AsMut<[u8]> + AsRef<[u8]>> borrow::BorrowMut<[u8]> for KeyTag<Octs> {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.as_slice_mut()
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


//--- Display

impl<Octets: AsRef<[u8]>> fmt::Display  for KeyTag<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut first = true;
        
        for v in self.octets.as_ref() {
            if first {
                write!(f, "{:X}", ((*v as u16) << 8) | *v as u16)?;
                first = false;
            } else {
                write!(f, ", {:X}", ((*v as u16) << 8) | *v as u16)?;
            }
        }

        Ok(())
    }
}

//--- PartialEq and Eq

impl<Octs: AsRef<[u8]>, Other: AsRef<[u8]>> PartialEq<Other> for KeyTag<Octs> {
    fn eq(&self, other: &Other) -> bool {
        self.as_slice().eq(other.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Eq for KeyTag<Octs> { }

//--- PartialOrd and Ord

impl<Octs: AsRef<[u8]>, Other: AsRef<[u8]>> PartialOrd<Other> for KeyTag<Octs> {
    fn partial_cmp(&self, other: &Other) -> Option<Ordering> {
        self.as_slice().partial_cmp(other.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Ord for KeyTag<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_slice().cmp(other.as_slice())
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for KeyTag<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state)
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

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use super::super::test::test_option_compose_parse;
    
    #[test]
    fn nsid_compose_parse() {
        test_option_compose_parse(
            &KeyTag::new("fooo"),
            |parser| KeyTag::parse(parser)
        );
    }
}

