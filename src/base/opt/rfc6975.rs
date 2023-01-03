//! EDNS Options from RFC 6975.

use super::super::iana::{OptionCode, SecAlg};
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Composer, Octets, Parse, ParseError, Parser,
};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use core::slice;


//------------ Dau, Dhu, N3u -------------------------------------------------

macro_rules! option_type {
    ( $name:ident, $fn:ident ) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name<Octs> {
            octets: Octs,
        }

        impl<Octs> $name<Octs> {
            pub fn from_octets(octets: Octs) -> Self {
                $name { octets }
            }

            pub fn iter(&self) -> SecAlgsIter
            where Octs: AsRef<[u8]> {
                SecAlgsIter::new(self.octets.as_ref())
            }
        }

        //--- Parse

        impl<'a, Octs: Octets> Parse<'a, Octs> for $name<Octs::Range<'a>> {
            fn parse(
                parser: &mut Parser<'a, Octs>
            ) -> Result<Self, ParseError> {
                let len = parser.remaining();
                parser.parse_octets(len).map(
                    Self::from_octets
                ).map_err(Into::into)
            }

            fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
                parser.advance_to_end();
                Ok(())
            }
        }

        //--- CodeOptData and ComposeOptData
        
        impl<Octs> OptData for $name<Octs> {
            fn code(&self) -> OptionCode {
                OptionCode::$name
            }
        }

        impl<'a, Octs> ParseOptData<'a, Octs> for $name<Octs::Range<'a>>
        where Octs: Octets {
            fn parse_option(
                code: OptionCode,
                parser: &mut Parser<'a, Octs>,
            ) -> Result<Option<Self>, ParseError> {
                if code == OptionCode::$name {
                    Self::parse(parser).map(Some)
                }
                else {
                    Ok(None)
                }
            }
        }

        impl<Octs: AsRef<[u8]>> ComposeOptData for $name<Octs> {
            fn compose_len(&self) -> u16 {
                self.octets.as_ref().len().try_into().expect("long option data")
            }

            fn compose_option<Target: OctetsBuilder + ?Sized>(
                &self, target: &mut Target
            ) -> Result<(), Target::AppendError> {
                target.append_slice(self.octets.as_ref())
            }
        }

        
        //--- IntoIter

        impl<'a, Octs: AsRef<[u8]>> IntoIterator for &'a $name<Octs> {
            type Item = SecAlg;
            type IntoIter = SecAlgsIter<'a>;

            fn into_iter(self) -> Self::IntoIter {
                self.iter()
            }
        }


        //------------ OptBuilder --------------------------------------------

        impl<'a, Target: Composer> OptBuilder<'a, Target> {
            pub fn $fn(
                &mut self, octets: &impl AsRef<[u8]>
            ) -> Result<(), Target::AppendError> {
                self.push(&$name::from_octets(octets.as_ref()))
            }
        }
    }
}

option_type!(Dau, dau);
option_type!(Dhu, dhu);
option_type!(N3u, n3u);


//------------ SecAlgsIter ---------------------------------------------------

pub struct SecAlgsIter<'a>(slice::Iter<'a, u8>);

impl<'a> SecAlgsIter<'a> {
    fn new(slice: &'a [u8]) -> Self {
        SecAlgsIter(slice.iter())
    }
}

impl<'a> Iterator for SecAlgsIter<'a> {
    type Item = SecAlg;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|x| SecAlg::from_int(*x))
    }
}

