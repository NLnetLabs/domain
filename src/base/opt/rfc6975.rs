//! EDNS Options from RFC 6975.

use super::super::iana::{OptionCode, SecAlg};
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, Composer, Octets, Parse, ParseError, Parser,
    ShortBuf
};
use super::{CodeOptData, ComposeOptData};
use octseq::builder::OctetsBuilder;
use core::slice;


//------------ Dau, Dhu, N3u -------------------------------------------------

macro_rules! option_type {
    ( $name:ident ) => {
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

        impl $name<()> {
            pub fn push<Target: Composer>(
                builder: &mut OptBuilder<Target>,
                algs: &[SecAlg]
            ) -> Result<(), ShortBuf> {
                assert!(algs.len() <= core::u16::MAX as usize);
                builder.push_raw_option(OptionCode::$name, |target| {
                    for alg in algs {
                        alg.to_int().compose(target)?;
                    }
                    Ok(())
                })
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
        
        impl<Octs> CodeOptData for $name<Octs> {
            const CODE: OptionCode = OptionCode::$name;
        }

        impl<Octs: AsRef<[u8]>> ComposeOptData for $name<Octs> {
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
    }
}

option_type!(Dau);
option_type!(Dhu);
option_type!(N3u);


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
