//! EDNS Options from RFC 6975.

use core::slice;
use super::super::iana::{OptionCode, SecAlg};
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, OctetsBuilder, OctetsRef, Parse, ParseError, Parser, ShortBuf
};
use super::CodeOptData;


//------------ Dau, Dhu, N3u -------------------------------------------------

macro_rules! option_type {
    ( $name:ident ) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name<Octets> {
            octets: Octets,
        }

        impl<Octets> $name<Octets> {
            pub fn from_octets(octets: Octets) -> Self {
                $name { octets }
            }

            pub fn iter(&self) -> SecAlgsIter
            where Octets: AsRef<[u8]> {
                SecAlgsIter::new(self.octets.as_ref())
            }
        }

        impl $name<()> {
            pub fn push<Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>>(
                builder: &mut OptBuilder<Target>,
                algs: &[SecAlg]
            ) -> Result<(), ShortBuf> {
                assert!(algs.len() <= core::u16::MAX as usize);
                builder.push_raw_option(OptionCode::$name, |target| {
                    target.append_all(|target| {
                        for alg in algs {
                            alg.to_int().compose(target)?;
                        }
                        Ok(())
                    })
                })
            }
        }

        //--- Parse and Compose

        impl<Ref: OctetsRef> Parse<Ref> for $name<Ref::Range> {
            fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
                let len = parser.remaining();
                parser.parse_octets(len).map(Self::from_octets)
            }

            fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
                parser.advance_to_end();
                Ok(())
            }
        }

        impl<Octets: AsRef<[u8]>> Compose for $name<Octets> {
            fn compose<T: OctetsBuilder + AsMut<[u8]>>(
                &self,
                target: &mut T
            ) -> Result<(), ShortBuf> {
                target.append_slice(self.octets.as_ref())
            }
        }


        //--- CodeOptData
        
        impl<Octets> CodeOptData for $name<Octets> {
            const CODE: OptionCode = OptionCode::$name;
        }

        
        //--- IntoIter

        impl<'a, Octets: AsRef<[u8]>> IntoIterator for &'a $name<Octets> {
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
