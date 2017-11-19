//! EDNS Options from RFC 6975.

use std::slice;
use bytes::{BufMut, Bytes};
use ::bits::compose::Composable;
use ::bits::error::ShortBuf;
use ::bits::message_builder::OptBuilder;
use ::bits::parse::Parser;
use ::iana::{OptionCode, SecAlg};
use super::OptData;


//------------ Dau, Dhu, N3u -------------------------------------------------

macro_rules! option_type {
    ( $name:ident ) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name {
            bytes: Bytes,
        }

        impl $name {
            pub fn from_bytes(bytes: Bytes) -> Self {
                $name { bytes }
            }

            pub fn iter(&self) -> SecAlgsIter {
                SecAlgsIter::new(self.bytes.as_ref())
            }

            pub fn push(builder: &mut OptBuilder, algs: &[SecAlg])
                        -> Result<(), ShortBuf> {
                assert!(algs.len() <= ::std::u16::MAX as usize);
                builder.build(OptionCode::$name, algs.len() as u16, |buf| {
                    for alg in algs {
                        buf.compose(&alg.to_int())?
                    }
                    Ok(())
                })
            }
        }

        //--- Composable and OptData

        impl Composable for $name {
            fn compose_len(&self) -> usize {
                self.bytes.len()
            }

            fn compose<B: BufMut>(&self, buf: &mut B) {
                buf.put_slice(self.bytes.as_ref())
            }
        }
        
        impl OptData for $name {
            type ParseErr = ShortBuf;

            fn code(&self) -> OptionCode {
                OptionCode::$name
            }

            fn parse(code: OptionCode, len: usize, parser: &mut Parser)
                     -> Result<Option<Self>, Self::ParseErr> {
                if code != OptionCode::$name {
                    return Ok(None)
                }
                parser.parse_bytes(len)
                       .map(|bytes| Some(Self::from_bytes(bytes)))
            }
        }

        
        //--- IntoIter

        impl<'a> IntoIterator for &'a $name {
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
