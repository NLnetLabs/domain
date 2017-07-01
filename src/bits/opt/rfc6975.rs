//! EDNS Options from RFC 6975.

use std::{ops, slice};
use ::bits::{Composer, ComposeResult, Parser, ParseResult};
use ::iana::{OptionCode, SecAlg};
use super::{OptData, ParsedOptData};



//------------ SecAlgs -------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecAlgs<B: AsRef<[u8]>>(B);

impl<B: AsRef<[u8]>> SecAlgs<B> {
    pub fn iter(&self) -> SecAlgsIter {
        SecAlgsIter(self.0.as_ref().iter())
    }

    fn compose<C: AsMut<Composer>>(&self, mut target: C, code: OptionCode)
                                   -> ComposeResult<()> {
        assert!(self.0.as_ref().len() <= ::std::u16::MAX as usize);
        target.as_mut().compose_u16(code.into())?;
        target.as_mut().compose_u16(self.0.as_ref().len() as u16)?;
        target.as_mut().compose_bytes(self.0.as_ref())
    }
}

impl<'a> SecAlgs<&'a [u8]> {
    fn parse<F, T>(wanted: OptionCode, code: OptionCode,
                   parser: &mut Parser<'a>,
                   wrap: F) -> ParseResult<Option<T>>
             where F: FnOnce(Self) -> T {
        if wanted == code {
            parser.parse_remaining().map(|bytes| Some(wrap(SecAlgs(bytes))))
        }
        else {
            Ok(None)
        }
    }
}

impl SecAlgs<Vec<u8>> {
    pub fn push(&mut self, alg: SecAlg) {
        self.0.push(alg.into())
    }
}


//------------ SecAlgsIter ---------------------------------------------------

pub struct SecAlgsIter<'a>(slice::Iter<'a, u8>);

impl<'a> Iterator for SecAlgsIter<'a> {
    type Item = SecAlg;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|x| SecAlg::from_int(*x))
    }
}


//------------ A Macro to Make the Three Option ------------------------------

macro_rules! option_type {
    ( $name:ident ) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name<B: AsRef<[u8]>>(SecAlgs<B>);

        impl<B: AsRef<[u8]>> $name<B> {
            pub fn new(data: B) -> Self {
                $name(SecAlgs(data))
            }
        }

        impl<B: AsRef<[u8]>> ops::Deref for $name<B> {
            type Target = SecAlgs<B>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<B: AsRef<[u8]>> ops::DerefMut for $name<B> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<B: AsRef<[u8]>> AsRef<SecAlgs<B>> for $name<B> {
            fn as_ref(&self) -> &SecAlgs<B> {
                &self.0
            }
        }

        impl<B: AsRef<[u8]>> AsMut<SecAlgs<B>> for $name<B> {
            fn as_mut(&mut self) -> &mut SecAlgs<B> {
                &mut self.0
            }
        }

        impl<B: AsRef<[u8]>> OptData for $name<B> {
            fn compose<C: AsMut<Composer>>(&self, target: C)
                                           -> ComposeResult<()> {
                self.0.compose(target, OptionCode::$name)
            }
        }

        impl<'a> ParsedOptData<'a> for $name<&'a [u8]> {
            fn parse(code: OptionCode, parser: &mut Parser<'a>)
                     -> ParseResult<Option<Self>> {
                SecAlgs::parse(OptionCode::$name, code, parser, $name)
            }
        }
    }
}


//------------ Dau -----------------------------------------------------------

option_type!(Dau);


//------------ Dhu -----------------------------------------------------------

option_type!(Dhu);


//------------ N3u -----------------------------------------------------------

option_type!(N3u);

