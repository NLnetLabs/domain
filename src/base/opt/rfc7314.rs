//! EDNS Options from RFC 7314

use core::fmt;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, OctetsBuilder, Parse, ParseError, Parser, ShortBuf
};
use super::CodeOptData;


//------------ Expire --------------------------------------------------------

// @TODO does this change influences more things below?
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Expire(u32);

impl Expire {
    pub fn new(expire: u32) -> Self {
        Expire(expire)
    }

    pub fn push<Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>>(
        builder: &mut OptBuilder<Target>,
        expire: u32
    ) -> Result<(), ShortBuf> {
        builder.push(&Self::new(expire))
    }

    pub fn expire(self) -> u32 {
        self.0
    }
}


//--- Parse and Compose

impl<Ref: AsRef<[u8]>> Parse<Ref> for Expire {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        u32::parse(parser).map(Self::new)
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        u32::skip(parser)
    }
}

impl Compose for Expire {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
       self.0.compose(target)
    }
}


//--- OptData

impl CodeOptData for Expire {
    const CODE: OptionCode = OptionCode::Expire;
}

