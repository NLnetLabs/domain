//! EDNS Options form RFC 7873

use crate::iana::OptionCode;
use crate::message_builder::OptBuilder;
use crate::octets::{Compose, OctetsBuilder, ShortBuf};
use crate::parse::{Parse, ParseError, Parser};
use super::CodeOptData;


//------------ Cookie --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cookie([u8; 8]);

impl Cookie {
    pub fn new(cookie: [u8; 8]) -> Self {
        Cookie(cookie)
    }

    pub fn push<Target: OctetsBuilder>(
        builder: &mut OptBuilder<Target>,
        cookie: [u8; 8]
    ) -> Result<(), ShortBuf> {
        builder.push(&Self::new(cookie))
    }

    pub fn cookie(self) -> [u8; 8] {
        self.0
    }
}


//--- ParseAll and Compose

impl<Ref: AsRef<[u8]>> Parse<Ref> for Cookie {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let mut res = [0u8; 8];
        parser.parse_buf(&mut res[..])?;
        Ok(Self::new(res))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance(8)
    }
}


impl Compose for Cookie {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_slice(&self.0[..])
    }
}


//--- OptData

impl CodeOptData for Cookie {
    const CODE: OptionCode = OptionCode::Cookie;
}

