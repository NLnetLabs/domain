//! EDNS Options form RFC 7873

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, OctetsBuilder, Parse, ParseError, Parser, ShortBuf
};
use super::CodeOptData;


//------------ Cookie --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cookie([u8; 8]);

impl Cookie {
    pub fn new(cookie: [u8; 8]) -> Self {
        Cookie(cookie)
    }

    pub fn push<Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>>(
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

impl<'a, Octs: AsRef<[u8]>> Parse<'a, Octs> for Cookie {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let mut res = [0u8; 8];
        parser.parse_buf(&mut res[..])?;
        Ok(Self::new(res))
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance(8).map_err(Into::into)
    }
}


impl Compose for Cookie {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
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

