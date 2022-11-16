//! EDNS Options from RFC 7828

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, OctetsBuilder, Parse, ParseError, Parser, ShortBuf
};
use super::CodeOptData;


//------------ TcpKeepalive --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TcpKeepalive(u16);

impl TcpKeepalive {
    pub fn new(timeout: u16) -> Self {
        TcpKeepalive(timeout)
    }

    pub fn push<Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>>(
        builder: &mut OptBuilder<Target>,
        timeout: u16
    ) -> Result<(), ShortBuf> {
        builder.push(&Self::new(timeout))
    }

    pub fn timeout(self) -> u16 {
        self.0
    }
}


//--- Parse and Compose

impl<'a, Octs: AsRef<[u8]>> Parse<'a, Octs> for TcpKeepalive {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        u16::parse(parser).map(Self::new)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        u16::skip(parser)
    }
}

impl Compose for TcpKeepalive {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        self.0.compose(target)
    }
}


//--- CodeOptData

impl CodeOptData for TcpKeepalive {
    const CODE: OptionCode = OptionCode::TcpKeepalive;
}

