//! EDNS Options from RFC 7828

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, Composer, Parse, ParseError, Parser, ShortBuf
};
use super::{CodeOptData, ComposeOptData};
use octseq::builder::OctetsBuilder;


//------------ TcpKeepalive --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TcpKeepalive(u16);

impl TcpKeepalive {
    pub fn new(timeout: u16) -> Self {
        TcpKeepalive(timeout)
    }

    pub fn push<Target: Composer>(
        builder: &mut OptBuilder<Target>,
        timeout: u16
    ) -> Result<(), ShortBuf> {
        builder.push(&Self::new(timeout))
    }

    pub fn timeout(self) -> u16 {
        self.0
    }
}

//--- Parse

impl<'a, Octs: AsRef<[u8]>> Parse<'a, Octs> for TcpKeepalive {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        u16::parse(parser).map(Self::new)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        u16::skip(parser)
    }
}

//--- CodeOptData

impl CodeOptData for TcpKeepalive {
    const CODE: OptionCode = OptionCode::TcpKeepalive;
}

impl ComposeOptData for TcpKeepalive {
    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.0.compose(target)
    }
}

