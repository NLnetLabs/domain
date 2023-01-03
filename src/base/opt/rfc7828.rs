//! EDNS Options from RFC 7828

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, Composer, Parse, ParseError, Parser,
};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;


//------------ TcpKeepalive --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TcpKeepalive(u16);

impl TcpKeepalive {
    pub fn new(timeout: u16) -> Self {
        TcpKeepalive(timeout)
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

//--- OptData

impl OptData for TcpKeepalive {
    fn code(&self) -> OptionCode {
        OptionCode::TcpKeepalive
    }
}

impl<'a, Octs: AsRef<[u8]>> ParseOptData<'a, Octs> for TcpKeepalive {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::TcpKeepalive {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeOptData for TcpKeepalive {
    fn compose_len(&self) -> u16 {
        u16::COMPOSE_LEN
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.0.compose(target)
    }
}


//------------ OptBuilder ----------------------------------------------------

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn tcp_keepalive(
        &mut self, timeout: u16
    ) -> Result<(), Target::AppendError> {
        self.push(&TcpKeepalive::new(timeout))
    }
}

