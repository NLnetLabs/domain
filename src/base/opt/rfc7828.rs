//! EDNS Options from RFC 7828

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Compose, Composer, Parse, ParseError};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::parse::Parser;


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

    pub fn parse<Octs: AsRef<[u8]>>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        u16::parse(parser).map(Self::new)
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

