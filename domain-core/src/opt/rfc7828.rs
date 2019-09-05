//! EDNS Options from RFC 7828

use crate::compose::{Compose, ComposeTarget};
use crate::iana::OptionCode;
// XXX use crate::message_builder::OptBuilder;
use crate::parse::{ParseAll, Parser, ParseAllError};
use super::CodeOptData;


//------------ TcpKeepalive --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TcpKeepalive(u16);

impl TcpKeepalive {
    pub fn new(timeout: u16) -> Self {
        TcpKeepalive(timeout)
    }

    /* XXX
    pub fn push(builder: &mut OptBuilder, timeout: u16)
                -> Result<(), ShortBuf> {
        builder.push(&Self::new(timeout))
    }
    */

    pub fn timeout(self) -> u16 {
        self.0
    }
}


//--- ParseAll and Compose

impl<Octets: AsRef<[u8]>> ParseAll<Octets> for TcpKeepalive {
    type Err = ParseAllError;

    fn parse_all(
        parser: &mut Parser<Octets>,
        len: usize
    ) -> Result<Self, Self::Err> {
        u16::parse_all(parser, len).map(Self::new)
    }
}

impl Compose for TcpKeepalive {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        self.0.compose(target)
    }
}


//--- CodeOptData

impl CodeOptData for TcpKeepalive {
    const CODE: OptionCode = OptionCode::TcpKeepalive;
}

