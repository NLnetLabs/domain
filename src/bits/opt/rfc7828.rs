//! EDNS Options from RFC 7828

use ::bits::{Composer, ComposeResult, Parser, ParseResult};
use ::iana::OptionCode;
use super::{OptData, ParsedOptData};


//------------ TcpKeepalive --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TcpKeepalive(u16);

impl TcpKeepalive {
    pub fn new(timeout: u16) -> Self {
        TcpKeepalive(timeout)
    }

    pub fn timeout(&self) -> u16 {
        self.0
    }
}

impl OptData for TcpKeepalive {
    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        let target = target.as_mut();
        target.compose_u16(OptionCode::EdnsTcpKeepalive.into())?;
        target.compose_u16(2)?;
        target.compose_u16(self.0)
    }
}

impl<'a> ParsedOptData<'a> for TcpKeepalive {
    fn parse(code: OptionCode, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if code != OptionCode::EdnsTcpKeepalive {
            return Ok(None)
        }
        let timeout = parser.parse_u16()?;
        parser.exhausted()?;
        Ok(Some(Self::new(timeout)))
    }
}

