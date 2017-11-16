//! EDNS Options from RFC 7828

use bytes::BufMut;
use ::bits::compose::Composable;
use ::bits::parse::Parser;
use ::iana::OptionCode;
use super::{OptData, OptionParseError};


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


//--- Composable and OptData

impl Composable for TcpKeepalive {
    fn compose_len(&self) -> usize {
        2
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.0.compose(buf)
    }
}

impl OptData for TcpKeepalive {
    type ParseErr = OptionParseError;

    fn code(&self) -> OptionCode {
        OptionCode::EdnsTcpKeepalive
    }

    fn parse(code: OptionCode, len: usize, parser: &mut Parser)
             -> Result<Option<Self>, Self::ParseErr> {
        if code != OptionCode::EdnsTcpKeepalive {
            return Ok(None)
        }
        if len == 2 {
            Ok(Some(Self::new(parser.parse_u16()?)))
        }
        else {
            Err(OptionParseError::InvalidLength(len))
        }
    }
}

