//! EDNS Options from RFC 7871

use std::mem;
use std::net::IpAddr;
use ::bits::{Composer, ComposeResult, Parser, ParseError, ParseResult};
use ::iana::OptionCode;
use super::{OptData, ParsedOptData};


//------------ ClientSubnet --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClientSubnet {
    source_prefix_len: u8,
    scope_prefix_len: u8,
    addr: IpAddr,
}


impl ClientSubnet {
    pub fn new(source_prefix_len: u8, scope_prefix_len: u8, addr: IpAddr)
               -> ClientSubnet {
        ClientSubnet { source_prefix_len, scope_prefix_len, addr }
    }

    pub fn source_prefix_len(&self) -> u8 { self.source_prefix_len }
    pub fn scope_prefix_len(&self) -> u8 { self.scope_prefix_len }
    pub fn addr(&self) -> IpAddr { self.addr }
}

impl OptData for ClientSubnet {
    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        let target = target.as_mut();
        target.compose_u16(OptionCode::EdnsClientSubnet.into())?;
        match self.addr {
            IpAddr::V4(addr) => {
                target.compose_u16(4 + 4)?;
                target.compose_u16(1)?;
                target.compose_u8(self.source_prefix_len)?;
                target.compose_u8(self.scope_prefix_len)?;
                target.compose_bytes(&addr.octets())
            }
            IpAddr::V6(addr) => {
                target.compose_u16(16 + 4)?;
                target.compose_u16(2)?;
                target.compose_u8(self.source_prefix_len)?;
                target.compose_u8(self.scope_prefix_len)?;
                target.compose_bytes(&addr.octets())
            }
        }
    }
}

impl<'a> ParsedOptData<'a> for ClientSubnet {
    fn parse(code: OptionCode, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if code != OptionCode::EdnsClientSubnet {
            return Ok(None)
        }
        let family = parser.parse_u16()?;
        let source_prefix_len = parser.parse_u8()?;
        let scope_prefix_len = parser.parse_u8()?;
        let addr = match family {
            1 => {
                let bytes: &[u8; 4] = unsafe {
                    mem::transmute(parser.parse_bytes(4)?.as_ptr())
                };
                IpAddr::from(*bytes)
            }
            2 => {
                let bytes: &[u8; 16] = unsafe {
                    mem::transmute(parser.parse_bytes(16)?.as_ptr())
                };
                IpAddr::from(*bytes)
            }
            _ => return Err(ParseError::FormErr)
        };
        parser.exhausted()?;
        Ok(Some(ClientSubnet::new(source_prefix_len, scope_prefix_len, addr)))
    }
}

