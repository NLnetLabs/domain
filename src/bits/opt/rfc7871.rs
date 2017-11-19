//! EDNS Options from RFC 7871

use std::mem;
use std::net::IpAddr;
use bytes::BufMut;
use ::bits::compose::Composable;
use ::bits::error::ShortBuf;
use ::bits::message_builder::OptBuilder;
use ::bits::parse::Parser;
use ::iana::OptionCode;
use super::OptData;


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

    pub fn push(builder: &mut OptBuilder, source_prefix_len: u8,
                scope_prefix_len: u8, addr: IpAddr) -> Result<(), ShortBuf> {
        builder.push(&Self::new(source_prefix_len, scope_prefix_len, addr))
    }

    pub fn source_prefix_len(&self) -> u8 { self.source_prefix_len }
    pub fn scope_prefix_len(&self) -> u8 { self.scope_prefix_len }
    pub fn addr(&self) -> IpAddr { self.addr }
}


//--- Composable and OptData

impl Composable for ClientSubnet {
    fn compose_len(&self) -> usize {
        match self.addr {
            IpAddr::V4(_) => 8,
            IpAddr::V6(_) => 20,
        }
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        match self.addr {
            IpAddr::V4(addr) => {
                1u16.compose(buf);
                self.source_prefix_len.compose(buf);
                self.scope_prefix_len.compose(buf);
                buf.put_slice(&addr.octets());
            }
            IpAddr::V6(addr) => {
                2u16.compose(buf);
                self.source_prefix_len.compose(buf);
                self.scope_prefix_len.compose(buf);
                buf.put_slice(&addr.octets());
            }
        }
    }
}

impl OptData for ClientSubnet {
    type ParseErr = OptionParseError;

    fn code(&self) -> OptionCode {
        OptionCode::EdnsClientSubnet
    }

    fn parse(code: OptionCode, len: usize, parser: &mut Parser)
             -> Result<Option<Self>, Self::ParseErr> {
        if code != OptionCode::EdnsClientSubnet {
            return Ok(None)
        }
        let family = parser.parse_u16()?;
        let source_prefix_len = parser.parse_u8()?;
        let scope_prefix_len = parser.parse_u8()?;
        let addr = match family {
            1 => {
                if len != 8 {
                    return Err(OptionParseError::InvalidV4Length(len))
                }
                let bytes: &[u8; 4] = unsafe {
                    mem::transmute(parser.peek(4)?.as_ptr())
                };
                parser.advance(4)?;
                IpAddr::from(*bytes)
            }
            2 => {
                if len != 20 {
                    return Err(OptionParseError::InvalidV6Length(len))
                }
                let bytes: &[u8; 16] = unsafe {
                    mem::transmute(parser.peek(16)?.as_ptr())
                };
                parser.advance(16)?;
                IpAddr::from(*bytes)
            }
            _ => return Err(OptionParseError::InvalidFamily(family))
        };
        Ok(Some(ClientSubnet::new(source_prefix_len, scope_prefix_len, addr)))
    }
}


//------------ ClientSubnetParseError ----------------------------------------

#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum OptionParseError {
    #[fail(display="invalid family {}", _0)]
    InvalidFamily(u16),

    #[fail(display="invalid length {} for IPv4 address", _0)]
    InvalidV4Length(usize),

    #[fail(display="invalid length {} for IPv6 address", _0)]
    InvalidV6Length(usize),

    #[fail(display="unexpected end of buffer")]
    ShortBuf,
}

impl From<ShortBuf> for OptionParseError {
    fn from(_: ShortBuf) -> Self {
        OptionParseError::ShortBuf
    }
}

