//! EDNS Options from RFC 7871

use std::error;
use std::net::IpAddr;
use bytes::BufMut;
use derive_more::Display;
use crate::compose::Compose;
use crate::iana::OptionCode;
use crate::message_builder::OptBuilder;
use crate::parse::{ParseAll, Parser, ShortBuf};
use super::CodeOptData;


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


//--- ParseAll and Compose


impl ParseAll for ClientSubnet {
    type Err = OptionParseError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let family = parser.parse_u16()?;
        let source_prefix_len = parser.parse_u8()?;
        let scope_prefix_len = parser.parse_u8()?;
        let addr = match family {
            1 => {
                if len != 8 {
                    return Err(OptionParseError::InvalidV4Length(len))
                }
                let bytes: &[u8; 4] = unsafe {
                    &*(parser.peek(4)?.as_ptr() as *const [u8; 4])
                };
                parser.advance(4)?;
                IpAddr::from(*bytes)
            }
            2 => {
                if len != 20 {
                    return Err(OptionParseError::InvalidV6Length(len))
                }
                let bytes: &[u8; 16] = unsafe {
                    &*(parser.peek(16)?.as_ptr() as *const [u8; 16])
                };
                parser.advance(16)?;
                IpAddr::from(*bytes)
            }
            _ => return Err(OptionParseError::InvalidFamily(family))
        };
        Ok(ClientSubnet::new(source_prefix_len, scope_prefix_len, addr))
    }
}

impl Compose for ClientSubnet {
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


//--- CodeOptData

impl CodeOptData for ClientSubnet {
    const CODE: OptionCode = OptionCode::ClientSubnet;
}


//------------ ClientSubnetParseError ----------------------------------------

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum OptionParseError {
    #[display(fmt="invalid family {}", _0)]
    InvalidFamily(u16),

    #[display(fmt="invalid length {} for IPv4 address", _0)]
    InvalidV4Length(usize),

    #[display(fmt="invalid length {} for IPv6 address", _0)]
    InvalidV6Length(usize),

    #[display(fmt="unexpected end of buffer")]
    ShortBuf,
}

impl error::Error for OptionParseError { }

impl From<ShortBuf> for OptionParseError {
    fn from(_: ShortBuf) -> Self {
        OptionParseError::ShortBuf
    }
}

