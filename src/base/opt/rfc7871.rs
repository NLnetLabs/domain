//! EDNS Options from RFC 7871

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::net::IpAddr;
use super::super::octets::{
    Compose, FormError, OctetsBuilder, Parse, ParseError, Parser, ShortBuf
};
use super::CodeOptData;


//------------ ClientSubnet --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClientSubnet {
    source_prefix_len: u8,
    scope_prefix_len: u8,
    addr: IpAddr,
}

impl ClientSubnet {
    pub fn new(
        source_prefix_len: u8,
        scope_prefix_len: u8,
        addr: IpAddr
    ) -> ClientSubnet {
        ClientSubnet { source_prefix_len, scope_prefix_len, addr }
    }

    pub fn push<Target: OctetsBuilder>(
        builder: &mut OptBuilder<Target>,
        source_prefix_len: u8,
        scope_prefix_len: u8,
        addr: IpAddr
    ) -> Result<(), ShortBuf> {
        builder.push(&Self::new(source_prefix_len, scope_prefix_len, addr))
    }

    pub fn source_prefix_len(&self) -> u8 { self.source_prefix_len }
    pub fn scope_prefix_len(&self) -> u8 { self.scope_prefix_len }
    pub fn addr(&self) -> IpAddr { self.addr }
}


//--- ParseAll and Compose

impl<Ref: AsRef<[u8]>> Parse<Ref> for ClientSubnet {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let family = parser.parse_u16()?;
        let source_prefix_len = parser.parse_u8()?;
        let scope_prefix_len = parser.parse_u8()?;
        let len = parser.remaining();
        let addr = match family {
            1 => {
                if len != 8 {
                    return Err(
                        FormError::new(
                            "invalid client subnet address length"
                        ).into()
                    )
                }
                let bytes: &[u8; 4] = unsafe {
                    &*(parser.peek(4)?.as_ptr() as *const [u8; 4])
                };
                parser.advance(4)?;
                IpAddr::from(*bytes)
            }
            2 => {
                if len != 20 {
                    return Err(
                        FormError::new(
                            "invalid client subnet address length"
                        ).into()
                    )
                }
                let bytes: &[u8; 16] = unsafe {
                    &*(parser.peek(16)?.as_ptr() as *const [u8; 16])
                };
                parser.advance(16)?;
                IpAddr::from(*bytes)
            }
            _ => {
                return Err(
                    FormError::new(
                        "invalid client subnet address family"
                    ).into()
                )
            }
        };
        Ok(ClientSubnet::new(source_prefix_len, scope_prefix_len, addr))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        // XXX Perhaps do a check?
        parser.advance_to_end();
        Ok(())
    }
}

impl Compose for ClientSubnet {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            match self.addr {
                IpAddr::V4(addr) => {
                    1u16.compose(target)?;
                    self.source_prefix_len.compose(target)?;
                    self.scope_prefix_len.compose(target)?;
                    addr.compose(target)
                }
                IpAddr::V6(addr) => {
                    2u16.compose(target)?;
                    self.source_prefix_len.compose(target)?;
                    self.scope_prefix_len.compose(target)?;
                    addr.compose(target)
                }
            }
        })
    }
}


//--- CodeOptData

impl CodeOptData for ClientSubnet {
    const CODE: OptionCode = OptionCode::ClientSubnet;
}

