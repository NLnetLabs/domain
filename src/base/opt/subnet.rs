//! EDNS Options from RFC 7871

use core::fmt;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::net::IpAddr;
use super::super::wire::{Compose, Composer, FormError, ParseError};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::parse::Parser;

//------------ ClientSubnet --------------------------------------------------

const ERR_ADDR_LEN: &str = "invalid address length in client subnet option";

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
        addr: IpAddr,
    ) -> ClientSubnet {
        let source_prefix_len = normalize_prefix_len(addr, source_prefix_len);
        let scope_prefix_len = normalize_prefix_len(addr, scope_prefix_len);
        let (addr, _) = addr_apply_mask(addr, source_prefix_len);

        ClientSubnet {
            source_prefix_len,
            scope_prefix_len,
            addr,
        }
    }

    pub fn source_prefix_len(&self) -> u8 {
        self.source_prefix_len
    }
    pub fn scope_prefix_len(&self) -> u8 {
        self.scope_prefix_len
    }
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn parse<Octs: AsRef<[u8]>>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        let family = parser.parse_u16()?;
        let source_prefix_len = parser.parse_u8()?;
        let scope_prefix_len = parser.parse_u8()?;

        // https://tools.ietf.org/html/rfc7871#section-6
        //
        // | ADDRESS, variable number of octets, contains either an IPv4 or
        // | IPv6 address, depending on FAMILY, which MUST be truncated to
        // | the number of bits indicated by the SOURCE PREFIX-LENGTH field,
        // | padding with 0 bits to pad to the end of the last octet needed.
        let prefix_bytes = prefix_bytes(source_prefix_len);

        let addr = match family {
            1 => {
                let mut buf = [0; 4];
                if prefix_bytes > buf.len() {
                    return Err(ParseError::form_error(ERR_ADDR_LEN));
                }
                parser
                    .parse_buf(&mut buf[..prefix_bytes])
                    .map_err(|_| ParseError::form_error(ERR_ADDR_LEN))?;

                if parser.remaining() != 0 {
                    return Err(ParseError::form_error(ERR_ADDR_LEN));
                }

                IpAddr::from(buf)
            }
            2 => {
                let mut buf = [0; 16];
                if prefix_bytes > buf.len() {
                    return Err(ParseError::form_error(ERR_ADDR_LEN));
                }
                parser
                    .parse_buf(&mut buf[..prefix_bytes])
                    .map_err(|_| ParseError::form_error(ERR_ADDR_LEN))?;

                if parser.remaining() != 0 {
                    return Err(ParseError::form_error(ERR_ADDR_LEN));
                }

                IpAddr::from(buf)
            }
            _ => {
                return Err(FormError::new(
                    "invalid client subnet address family",
                )
                .into())
            }
        };

        // If the trailing bits beyond prefix length are not zero,
        // return form error.
        let (addr, modified) = addr_apply_mask(addr, source_prefix_len);
        if modified {
            return Err(ParseError::form_error(ERR_ADDR_LEN));
        }

        // no need to pass the normalizer in constructor again
        Ok(ClientSubnet {
            source_prefix_len,
            scope_prefix_len,
            addr,
        })
    }
}

//--- OptData

impl OptData for ClientSubnet {
    fn code(&self) -> OptionCode {
        OptionCode::ClientSubnet
    }
}

impl<'a, Octs: AsRef<[u8]>> ParseOptData<'a, Octs> for ClientSubnet {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::ClientSubnet {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeOptData for ClientSubnet {
    fn compose_len(&self) -> u16 {
        u16::try_from(prefix_bytes(self.source_prefix_len)).unwrap() + 4
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        let prefix_bytes = prefix_bytes(self.source_prefix_len);
        match self.addr {
            IpAddr::V4(addr) => {
                1u16.compose(target)?;
                self.source_prefix_len.compose(target)?;
                self.scope_prefix_len.compose(target)?;
                let array = addr.octets();
                assert!(prefix_bytes <= array.len());
                target.append_slice(&array[..prefix_bytes])
            }
            IpAddr::V6(addr) => {
                2u16.compose(target)?;
                self.source_prefix_len.compose(target)?;
                self.scope_prefix_len.compose(target)?;
                let array = addr.octets();
                assert!(prefix_bytes <= array.len());
                target.append_slice(&array[..prefix_bytes])
            }
        }
    }
}

fn prefix_bytes(bits: u8) -> usize {
    (usize::from(bits) + 7) / 8
}

// Apply a prefix bit mask indicated by its length to the provided
// buffer, clear rest of the buffer which is not covered by the mask.
// Reture whether or not the buffer has been modified.
fn apply_bit_mask(buf: &mut [u8], mask: usize) -> bool {
    let mut modified = false;

    // skip full bytes covered by prefix length
    let mut p = mask / 8;
    if p >= buf.len() {
        return modified;
    }

    // clear extra bits in a byte
    let bits = mask % 8;
    if bits != 0 {
        if buf[p].trailing_zeros() < (8 - bits) as u32 {
            buf[p] &= 0xff << (8 - bits);
            modified = true;
        }
        p += 1;
    }

    // clear the rest bytes
    while p < buf.len() {
        if buf[p] != 0 {
            buf[p] = 0;
            modified = true;
        }
        p += 1;
    }

    modified
}

fn addr_apply_mask(addr: IpAddr, len: u8) -> (IpAddr, bool) {
    match addr {
        IpAddr::V4(a) => {
            let mut array = a.octets();
            let m = apply_bit_mask(&mut array, len as usize);
            (array.into(), m)
        }
        IpAddr::V6(a) => {
            let mut array = a.octets();
            let m = apply_bit_mask(&mut array, len as usize);
            (array.into(), m)
        }
    }
}

fn normalize_prefix_len(addr: IpAddr, len: u8) -> u8 {
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    core::cmp::min(len, max)
}


//------------ OptBuilder ----------------------------------------------------

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn client_subnet(
        &mut self,
        source_prefix_len: u8,
        scope_prefix_len: u8,
        addr: IpAddr,
    ) -> Result<(), Target::AppendError> {
        self.push(
            &ClientSubnet::new(source_prefix_len, scope_prefix_len, addr)
        )
    }
}

impl fmt::Display for ClientSubnet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.addr {
            IpAddr::V4(a) => {
                if self.scope_prefix_len != 0 {
                    write!(f, "{}/{}/{}", a, self.source_prefix_len,
                        self.scope_prefix_len)?;
                } else {
                    write!(f, "{}/{}", a, self.source_prefix_len)?;
                }
            }
            IpAddr::V6(a) => {
                if self.scope_prefix_len != 0 {
                    write!(f, "{}/{}/{}", a, self.source_prefix_len,
                        self.scope_prefix_len)?;
                } else {
                    write!(f, "{}/{}", a, self.source_prefix_len)?;
                }
            }
        }

        Ok(())
    }
}

//============ Testing =======================================================

#[cfg(all(test, feature="std", feature = "bytes"))]
mod tests {
    use super::*;
    use super::super::test::test_option_compose_parse;
    use octseq::builder::infallible;
    use std::vec::Vec;
    use core::str::FromStr;

    macro_rules! check {
        ($name:ident, $addr:expr, $prefix:expr, $exp:expr, $ok:expr) => {
            #[test]
            fn $name() {
                let addr = $addr.parse().unwrap();
                let opt = ClientSubnet::new($prefix, 0, addr);
                assert_eq!(opt.addr(), $exp.parse::<IpAddr>().unwrap());

                // Check parse by mangling the addr in option to
                // generate maybe invalid buffer.
                let mut opt_ = opt.clone();
                opt_.addr = addr;
                let mut buf = Vec::new();

                infallible(opt_.compose_option(&mut buf));
                match ClientSubnet::parse(&mut Parser::from_ref(&buf)) {
                    Ok(v) => assert_eq!(opt, v),
                    Err(_) => assert!(!$ok),
                }
            }
        };
    }

    check!(prefix_at_boundary_v4, "192.0.2.0", 24, "192.0.2.0", true);
    check!(prefix_at_boundary_v6, "2001:db8::", 32, "2001:db8::", true);
    check!(prefix_no_truncation, "192.0.2.0", 23, "192.0.2.0", true);
    check!(prefix_need_truncation, "192.0.2.0", 22, "192.0.0.0", false);
    check!(prefix_min, "192.0.2.0", 0, "0.0.0.0", true);
    check!(prefix_max, "192.0.2.0", 32, "192.0.2.0", true);
    check!(prefix_too_long, "192.0.2.0", 100, "192.0.2.0", false);
    
    #[test]
    fn client_subnet_compose_parse() {
        test_option_compose_parse(
            &ClientSubnet::new(4, 6, IpAddr::from_str("127.0.0.1").unwrap()),
            |parser| ClientSubnet::parse(parser)
        );
    }
}
