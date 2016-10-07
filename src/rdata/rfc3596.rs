//! Record data from [RFC 3596].
//!
//! This RFC defines the Aaaa record type.
//!
//! [RFC 3596]: https://tools.ietf.org/html/rfc3596

use std::fmt;
use std::net::Ipv6Addr;
use std::str::FromStr;
use ::bits::{Composable, Composer, ComposeResult, DNameSlice, ParsedRecordData,
             Parser, ParseResult, RecordData};
use ::iana::Rtype;
use ::master::{Scanner, ScanResult};


//------------ Aaaa ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Aaaa {
    addr: Ipv6Addr
}

impl Aaaa {
    pub fn new(addr: Ipv6Addr) -> Aaaa {
        Aaaa { addr: addr }
    }

    pub fn addr(&self) -> Ipv6Addr { self.addr }
    pub fn set_addr(&mut self, addr: Ipv6Addr) { self.addr = addr }

    fn parse_always(parser: &mut Parser) -> ParseResult<Self> {
        Ok(Aaaa::new(Ipv6Addr::new(try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()))))
    }

    pub fn scan<S: Scanner>(scanner: &mut S, _origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        scanner.scan_str_phrase(|slice| {
            let addr = try!(Ipv6Addr::from_str(slice));
            Ok(Aaaa::new(addr))
        })
    }
}

impl RecordData for Aaaa {
    fn rtype(&self) -> Rtype { Rtype::Aaaa }

    fn compose<C: AsMut<Composer>>(&self, mut target: C)
                                   -> ComposeResult<()> {
        for i in &self.addr.segments() {
            try!(i.compose(target.as_mut()));
        }
        Ok(())
    }
}

impl<'a> ParsedRecordData<'a> for Aaaa {
    fn parse(rtype: Rtype, parser: &mut Parser) -> ParseResult<Option<Self>> {
        if rtype == Rtype::Aaaa { Aaaa::parse_always(parser).map(Some) }
        else { Ok(None) }
    }
}

impl fmt::Display for Aaaa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}

