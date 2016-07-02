//! Record data from RFC 3596.
//!
//! This RFC defines the Aaaa record type.

use std::fmt;
use std::net::Ipv6Addr;
use bits::compose::ComposeBytes;
use bits::error::{ComposeResult, ParseResult};
use iana::RRType;
use bits::parse::ParseBytes;
use bits::rdata::RecordData;


//------------ Aaaa ---------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Aaaa {
    addr: Ipv6Addr
}

impl Aaaa {
    pub fn new(addr: Ipv6Addr) -> Aaaa {
        Aaaa { addr: addr }
    }

    pub fn addr(&self) -> Ipv6Addr { self.addr }
    pub fn set_addr(&mut self, addr: Ipv6Addr) { self.addr = addr }

    fn parse_always<'a, P>(parser: &mut P) -> ParseResult<Self>
                    where P: ParseBytes<'a> {
        Ok(Aaaa::new(Ipv6Addr::new(try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()),
                                   try!(parser.parse_u16()))))
    }
}

impl<'a> RecordData<'a> for Aaaa {
    fn rtype(&self) -> RRType { RRType::Aaaa }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in self.addr.segments().iter() {
            try!(target.push_u16(*i));
        }
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        if rtype == RRType::Aaaa { Some(Aaaa::parse_always(parser)) }
        else { None }
    }
}

impl fmt::Display for Aaaa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}

