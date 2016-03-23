//! Record data from RFC 3596.
//!
//! This RFC defines the AAAA record type.

use std::fmt;
use std::net::Ipv6Addr;
use super::super::compose::ComposeBytes;
use super::super::error::{ComposeResult, ParseResult};
use super::super::flavor::{FlatFlavor, Flavor};
use super::super::iana::RRType;
use super::super::parse::ParseFlavor;
use super::{FlatRecordData, RecordData};


//------------ AAAA ---------------------------------------------------------

#[derive(Clone, Debug)]
pub struct AAAA {
    addr: Ipv6Addr
}

impl AAAA {
    pub fn new(addr: Ipv6Addr) -> AAAA {
        AAAA { addr: addr }
    }

    pub fn addr(&self) -> &Ipv6Addr { &self.addr }
    pub fn addr_mut(&mut self) -> &mut Ipv6Addr {&mut self.addr }
}

impl <F: Flavor> RecordData<F> for AAAA {
    fn rtype(&self) -> RRType { RRType::AAAA }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in self.addr.segments().iter() {
            try!(target.push_u16(*i));
        }
        Ok(())
    }
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for AAAA {
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        if rtype != RRType::AAAA { return Ok(None) }
        Ok(Some(AAAA::new(Ipv6Addr::new(try!(parser.parse_u16()),
                                        try!(parser.parse_u16()),
                                        try!(parser.parse_u16()),
                                        try!(parser.parse_u16()),
                                        try!(parser.parse_u16()),
                                        try!(parser.parse_u16()),
                                        try!(parser.parse_u16()),
                                        try!(parser.parse_u16())))))
    }
}

impl fmt::Display for AAAA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}

