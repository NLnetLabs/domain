use std::fmt;
use std::net;
use super::super::compose::ComposeBytes;
use super::super::error::{ComposeResult, ParseResult};
use super::super::flavor::Flavor;
use super::super::iana::RRType;
use super::super::parse::ParseFlavor;
use super::traits::RecordData;




//------------ A ------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct A {
    addr: net::Ipv4Addr,
}

impl A {
    pub fn new(addr: net::Ipv4Addr) -> A {
        A { addr: addr }
    }

    pub fn addr(&self) -> &net::Ipv4Addr { &self.addr }
    pub fn addr_mut(&mut self) -> &mut net::Ipv4Addr { &mut self.addr }
}

impl<'a, F: Flavor<'a>> RecordData<'a, F> for A {
    fn rtype(&self) -> RRType { RRType::A }
    
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in self.addr.octets().iter() {
            try!(target.push_u8(*i))
        }
        Ok(())
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        if rtype != RRType::A { return Ok(None) }
        Ok(Some(A::new(net::Ipv4Addr::new(try!(parser.parse_u8()),
                                          try!(parser.parse_u8()),
                                          try!(parser.parse_u8()),
                                          try!(parser.parse_u8())))))
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}


//------------ NS -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct NS<'a, F: Flavor<'a>> {
    nsdname: F::DName
}

impl<'a, F: Flavor<'a>> NS<'a, F> {
    pub fn new(nsdname: F::DName) -> Self {
        NS { nsdname: nsdname }
    }

    pub fn nsdname(&self) -> &F::DName {
        &self.nsdname
    }
}

impl<'a, F: Flavor<'a>> RecordData<'a, F> for NS<'a, F> {
    fn rtype(&self) -> RRType { RRType::NS }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        target.push_dname_compressed(&self.nsdname)
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        if rtype != RRType::NS { return Ok(None) }
        Ok(Some(NS::new(try!(parser.parse_name()))))
    }
}


impl<'a, F: Flavor<'a>> fmt::Display for NS<'a, F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.nsdname.fmt(f)
    }
}

