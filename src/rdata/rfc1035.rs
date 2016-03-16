use std::fmt;
use std::net;
use super::super::bytes::{BytesBuf, BytesSlice};
use super::super::iana::RRType;
use super::super::name::{DomainName, CompactDomainName};
use super::super::question::Result;
use super::traits::{ConcreteRecordData, CompactConcreteRecordData};


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

impl<'a> ConcreteRecordData<'a> for A {
    fn rtype() -> RRType { RRType::A }
    
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        for i in self.addr.octets().iter() {
            buf.push_u8(*i);
        }
        Ok(())
    }
}

impl<'a> CompactConcreteRecordData<'a> for A {
    fn parse(rdata: &'a[u8], _: &[u8]) -> Result<Self> {
        let (a, rdata) = try!(rdata.split_u8());
        let (b, rdata) = try!(rdata.split_u8());
        let (c, rdata) = try!(rdata.split_u8());
        let (d, _) = try!(rdata.split_u8());
        Ok(A::new(net::Ipv4Addr::new(a, b, c, d)))
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}


//------------ NS -----------------------------------------------------------

#[derive(Debug)]
pub struct NS<N: DomainName> {
    nsdname: N
}

pub type CompactNS<'a> = NS<CompactDomainName<'a>>;

impl<N: DomainName> NS<N> {
    pub fn new(nsdname: N) -> Self {
        NS { nsdname: nsdname }
    }

    pub fn nsdname(&self) -> &N {
        &self.nsdname
    }
}

impl<'a, N: DomainName> ConcreteRecordData<'a> for NS<N> {
    fn rtype() -> RRType { RRType::NS }

    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.nsdname.push_buf_compressed(buf));
        Ok(())
    }
}

impl<'a> CompactConcreteRecordData<'a> for NS<CompactDomainName<'a>> {
    fn parse(rdata: &'a[u8], context: &'a [u8]) -> Result<Self> {
        let (name, _) = try!(CompactDomainName::split_from(rdata, context));
        Ok(NS::new(name))
    }
}


impl<N: DomainName> fmt::Display for NS<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.nsdname.fmt(f)
    }
}
