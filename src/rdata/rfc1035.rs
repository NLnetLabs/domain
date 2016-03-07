use std::borrow::Cow;
use std::net;
use ::bytes::{BytesBuf, BytesSlice};
use ::question::Result;
use ::name::{BuildDomainName, DomainName, DomainNameBuf, WireDomainName};
use super::traits::ConcreteRecordData;

#[derive(Clone, Debug)]
pub struct A {
    pub addr: net::Ipv4Addr,
}

impl A {
    pub fn new(addr: net::Ipv4Addr) -> A {
        A { addr: addr }
    }
}

impl<'a> ConcreteRecordData<'a> for A {
    fn rtype() -> u16 { 1 }
    fn rname() -> &'static str { "A" }
    
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        for i in self.addr.octets().iter() {
            buf.push_u8(*i);
        }
        Ok(())
    }

    fn parse(rdata: &'a[u8], _: &[u8]) -> Result<Self> {
        let (a, rdata) = try!(rdata.split_u8());
        let (b, rdata) = try!(rdata.split_u8());
        let (c, rdata) = try!(rdata.split_u8());
        let (d, _) = try!(rdata.split_u8());
        Ok(A::new(net::Ipv4Addr::new(a, b, c, d)))
    }
    
    fn to_owned(&self) -> Self {
        self.clone()
    }
}


pub struct NS<'a> {
    pub nsdname: Cow<'a, DomainName>,
}

impl<'a> NS<'a> {
    pub fn new(nsdname: Cow<'a, DomainName>) -> Self {
        NS { nsdname: nsdname }
    }

    pub fn nsdname(&self) -> &DomainName {
        &self.nsdname
    }

    pub fn nsdname_mut(&mut self) -> &mut DomainNameBuf {
        self.nsdname.to_mut()
    }
}

impl<'a> ConcreteRecordData<'a> for NS<'a> {
    fn rtype() -> u16 { 2 }
    fn rname() -> &'static str { "NS" }

    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.nsdname.push_buf(buf));
        Ok(())
    }

    fn parse(rdata: &'a[u8], context: &'a [u8]) -> Result<Self> {
        let (name, _) = try!(WireDomainName::split_from(rdata, context));
        Ok(NS::new(try!(name.decompress())))
    }

    fn to_owned(&self) -> Self {
        NS { nsdname: self.nsdname.to_owned() }
    }
}
