use std::fmt;
use super::name::{DomainName, CompactDomainName};
use super::bytes::{self, BytesSlice, BytesBuf};
use super::question::Result; // XXX Temporary.
use super::iana::{Class, RRType};
use super::rdata::traits::{RecordData, CompactRecordData};


//------------ Record -------------------------------------------------------

#[derive(Debug)]
pub struct Record<N: DomainName, D: RecordData> {
    name: N,
    rclass: Class,
    ttl: u32,
    rdata: D
}


//--- Common

impl<N: DomainName, D: RecordData> Record<N, D> {
    pub fn new(name: N, rclass: Class, ttl: u32, rdata: D) -> Self {
        Record { name: name, rclass: rclass, ttl: ttl, rdata: rdata }
    }

    pub fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.name.push_buf(buf));
        self.rdata.rtype().push_buf(buf);
        self.rclass.push_buf(buf);
        buf.push_u32(self.ttl);
        let pos = buf.pos();
        buf.push_u16(0);
        try!(self.rdata.push_buf(buf));
        let delta = buf.delta(pos);
        if delta > (::std::u16::MAX as usize) {
            return Err(bytes::Error::Overflow.into())
        }
        buf.update_u16(pos, delta as u16);
        Ok(())
    }

    /// Returns the domain name.
    pub fn name(&self) -> &N { &self.name }

    /// Returns the record type.
    pub fn rtype(&self) -> RRType { self.rdata.rtype() }

    /// Returns the record class.
    pub fn rclass(&self) -> Class { self.rclass }

    /// Returns the record’s time to live.
    pub fn ttl(&self) -> u32 { self.ttl }

    /// Returns the raw record data.
    pub fn rdata(&self) -> &D { &self.rdata }
}


//---- Compact record

impl <'a, D: CompactRecordData<'a>> Record<CompactDomainName<'a>, D> {
    /// Splits a record from the front of a bytes slice.
    ///
    pub fn split_from(slice: &'a[u8], context: &'a[u8])
                      -> Result<(Option<Self>, &'a[u8])> {
        let (name, slice) = try!(CompactDomainName::split_from(slice,
                                                               context));
        let (rtype, slice) = try!(slice.split_u16());
        let (rclass, slice) = try!(slice.split_u16());
        let (ttl, slice) = try!(slice.split_u32());
        let (rdlen, slice) = try!(slice.split_u16());
        let (rdata, slice) = try!(slice.split_bytes(rdlen as usize));
        match try!(D::from_bytes(rtype.into(), rdata, context)) {
            None => Ok((None, slice)),
            Some(rdata) => {
                Ok((Some(Record::new(name, rclass.into(), ttl, rdata)),
                   slice))
            }
        }
    }
}


//---- Traits

impl <N: DomainName, D: RecordData> fmt::Display for Record<N, D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t{}\t{}\t{}\t{}",
               self.name, self.ttl, self.rclass, self.rdata.rtype(),
               self.rdata)
    }
}

