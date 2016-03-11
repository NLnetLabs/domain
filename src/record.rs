use std::borrow::Cow;
use super::name::{BuildDomainName, DomainName, DomainNameBuf, WireDomainName};
use super::bytes::{self, BytesSlice, BytesBuf};
use super::question::{Result, Error}; // XXX Temporary.
use super::iana::{Class, RRType};
use super::rdata::traits::{BuildRecordData, RecordDataSlice};

//------------ RecordBuf ----------------------------------------------------

#[derive(Debug)]
pub struct RecordBuf<D: BuildRecordData> {
    name: DomainNameBuf,
    rclass: Class,
    ttl: u32,
    rdata: D,
}

impl<D: BuildRecordData> RecordBuf<D> {
    /// Creates a new empty record.
    pub fn new<N: AsRef<DomainName>>(name: &N, rclass: Class, ttl: u32,
                                     rdata: D) -> Self {
        RecordBuf { name: name.as_ref().to_owned(), rclass: rclass, ttl: ttl,
                    rdata: rdata }
    }

    pub fn rdata(&self) -> &D { &self.rdata }
    pub fn rdata_mut(&mut self) -> &mut D { &mut self.rdata }
}

impl<D: BuildRecordData> BuildRecord for RecordBuf<D> {
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.name.push_buf(buf));
        buf.push_u16(self.rdata.rtype());
        self.rclass.push_buf(buf);
        buf.push_u32(self.ttl);
        let pos = buf.pos();
        buf.push_u16(0);
        try!(self.rdata.push_buf(buf));
        let delta = buf.delta(pos);
        if delta > (::std::u16::MAX as usize) {
            return Err(Error::OctetError(bytes::Error::Overflow));
        }
        buf.update_u16(pos, delta as u16);
        Ok(())
    }
}


//------------ WireRecord --------------------------------------------------

#[derive(Debug)]
pub struct WireRecord<'a> {
    name: WireDomainName<'a>,
    rtype: RRType,
    rclass: Class,
    ttl: u32,
    rdata: &'a[u8],
    message: &'a[u8],
}

/// # Creation and Conversion
///
impl<'a> WireRecord<'a> {
    /// Create a new raw record.
    ///
    pub fn new(name: WireDomainName<'a>, rtype: RRType, rclass: Class,
               ttl: u32, rdata: &'a[u8], message: &'a[u8])
               -> WireRecord<'a> {
        WireRecord { name: name, rtype: rtype, rclass: rclass, ttl: ttl,
                      rdata: rdata, message: message }
    }

    /// Splits a record from the front of a bytes slice.
    ///
    pub fn split_from(slice: &'a[u8], context: &'a[u8])
                      -> Result<(WireRecord<'a>, &'a[u8])> {
        let (name, slice) = try!(WireDomainName::split_from(slice,
                                                             context));
        let (rtype, slice) = try!(slice.split_u16());
        let (rclass, slice) = try!(slice.split_u16());
        let (ttl, slice) = try!(slice.split_u32());
        let (rdlen, slice) = try!(slice.split_u16());
        let (rdata, slice) = try!(slice.split_bytes(rdlen as usize));
        Ok((WireRecord::new(name, rtype.into(), rclass.into(), ttl, rdata,
                            context),
            slice))
    }

    /// Converts `self` into an owned record.
    pub fn to_owned<D: RecordDataSlice<'a>>(&self)
                -> Result<Option<RecordBuf<D::Owned>>> {
        let rdata = match try!(self.rdata::<D>()) {
            None => return Ok(None),
            Some(rdata) => rdata
        };
        Ok(Some(RecordBuf { name: try!(self.name.to_owned()),
                            rclass: self.rclass, ttl: self.ttl,
                            rdata: rdata.to_owned() }))
    }

    pub fn rdata<D: RecordDataSlice<'a>>(&self) -> Result<Option<D>> {
        D::parse(self.rtype.to_int(), self.rdata, self.message)
            .map_err(|e| e.into())
    }
}

/// # Element Access
///
impl<'a> WireRecord<'a> {
    /// Returns the domain name.
    pub fn name(&self) -> WireDomainName<'a> {
        self.name.clone()
    }

    /// Returns the uncompressed domain name.
    pub fn decompressed_name(&self) -> Result<Cow<DomainName>> {
        Ok(try!(self.name.decompress()))
    }

    /// Returns the record type.
    pub fn rtype(&self) -> RRType { self.rtype }

    /// Returns the record class.
    pub fn rclass(&self) -> Class { self.rclass }

    /// Returns the record’s time to live.
    pub fn ttl(&self) -> u32 { self.ttl }

    /// Returns the raw record data.
    pub fn rdata_bytes(&self) -> &'a[u8] { self.rdata }
}

impl<'a> BuildRecord for WireRecord<'a> {
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        try!(self.name.push_buf(buf));
        self.rtype.push_buf(buf);
        self.rclass.push_buf(buf);
        buf.push_u32(self.ttl);
        buf.push_u16(self.rdata.len() as u16);
        buf.push_bytes(self.rdata);
        Ok(())
    }
}


//------------ BuildRecord --------------------------------------------------

pub trait BuildRecord {
    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()>;
}
