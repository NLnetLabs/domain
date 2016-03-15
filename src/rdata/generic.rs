//! Generic Record Data Types

use std::fmt;
use super::super::bytes::BytesBuf;
use super::super::iana::RRType;
use super::super::name::CompactDomainName;
use super::traits::{RecordData, CompactRecordData, Result};


//------------ GenericRecordData --------------------------------------------

/// A slice of generic record data.
///
pub struct GenericRecordData<'a> {
    rtype: RRType,
    data: &'a [u8],
}

impl<'a> GenericRecordData<'a> {
    pub fn new(rtype: RRType, data: &'a[u8]) -> Self {
        GenericRecordData { rtype: rtype, data: data }
    }
}

impl<'a> RecordData for GenericRecordData<'a> {
    fn rtype(&self) -> RRType {
        self.rtype
    }

    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        buf.push_bytes(self.data);
        Ok(())
    }
}


//------------ CompactGenericRecordData -------------------------------------

pub struct CompactGenericRecordData<'a> {
    rtype: RRType,
    data: &'a [u8],
    context: &'a [u8],
}

impl<'a> CompactGenericRecordData<'a> {
    pub fn new(rtype: RRType, data: &'a[u8], context: &'a[u8]) -> Self {
        CompactGenericRecordData { rtype: rtype, data: data,
                                   context: context }
    }

    pub fn rtype(&self) -> RRType { self.rtype }
    pub fn data(&self) -> &[u8] { self.data }
    pub fn context(&self) -> &[u8] { self.context }

    pub fn fmt<C>(&self, f: &mut fmt::Formatter) -> fmt::Result
               where C: CompactRecordData<'a> + fmt::Display {
        match C::from_bytes(self.rtype, self.data, self.context) {
            Err(..) => Ok(()),
            Ok(None) => Ok(()),
            Ok(Some(data)) => data.fmt(f)
        }
    }
}

impl<'a> RecordData for CompactGenericRecordData<'a> {
    fn rtype(&self) -> RRType {
        self.rtype
    }

    fn push_buf<B: BytesBuf>(&self, buf: &mut B) -> Result<()> {
        buf.push_bytes(self.data);
        Ok(())
    }
}

impl<'a> CompactRecordData<'a> for CompactGenericRecordData<'a> {
    fn from_bytes(rtype: RRType, slice: &'a[u8], context: &'a[u8])
                  -> Result<Option<Self>> {
        Ok(Some(CompactGenericRecordData::new(rtype, slice, context)))
    }
}

impl<'a> fmt::Display for CompactGenericRecordData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use super::rfc1035::*;

        match self.rtype {
            RRType::A => self.fmt::<A>(f),
            RRType::NS => self.fmt::<NS<CompactDomainName<'a>>>(f),
            _ => "...".fmt(f)
        }
    }
}
