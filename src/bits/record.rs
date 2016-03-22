//! DNS Records

use std::fmt;
use super::compose::ComposeBytes;
use super::error::{ComposeError, ComposeResult, ParseResult};
use super::flavor::Flavor;
use super::iana::{Class, RRType};
use super::parse::ParseFlavor;
use super::rdata::RecordData;

//------------ Record -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Record<'a, F: Flavor<'a>, D: RecordData<'a, F>> {
    name: F::DName,
    class: Class,
    ttl: u32,
    rdata: D
}


/// # Creation and Conversion
///
impl<'a, F: Flavor<'a>, D: RecordData<'a, F>> Record<'a, F, D> {
    /// Creates a new record from its parts.
    pub fn new(name: F::DName, class: Class, ttl: u32, rdata: D) -> Self {
        Record { name: name, class: class, ttl: ttl, rdata: rdata }
    }
}


/// # Element Access
///
impl<'a, F: Flavor<'a>, D: RecordData<'a, F>> Record<'a, F, D> {
    /// Returns a reference to the domain name.
    pub fn name(&self) -> &F::DName {
        &self.name
    }

    /// Returns the record type.
    pub fn rtype(&self) -> RRType {
        self.rdata.rtype()
    }

    /// Returns the record class.
    pub fn class(&self) -> Class {
        self.class
    }

    /// Returns the record’s time to live.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Return a reference to the record data.
    pub fn rdata(&self) -> &D {
        &self.rdata
    }
}


/// Parsing and Composing
///
impl<'a, F: Flavor<'a>, D: RecordData<'a, F>> Record<'a, F, D> {
    pub fn parse<P>(parser: &mut P) -> ParseResult<Option<Self>>
                 where P: ParseFlavor<'a, F> {
        let name = try!(parser.parse_name());
        let rtype = try!(parser.parse_u16()).into();
        let class = try!(parser.parse_u16()).into();
        let ttl = try!(parser.parse_u32());
        let rdlen = try!(parser.parse_u16()) as usize;
        let mut rdata_sub = try!(parser.parse_sub(rdlen));
        Ok(try!(D::parse(rtype, &mut rdata_sub))
                  .map(|rdata| Record::new(name, class, ttl, rdata)))
    }

    pub fn compose<C: ComposeBytes>(&self, target: &mut C)
                                    -> ComposeResult<()> {
        try!(target.push_dname_compressed(&self.name));
        try!(target.push_u16(self.rdata.rtype().into()));
        try!(target.push_u16(self.class.into()));
        try!(target.push_u32(self.ttl));
        let pos = target.pos();
        try!(target.push_u16(0));
        try!(self.rdata.compose(target));
        let delta = target.delta(pos);
        if delta > (::std::u16::MAX as usize) {
            return Err(ComposeError::Overflow)
        }
        target.update_u16(pos, delta as u16)
    }
}


//--- Display

impl<'a, F, D> fmt::Display for Record<'a, F, D> 
     where F: Flavor<'a>, D: RecordData<'a, F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t{}\t{}\t{}\t{}",
               self.name, self.ttl, self.class, self.rdata.rtype(),
               self.rdata)
    }
}


//------------ ComposeRecord ------------------------------------------------

/// Helper trait to allow composing records from tuples.
pub trait ComposeRecord {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()>;
}

impl<'a, F, D> ComposeRecord for Record<'a, F, D>
      where F: Flavor<'a>, D: RecordData<'a, F> {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        self.compose(target)
    }
}

