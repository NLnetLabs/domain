//! DNS Records

use std::fmt;
use super::compose::ComposeBytes;
use super::error::{ComposeError, ComposeResult, ParseResult};
use super::iana::{Class, RRType};
use super::name::{AsDName, DName};
use super::parse::ParseBytes;
use super::rdata::RecordData;

//------------ Record -------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct Record<'a, D: RecordData<'a>> {
    name: DName<'a>,
    class: Class,
    ttl: u32,
    rdata: D
}


/// # Creation and Conversion
///
impl<'a, D: RecordData<'a>> Record<'a, D> {
    /// Creates a new record from its parts.
    pub fn new(name: DName<'a>, class: Class, ttl: u32, rdata: D) -> Self {
        Record { name: name, class: class, ttl: ttl, rdata: rdata }
    }
}


/// # Element Access
///
impl<'a, D: RecordData<'a>> Record<'a, D> {
    /// Returns a reference to the domain name.
    pub fn name(&self) -> &DName<'a> {
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

macro_rules! try_opt {
    ( $expr:expr ) => {
        match $expr {
            Ok(some) => some,
            Err(err) => return Some(Err(err.into()))
        }
    }
}

/// Parsing and Composing
///
impl<'a, D: RecordData<'a>> Record<'a, D> {
    pub fn parse<P>(parser: &mut P) -> Option<ParseResult<Self>>
                 where P: ParseBytes<'a> {
        let name = try_opt!(parser.parse_dname());
        let rtype = try_opt!(parser.parse_u16()).into();
        let class = try_opt!(parser.parse_u16()).into();
        let ttl = try_opt!(parser.parse_u32());
        let rdlen = try_opt!(parser.parse_u16()) as usize;
        let mut rdata_sub = try_opt!(parser.parse_sub(rdlen));
        match D::parse(rtype, &mut rdata_sub) {
            Some(Ok(data)) => Some(Ok(Record::new(name, class, ttl, data))),
            Some(Err(err)) => Some(Err(err)),
            None => None
        }
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
        let delta = target.delta(pos) - 2;
        if delta > (::std::u16::MAX as usize) {
            return Err(ComposeError::Overflow)
        }
        target.update_u16(pos, delta as u16)
    }

}


//--- Display

impl<'a, D: RecordData<'a>> fmt::Display for Record<'a, D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t{}\t{}\t{}\t{}",
               self.name, self.ttl, self.class, self.rdata.rtype(),
               self.rdata)
    }
}


//------------ RecordTarget -------------------------------------------------

pub trait RecordTarget<C: ComposeBytes> {
    fn compose<F>(&mut self, push: F) -> ComposeResult<()>
               where F: Fn(&mut C) -> ComposeResult<()>;
}


pub fn push_record<C, T, N, F>(target: &mut T, name: N, rtype: RRType,
                        class: Class, ttl: u32, data: F)
                        -> ComposeResult<()>
            where C: ComposeBytes, T: RecordTarget<C>, N: AsDName,
                  F: Fn(&mut C) -> ComposeResult<()> {
    target.compose(|target| {
        try!(target.push_dname_compressed(&name.as_dname()));
        try!(target.push_u16(rtype.into()));
        try!(target.push_u16(class.into()));
        try!(target.push_u32(ttl));
        let pos = target.pos();
        try!(target.push_u16(0));
        try!(data(target));
        let delta = target.delta(pos) - 2;
        if delta > (::std::u16::MAX as usize) {
            return Err(ComposeError::Overflow)
        }
        target.update_u16(pos, delta as u16)
    })
}




/*
//------------ ComposeRecord ------------------------------------------------

/// Helper trait to allow composing records from tuples.
pub trait ComposeRecord {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()>;
}

impl<F: Flavor, D: RecordData<F>> ComposeRecord for Record<F, D> {
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        self.compose(target)
    }
}
*/
