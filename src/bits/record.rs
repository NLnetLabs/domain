//! DNS Resource Records
//!
//! This module defines the type `Record` that represents a resource record.

use std::fmt;
use iana::{Class, RRType};
use super::compose::ComposeBytes;
use super::error::{ComposeError, ComposeResult, ParseResult};
use super::name::{AsDName, DName};
use super::nest::Nest;
use super::parse::ParseBytes;
use super::rdata::{GenericRecordData, RecordData};


//------------ Record -------------------------------------------------------

/// A resource record.
///
/// The information stored in the DNS is arranged in resource records. The
/// node the information pertains to is described by a domain name and a
/// class value. Each record has a record type that describes the type of
/// information stored in the record and the format of record data. In order
/// to allow caching of resource records, each record also carries a
/// time-to-live or TTL value that contains the number of seconds this record
/// is still considered to be current.
///
/// There can be more than one record for each combination of name, class,
/// and type.
///
/// This type represents one such resource record. Since there are more than
/// eighty record types currently defined—see `RRType` for a complete list—
/// the type is generic over a `RecordData` trait that represents the
/// concrete record data of the type.
///
/// Thus, most often when using records, you specify it in terms of the
/// record data it contains. For instance, a resource record of type
/// `RRType::A`, generally called an A record, can be given as `Record<A>`
/// (with the type `A` actually being `domain::rdata::A`).
///
/// There is a type for unknown record types, `GenericRecordData`, that can
/// also be used for working with records when the actual data doesn’t
/// matter.
///
/// DNS messages have three sections of resource records. These are explained
/// at the `Message` class which serves to parse messages. It features a type
/// for these sections which iterates over records.
///
/// When building messages, there are types for these sections as well. You
/// can use their `push()` method to add records you already have `Record`
/// values for. In addition, most record data types have associated functions
/// call `push()`, too, that allow you to create a record of their type
/// directly from components without creating a record first.
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

    /// Returns a mutable reference to the domain name.
    pub fn name_mut(&mut self) -> &mut DName<'a> {
        &mut self.name
    }

    /// Returns the record type.
    pub fn rtype(&self) -> RRType {
        self.rdata.rtype()
    }

    /// Returns the record class.
    pub fn class(&self) -> Class {
        self.class
    }

    /// Sets the record’s class.
    pub fn set_class(&mut self, class: Class) {
        self.class = class
    }

    /// Returns the record’s time-to-live.
    pub fn ttl(&self) -> u32 {
        self.ttl
    }

    /// Sets the record’s time-to-live.
    pub fn set_ttl(&mut self, ttl: u32) {
        self.ttl = ttl
    }

    /// Return a reference to the record data.
    pub fn rdata(&self) -> &D {
        &self.rdata
    }

    /// Returns a mutable reference to the record data.
    pub fn rdata_mut(&mut self) -> &mut D {
        &mut self.rdata
    }

    /// Converts the record into its record data.
    pub fn into_rdata(self) -> D {
        self.rdata
    }
}

/// Parsing and Composing
///
impl<'a, D: RecordData<'a>> Record<'a, D> {
    /// Parses a record from the beginning of a parser.
    ///
    /// Like `Record` itself, this function is generic over a record data
    /// type. In most cases, you will have to use a type parameter for
    /// describing this type.
    ///
    /// The function will return `Ok(Some(..))` if parsing the record
    /// succeeded and the record data type accepted records of this type.
    /// It will return `Ok(None)` if parsing the record itself succeeded,
    /// but either the record data type didn’t feel responsible for this
    /// record type or if parsing the record data failed.
    /// It will, finally, return `Err(..)` if parsing of the record itself
    /// failed.
    ///
    /// With this return scheme, there is, unfortunately, no way to
    /// distinguish between unaccepted record data and parse failed of the
    /// record data. For most operations this seems to be more agreeable
    /// then having a return type of `ParseError<Option<ParseError<Self>>>`.
    /// If you need to distinguish between the two cases, you can first
    /// parse into a `Record<GenericRecordData>>` and continue from there
    /// to your concrete type.
    pub fn parse<P>(parser: &mut P) -> ParseResult<Option<Self>>
                 where P: ParseBytes<'a> {
        let name = try!(parser.parse_dname());
        let rtype = try!(parser.parse_u16()).into();
        let class = try!(parser.parse_u16()).into();
        let ttl = try!(parser.parse_u32());
        let rdlen = try!(parser.parse_u16()) as usize;
        let mut rdata_sub = try!(parser.parse_sub(rdlen));
        match D::parse(rtype, &mut rdata_sub) {
            Some(Ok(data)) => Ok(Some(Record::new(name, class, ttl, data))),
            Some(Err(_)) | None => Ok(None),
        }
    }

    /// Pushes the record to the end of the compose target.
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

impl<'a, D: RecordData<'a> + fmt::Display> fmt::Display for Record<'a, D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t{}\t{}\t{}\t{}",
               self.name, self.ttl, self.class, self.rdata.rtype(),
               self.rdata)
    }
}


//------------ GenericRecord -------------------------------------------------

pub type GenericRecord<'a> = Record<'a, GenericRecordData<'a>>;

impl<'a> Record<'a, GenericRecordData<'a>> {
    pub fn new_generic(name: DName<'a>, class: Class, rtype: RRType,
                       ttl: u32, rdata: Nest<'a>) -> Self {
        Record::new(name, class, ttl, GenericRecordData::new(rtype, rdata))
    }
}


//------------ RecordTarget -------------------------------------------------

/// A helper trait to compose records without creating `Record` values first.
///
/// This trait is implemented by the various sections attainable from a
/// `MessageBuilder`. It is used by most record data types to compose
/// records of the specific type on the fly. These types usually provide a
/// associate method named `push()` or similar.
pub trait RecordTarget<C: ComposeBytes> {
    fn compose<F>(&mut self, push: F) -> ComposeResult<()>
               where F: Fn(&mut C) -> ComposeResult<()>;
}


/// A helper function to implement on the fly record composition.
///
/// Use this function when implementing the `push()` function for a
/// record data type.
///
/// Yes, it really needs all these type parameters. Sorry about that.
pub fn push_record<C, T, N, F>(target: &mut T, name: &N, rtype: RRType,
                        class: Class, ttl: u32, data: F)
                        -> ComposeResult<()>
            where C: ComposeBytes, T: RecordTarget<C>, N: AsDName,
                  F: Fn(&mut C) -> ComposeResult<()> {
    target.compose(|target| {
        try!(target.push_dname_compressed(name));
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

