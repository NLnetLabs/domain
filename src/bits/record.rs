//! Resource Records
//!
//! This module defines the [`Record`] type that represents DNS resource
//! records. It also provides a type alias for parsed records with generic
//! data through [`GenericRecord`].
//!
//! [`Record`]: struct.Record.html
//! [`GenericRecord`]: type.GenericRecord.html

use std::fmt;
use super::{Composer, ComposeError, ComposeResult, DName, GenericRecordData,
            ParsedDName, ParsedRecordData, Parser, ParseResult, RecordData};
use ::iana::{Class, Rtype};


//------------ Record --------------------------------------------------------

/// A DNS resource record.
///
/// All information available through the DNS is stored in resource records.
/// They have a three part key of a domain name, resource record type, and
/// class. Data is arranged in a tree which is navigated using the domain
/// name. Each node in the tree carries a label, starting with the root
/// label as the top-most node. The tree is traversed by stepping through the
/// name from right to left, finding a child node carring the label of each
/// step.
///
/// The record type describes the kind of data the record holds, such as IP
/// addresses. The class, finally, describes which sort of network the
/// information is for since DNS was originally intended to be used for
/// networks other than the Internet as well. In practice, the only relevant
/// class is IN, the Internet. Note that each class has its own tree of nodes.
///
/// The payload of a resource record is its data. Its purpose, meaning, and
/// format is determined by the record type. For each unique three-part key
/// there can be multiple resource records. All these records for the same
/// key are called *resource record sets,* most often shortened to ‘RRset.’
///
/// There is one more piece of data: the TTL or time to live. This value
/// says how long a record remains valid before it should be refreshed from
/// its original source, given in seconds. The TTL is used to add caching
/// facilities to the DNS.
///
/// Values of the `Record` type represent one single resource record. Since
/// there are currently more than eighty record types—see [`Rtype`] for a
/// complete list—, the type is generic over a trait for record data. This
/// trait holds both the record type value and the record data as they are
/// inseparably entwined.
///
/// Since records contain domain names, the `Record` type is additionally
/// generic over a domain name type. 
///
/// There is three ways to create a record value. First, you can make one
/// yourself using the [`new()`] function. In will neatly take care of all
/// the generics through type inference. Secondly, you can parse a record
/// from an existing message. [`Message`] and its friends provide a way to
/// do that; see there for all the details. Finally, you can scan a record
/// from master data (aka zonefiles). See the [`domain::master`] module for
/// that.
///
/// Records can be place into DNS messages through the value chain starting 
/// with [`MessageBuilder`]. In order to make adding records easier, `Record`
/// implements the `From` trait for two kinds of tuples: A four-tuple of
/// name, class, time-to-live value, and record data and a triple leaving
/// out the class and assuming it to `Class::In`.
///
/// [`new()´]: #method.new
/// [`Message`]: ../message/struct.Message.html
/// [`MessageBuilder`]: ../message_builder/struct.MessageBuilder.html
/// [`Rtype`]: ../../iana/enum.Rtype.html
/// [`domain::master`]: ../../master/index.html
#[derive(Clone, Debug)]
pub struct Record<N: DName, D: RecordData> {
    name: N,
    class: Class,
    ttl: u32,
    data: D
}


/// # Creation and Element Access
///
impl<N: DName, D: RecordData> Record<N, D> {
    /// Creates a new record from its parts.
    pub fn new(name: N, class: Class, ttl: u32, data: D) -> Self {
        Record{name: name, class: class, ttl: ttl, data: data}
    }

    /// Returns a reference to the domain name.
    ///
    /// The domain name, sometimes called the *owner* of the record,
    /// specifies the node in the DNS tree this record belongs to.
    pub fn name(&self) -> &N {
        &self.name
    }

    /// Returns the record type.
    pub fn rtype(&self) -> Rtype {
        self.data.rtype()
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
    pub fn data(&self) -> &D {
        &self.data
    }

    /// Returns a mutable reference to the record data.
    pub fn data_mut(&mut self) -> &mut D {
        &mut self.data
    }

    /// Trades the record for its record data.
    pub fn into_data(self) -> D {
        self.data
    }
}


/// # Parsing
///
impl<'a, D: ParsedRecordData<'a>> Record<ParsedDName<'a>, D> {
    /// Parses a record from a parser.
    ///
    /// This function is only available for records that use a parsed domain
    /// name and a record data type that, too, can be parsed.
    pub fn parse(parser: &mut Parser<'a>) -> ParseResult<Option<Self>> {
        let name = try!(ParsedDName::parse(parser));
        let rtype = try!(Rtype::parse(parser));
        let class = try!(Class::parse(parser));
        let ttl = try!(parser.parse_u32());
        let rdlen = try!(parser.parse_u16()) as usize;
        try!(parser.set_limit(rdlen));
        let data = try!(D::parse(rtype, parser));
        if data.is_none() {
            try!(parser.skip(rdlen));
        }
        parser.remove_limit();
        Ok(data.map(|data| Record::new(name, class, ttl, data)))
    }
}

impl<'a> Record<ParsedDName<'a>, GenericRecordData<'a>> {
    /// Parses a record with generic data from a parser.
    pub fn parse_generic(parser: &mut Parser<'a>) -> ParseResult<Self> {
        Self::parse(parser).map(Option::unwrap)
    }
}
    

/// # Composing
///
impl<N: DName, D: RecordData> Record<N, D> {
    /// Appends the record’s wire-format representation to a composer.
    pub fn compose<C: AsMut<Composer>>(&self, mut composer: C)
                                       -> ComposeResult<()> {
        try!(self.name.compose(composer.as_mut()));
        try!(self.data.rtype().compose(composer.as_mut()));
        try!(self.class.compose(composer.as_mut()));
        try!(composer.as_mut().compose_u32(self.ttl));
        let pos = composer.as_mut().pos();
        try!(composer.as_mut().compose_u16(0));
        try!(self.data.compose(composer.as_mut()));
        let delta = composer.as_mut().delta(pos) - 2;
        if delta > (::std::u16::MAX as usize) {
            return Err(ComposeError::Overflow)
        }
        composer.as_mut().update_u16(pos, delta as u16);
        Ok(())
    }
}


//--- From

impl<N: DName, D: RecordData> From<(N, Class, u32, D)> for Record<N, D> {
    fn from(x: (N, Class, u32, D)) -> Self {
        Record::new(x.0, x.1, x.2, x.3)
    }
}

impl<N: DName, D: RecordData> From<(N, u32, D)> for Record<N, D> {
    fn from(x: (N, u32, D)) -> Self {
        Record::new(x.0, Class::In, x.1, x.2)
    }
}


//--- Display

impl<N, D> fmt::Display for Record<N, D>
     where N: DName + fmt::Display,
           D: RecordData + fmt::Display {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t{}\t{}\t{}\t{}",
               self.name, self.ttl, self.class, self.data.rtype(),
               self.data)
    }
}


//------------ GenericRecord -------------------------------------------------

/// A record with generic record data.
pub type GenericRecord<'a> = Record<ParsedDName<'a>, GenericRecordData<'a>>;

