//! Resource Records
//!
//! This module defines the [`Record`] type that represents DNS resource
//! records. It also provides a type alias for parsed records with generic
//! data through [`GenericRecord`].
//!
//! [`Record`]: struct.Record.html
//! [`GenericRecord`]: type.GenericRecord.html

use std::fmt;
use bytes::BufMut;
use ::iana::{Class, Rtype};
use super::compose::Composable;
use super::parse::{Parseable, Parser, ShortParser};
use super::rdata::RecordData;


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
pub struct Record<N, D> {
    name: N,
    class: Class,
    ttl: i32,
    data: D
}


/// # Creation and Element Access
///
impl<N, D> Record<N, D> {
    /// Creates a new record from its parts.
    pub fn new(name: N, class: Class, ttl: i32, data: D) -> Self {
        Record { name, class, ttl, data }
    }

    /// Returns a reference to the domain name.
    ///
    /// The domain name, sometimes called the *owner* of the record,
    /// specifies the node in the DNS tree this record belongs to.
    pub fn name(&self) -> &N {
        &self.name
    }

    /// Returns the record type.
    pub fn rtype(&self) -> Rtype where D: RecordData {
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
    pub fn ttl(&self) -> i32 {
        self.ttl
    }

    /// Sets the record’s time-to-live.
    pub fn set_ttl(&mut self, ttl: i32) {
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


//--- Parsable and Composable

impl<N: Parseable, D: RecordData> Parseable for Option<Record<N, D>> {
    type Err = RecordParseError<N::Err, D::ParseErr>;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let header = RecordHeader::parse(parser)?;
        match D::parse(header.rtype(), header.rdlen() as usize, parser) {
            Ok(Some(data)) => {
                Ok(Some(header.into_record(data)))
            }
            Ok(None) => {
                parser.advance(header.rdlen() as usize)?;
                Ok(None)
            }
            Err(err) => {
                Err(RecordParseError::Data(err))
            }
        }
    }
}

impl<N: Composable, D: RecordData> Composable for Record<N, D> {
    fn compose_len(&self) -> usize {
        self.name.compose_len() + self.data.compose_len() + 10
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        RecordHeader::new(&self.name, self.data.rtype(), self.class, self.ttl,
                          (self.data.compose_len() as u16))
                     .compose(buf);
        self.data.compose(buf);
    }
}


//--- From

impl<N, D> From<(N, Class, i32, D)> for Record<N, D> {
    fn from(x: (N, Class, i32, D)) -> Self {
        Record::new(x.0, x.1, x.2, x.3)
    }
}

impl<N, D> From<(N, i32, D)> for Record<N, D> {
    fn from(x: (N, i32, D)) -> Self {
        Record::new(x.0, Class::In, x.1, x.2)
    }
}


//--- Display

impl<N, D> fmt::Display for Record<N, D>
     where N: fmt::Display, D: RecordData + fmt::Display {
   fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\t{}\t{}\t{}\t{}",
               self.name, self.ttl, self.class, self.data.rtype(),
               self.data)
    }
}


//------------ RecordHeader --------------------------------------------------

/// The header of a resource record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecordHeader<N> {
    name: N,
    rtype: Rtype,
    class: Class,
    ttl: i32,
    rdlen: u16,
}

impl<N> RecordHeader<N> {
    /// Creates a new record header from its components.
    pub fn new(name: N, rtype: Rtype, class: Class, ttl: i32, rdlen: u16)
               -> Self {
        RecordHeader { name, rtype, class, ttl, rdlen }
    }

    /// Returns a reference to the owner of the record.
    pub fn name(&self) -> &N {
        &self.name
    }

    /// Returns the record type of the record.
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// Returns the class of the record.
    pub fn class(&self) -> Class {
        self.class
    }

    /// Returns the TTL of the record.
    pub fn ttl(&self) -> i32 {
        self.ttl
    }

    /// Returns the data length of the record.
    pub fn rdlen(&self) -> u16 {
        self.rdlen
    }

    /// Converts the header into an actual record.
    pub fn into_record<D>(self, data: D) -> Record<N, D> {
        Record::new(self.name, self.class, self.ttl, data)
    }
}


//--- Parseable and Composable

impl<N: Parseable> Parseable for RecordHeader<N> {
    type Err = RecordHeaderParseError<N::Err>;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(RecordHeader::new(
                N::parse(parser).map_err(RecordHeaderParseError::Name)?,
                Rtype::parse(parser)?,
                Class::parse(parser)?,
                parser.parse_i32()?,
                parser.parse_u16()?
        ))
    }
}

impl<N: Composable> Composable for RecordHeader<N> {
    fn compose_len(&self) -> usize {
        self.name.compose_len() + 10
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.name.compose(buf);
        self.rtype.compose(buf);
        self.class.compose(buf);
        self.ttl.compose(buf);
        self.rdlen.compose(buf);
    }
}


//------------ RecordHeaderParseError ----------------------------------------

#[derive(Clone, Debug)]
pub enum RecordHeaderParseError<N> {
    Name(N),
    ShortParser,
}

impl<N> From<ShortParser> for RecordHeaderParseError<N> {
    fn from(_: ShortParser) -> Self {
        RecordHeaderParseError::ShortParser
    }
}


//------------ RecordParseError ----------------------------------------------

#[derive(Clone, Debug)]
pub enum RecordParseError<N, D> {
    Name(N),
    Data(D),
    ShortParser,
}

impl<N, D> From<RecordHeaderParseError<N>> for RecordParseError<N, D> {
    fn from(err: RecordHeaderParseError<N>) -> Self {
        match err {
            RecordHeaderParseError::Name(err) => RecordParseError::Name(err),
            RecordHeaderParseError::ShortParser => RecordParseError::ShortParser
        }
    }
}

impl<N, D> From<ShortParser> for RecordParseError<N, D> {
    fn from(_: ShortParser) -> Self {
        RecordParseError::ShortParser
    }
}

