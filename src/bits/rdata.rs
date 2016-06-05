//! Basic resource data handling.
//!
//! DNS resource records consist of some common start defining the domain
//! name they pertain to, their type and class, and finally record data
//! the format of which depends on the specific record type. As there are
//! currently more than eighty record types, having a giant enum for record
//! data seemed like a bad idea. Instead, resource records are generic over
//! the `RecordData` trait which is being implemented by all concrete
//! record data types—these are defined in module `domain::rdata`.
//!
//! In order to walk over all resource records in a message or work with
//! unknown record types, this module also defines the `GenericRecordData`
//! type that can deal with all record types.

use std::fmt;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
use super::iana::RRType;
use super::nest::Nest;
use super::parse::ParseBytes;


///----------- RecordData ------------------------------------------------

/// A trait for parsing and composing record data.
pub trait RecordData<'a>: fmt::Display + Sized {
    /// Returns the record type for this record data instance.
    fn rtype(&self) -> RRType;

    /// Appends the record data to the end of compose target.
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()>;

    /// Parse the record data from a cursor if the type is right.
    ///
    /// If this record data type does not feel responsible for records of
    /// type `rtype`, it should return `None` an leave the parser untouche.
    /// Otherwise it should return a value or an error if parsing fails.
    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a>;
}


//------------ GenericRecordData --------------------------------------------

/// A type for any type of record data.
///
/// This type accepts any record type and stores the plain binary data in
/// form of a `Nest`. This way, it can provide a parser for converting the
/// data into into concrete record data type if necessary.
///
/// Since values may be built from messages, the data may contain compressed
/// domain names. When composing a new message, this may lead to corrupt
/// messages when simply pushing the data as is. However, the type follows
/// RFC 3597, ‘Handling of Unknown DNS Resource Record (RR) Types,’ and
/// assumes that compressed domain names only occur in record types defined
/// in RFC 1035. When composing, it treats those values specially ensuring
/// that compressed names are handled correctly. This may still lead to
/// corrupt messages, however, if the generic record data is obtained from
/// a source not complying with RFC 3597. In general, be wary when
/// re-composing parsed messages unseen.
#[derive(Clone, Debug)]
pub struct GenericRecordData<'a> {
    rtype: RRType,
    data: Nest<'a>,
}

impl<'a> GenericRecordData<'a> {
    /// Creates a generic record data value from its components.
    pub fn new(rtype: RRType, data: Nest<'a>) -> Self {
        GenericRecordData { rtype: rtype, data: data }
    }

    /// Returns the record type of the generic record data value.
    pub fn rtype(&self) -> RRType { self.rtype }

    /// Returns a reference to the value’s data.
    pub fn data(&self) -> &Nest { &self.data }

    /// Tries to re-parse the value for the concrete type `R`.
    ///
    /// Returns `None` if `R` does not want to parse the value.
    pub fn concrete<'b, R: RecordData<'b>>(&'b self) -> Option<ParseResult<R>> {
        let mut parser = self.data.parser();
        R::parse(self.rtype, &mut parser)
    }

    /// Formats the record data as if it were of concrete type `R`.
    pub fn fmt<'b: 'a, R: RecordData<'a>>(&'b self, f: &mut fmt::Formatter)
                                  -> fmt::Result {
        let mut parser = self.data.parser();
        match R::parse(self.rtype, &mut parser) {
            Some(Ok(data)) => data.fmt(f),
            Some(Err(..)) => Ok(()),
            None => Ok(())
        }
    }
}


impl<'a> RecordData<'a> for GenericRecordData<'a> {
    fn rtype(&self) -> RRType {
        self.rtype
    }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        self.data.compose(target)
    }

    fn parse<P>(rtype: RRType, parser: &mut P) -> Option<ParseResult<Self>>
             where P: ParseBytes<'a> {
        let len = parser.left();
        match parser.parse_nest(len) {
            Err(err) => Some(Err(err)),
            Ok(nest) => Some(Ok(GenericRecordData::new(rtype, nest)))
        }
    }
}


impl<'a> fmt::Display for GenericRecordData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use rdata::*;

        match self.rtype {
            // RFC 1035
            RRType::A => self.fmt::<A>(f),
            RRType::CNAME => self.fmt::<CName>(f),
            RRType::HINFO => self.fmt::<HInfo>(f),
            RRType::MB => self.fmt::<MB>(f),
            RRType::MD => self.fmt::<MD>(f),
            RRType::MF => self.fmt::<MF>(f),
            RRType::MG => self.fmt::<MG>(f),
            RRType::MINFO => self.fmt::<MInfo>(f),
            RRType::MR => self.fmt::<MR>(f),
            RRType::MX => self.fmt::<MX>(f),
            RRType::NS => self.fmt::<NS>(f),
            RRType::NULL => self.fmt::<Null>(f),
            RRType::PTR => self.fmt::<Ptr>(f),
            RRType::SOA => self.fmt::<Soa>(f),
            RRType::TXT => self.fmt::<Txt>(f),
            RRType::WKS => self.fmt::<Wks>(f),

            // RFC 3596
            RRType::AAAA => self.fmt::<AAAA>(f),

            // Unknown
            _ => "...".fmt(f)
        }
    }
}


impl<'a> PartialEq for GenericRecordData<'a> {
    /// Compares two generic record data values for equality.
    ///
    /// Almost all record types can be compared bitwise. However, record
    /// types from RFC 1035 may employ name compression if they contain
    /// domain names. For these we need to actually check.
    fn eq(&self, other: &Self) -> bool {
        if self.rtype != other.rtype { false }
        else {
            use rdata::rfc1035::*;

            match self.rtype {
                RRType::CNAME => rdata_eq::<CName>(self, other),
                RRType::MB => rdata_eq::<MB>(self, other),
                RRType::MD => rdata_eq::<MD>(self, other),
                RRType::MF => rdata_eq::<MF>(self, other),
                RRType::MG => rdata_eq::<MG>(self, other),
                RRType::MINFO => rdata_eq::<MInfo>(self, other),
                RRType::MR => rdata_eq::<MR>(self, other),
                RRType::MX => rdata_eq::<MX>(self, other),
                RRType::NS => rdata_eq::<NS>(self, other),
                RRType::PTR => rdata_eq::<Ptr>(self, other),
                RRType::SOA => rdata_eq::<Soa>(self, other),
                RRType::TXT => rdata_eq::<Txt>(self, other),
                _ => self.data.as_bytes() == other.data.as_bytes()
            }
        }
    }
}

/// Parse and then compare with concrete type.
fn rdata_eq<'a, D>(left: &'a GenericRecordData<'a>,
                   right: &'a GenericRecordData<'a>) -> bool
            where D: RecordData<'a> + PartialEq {
    D::parse(left.rtype, &mut left.data.parser())
        == D::parse(right.rtype, &mut right.data.parser())
}

