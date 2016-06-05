//! Basic resource data handling.

use std::fmt;
use super::compose::ComposeBytes;
use super::error::{ComposeResult, ParseResult};
use super::iana::RRType;
use super::nest::Nest;
use super::parse::ParseBytes;


/// A trait for creating record data.
pub trait RecordData<'a>: fmt::Display + Sized {
    /// Returns the record type for this record data instance.
    fn rtype(&self) -> RRType;

    /// Appends the record data to the end of a buffer.
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()>;

    /// Parse the record data from a cursor if the type is right.
    ///
    /// If this record data type does not feel responsible for records of
    /// type `rtype`, it should return `Ok(None)`. Otherwise it should
    /// return something or an error if parsing fails.
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseBytes<'a>;
}

#[derive(Clone, Debug)]
pub struct GenericRecordData<'a> {
    rtype: RRType,
    data: Nest<'a>,
}

impl<'a> GenericRecordData<'a> {
    pub fn new(rtype: RRType, data: Nest<'a>) -> Self {
        GenericRecordData { rtype: rtype, data: data }
    }

    pub fn rtype(&self) -> RRType { self.rtype }
    pub fn data(&self) -> &Nest { &self.data }

    pub fn fmt<'b: 'a, R: RecordData<'a>>(&'b self, f: &mut fmt::Formatter)
                                  -> fmt::Result {
        let mut parser = self.data.parser();
        match R::parse(self.rtype, &mut parser) {
            Err(..) => Ok(()),
            Ok(None) => Ok(()),
            Ok(Some(data)) => data.fmt(f)
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

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseBytes<'a> {
        let len = parser.left();
        let nest = try!(parser.parse_nest(len));
        Ok(Some(GenericRecordData::new(rtype, nest)))
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
            RRType::SOA => self.fmt::<SOA>(f),
            RRType::TXT => self.fmt::<Txt>(f),
            RRType::WKS => self.fmt::<WKS>(f),

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
                RRType::SOA => rdata_eq::<SOA>(self, other),
                RRType::TXT => rdata_eq::<Txt>(self, other),
                _ => self.data.as_bytes() == other.data.as_bytes()
            }
        }
    }
}

fn rdata_eq<'a, D>(left: &'a GenericRecordData<'a>,
                   right: &'a GenericRecordData<'a>) -> bool
            where D: RecordData<'a> + PartialEq {
    D::parse(left.rtype, &mut left.data.parser())
        == D::parse(right.rtype, &mut right.data.parser())
}

impl<'a> Eq for GenericRecordData<'a> { }

