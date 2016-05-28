//! Generic Record Data Types

use std::fmt;
use super::super::compose::ComposeBytes;
use super::super::error::{ComposeResult, ParseResult};
use super::super::iana::RRType;
use super::super::nest::Nest;
use super::super::parse::ParseBytes;
use super::traits::RecordData;

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
        use super::rfc1035::*;
        use super::rfc3596::*;

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
