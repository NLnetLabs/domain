//! Generic Record Data Types

use std::fmt;
use super::super::compose::ComposeBytes;
use super::super::flavor::FlatFlavor;
use super::super::error::{ComposeResult, ParseResult};
use super::super::iana::RRType;
use super::super::nest::{FlatNest, Nest};
use super::super::parse::ParseFlavor;
use super::traits::{FlatRecordData, RecordData};


pub struct GenericRecordData<'a, F: FlatFlavor<'a>> {
    rtype: RRType,
    data: F::FlatNest,
}

impl<'a, F: FlatFlavor<'a>> GenericRecordData<'a, F> {
    pub fn new(rtype: RRType, data: F::FlatNest) -> Self {
        GenericRecordData { rtype: rtype, data: data }
    }

    pub fn rtype(&self) -> RRType { self.rtype }
    pub fn data(&self) -> &F::FlatNest { &self.data }

    pub fn fmt<R: FlatRecordData<'a, F>>(&self, f: &mut fmt::Formatter)
                                         -> fmt::Result {
        let mut parser = self.data.parser();
        match R::parse(self.rtype, &mut parser) {
            Err(..) => Ok(()),
            Ok(None) => Ok(()),
            Ok(Some(data)) => data.fmt(f)
        }
    }
}


impl<'a, F: FlatFlavor<'a>> RecordData<F> for GenericRecordData<'a, F> {

    fn rtype(&self) -> RRType {
        self.rtype
    }

    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        self.data.compose(target)
    }
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for GenericRecordData<'a, F> {

    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        let len = parser.left();
        let nest = try!(parser.parse_nest(len));
        Ok(Some(GenericRecordData::new(rtype, nest)))
    }
}


impl<'a, F: FlatFlavor<'a>> fmt::Display for GenericRecordData<'a, F> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use super::rfc1035::*;
        use super::rfc3596::*;

        match self.rtype {
            // RFC 1035
            RRType::A => self.fmt::<A>(f),
            RRType::CNAME => self.fmt::<CName<F>>(f),
            RRType::HINFO => self.fmt::<HInfo<F>>(f),
            RRType::MB => self.fmt::<MB<F>>(f),
            RRType::MD => self.fmt::<MD<F>>(f),
            RRType::MF => self.fmt::<MF<F>>(f),
            RRType::MG => self.fmt::<MG<F>>(f),
            RRType::MINFO => self.fmt::<MInfo<F>>(f),
            RRType::MR => self.fmt::<MR<F>>(f),
            RRType::MX => self.fmt::<MX<F>>(f),
            RRType::NS => self.fmt::<NS<F>>(f),
            RRType::NULL => self.fmt::<Null<F>>(f),
            RRType::PTR => self.fmt::<Ptr<F>>(f),
            RRType::SOA => self.fmt::<SOA<F>>(f),
            RRType::TXT => self.fmt::<Txt<F>>(f),
            RRType::WKS => self.fmt::<WKS<F>>(f),

            // RFC 3596
            RRType::AAAA => self.fmt::<AAAA>(f),
            _ => "...".fmt(f)
        }
    }
}
