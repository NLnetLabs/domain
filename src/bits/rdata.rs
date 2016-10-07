//! Basic resource data handling.

use std::fmt;
use ::iana::Rtype;
use ::rdata::fmt_rdata;
use super::{Composer, ComposeResult, Parser, ParseResult};


//----------- RecordData -----------------------------------------------------

pub trait RecordData: Sized {
    /// Returns the record type for this record data instance.
    fn rtype(&self) -> Rtype;

    /// Appends the record data to the end of a composer.
    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()>;
}


//------------ ParsedRecordData ----------------------------------------------

pub trait ParsedRecordData<'a>: RecordData {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>>;
}


//------------ GenericRecordData --------------------------------------------

#[derive(Clone, Debug)]
pub struct GenericRecordData<'a> {
    rtype: Rtype,
    parser: Parser<'a>,
}

impl<'a> GenericRecordData<'a> {
    fn reparse<D: ParsedRecordData<'a>>(&self) -> ParseResult<D> {
        D::parse(self.rtype, &mut self.parser.clone()).map(Option::unwrap)
    }
}

impl<'a> RecordData for GenericRecordData<'a> {
    fn rtype(&self) -> Rtype {
        self.rtype
    }

    fn compose<C: AsMut<Composer>>(&self, target: C) -> ComposeResult<()> {
        use ::rdata::rfc1035::parsed::*;

        match self.rtype {
            Rtype::A => try!(self.reparse::<A>()).compose(target),
            _ => unimplemented!()
        }
    }
}

impl<'a> ParsedRecordData<'a> for GenericRecordData<'a> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        let my_parser = parser.clone();
        let len = parser.remaining();
        try!(parser.skip(len));
        Ok(Some(GenericRecordData {
            rtype: rtype,
            parser: my_parser
        }))
    }
}

impl<'a> fmt::Display for GenericRecordData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt_rdata(self.rtype, &mut self.parser.clone(), f)
    }
}

