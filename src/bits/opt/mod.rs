//! Record data for OPT records.
//!
//! OPT records are meta records used by EDNS to convey additional data about
//! clients, servers, and the query being performed. Because these records are
//! fundamental for modern DNS operations, they are here instead of in the
//! `rdata` module and the types defined for operating on them differ from
//! how other record types are handled.

use std::marker::PhantomData;
use ::iana::{OptionCode, Rtype};
use super::{Composer, ComposeResult, ParsedRecordData, Parser, ParseResult,
            RecordData};


pub mod rfc5001;
pub mod rfc6975;
pub mod rfc7314;
pub mod rfc7828;
pub mod rfc7830;
pub mod rfc7871;
pub mod rfc7873;
pub mod rfc7901;
pub mod rfc8145;


//------------ Opt -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Opt<'a>(Parser<'a>);

impl<'a> Opt<'a> {
    pub fn iter<O: ParsedOptData<'a>>(&self) -> OptIter<'a, O> {
        OptIter::new(self.0.clone())
    }
}

impl<'a> RecordData for Opt<'a> {
    fn rtype(&self) -> Rtype {
        Rtype::Opt
    }

    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        // Technically, there shouldn’t be name compression in OPT record
        // data. So we should be fine just copying the data verbatim.
        target.as_mut().compose_bytes(self.0.bytes())
    }
}


impl<'a> ParsedRecordData<'a> for Opt<'a> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if rtype == Rtype::Opt {
            Ok(Some(Opt(parser.clone())))
        }
        else {
            Ok(None)
        }
    }
}


//------------ OptIter -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OptIter<'a, O: ParsedOptData<'a>> { 
    parser: Parser<'a>,
    marker: PhantomData<O>
}

impl<'a, O: ParsedOptData<'a>> OptIter<'a, O> {
    fn new(parser: Parser<'a>) -> Self {
        OptIter { parser, marker: PhantomData }
    }
}

impl<'a, O: ParsedOptData<'a>> Iterator for OptIter<'a, O> {
    type Item = ParseResult<O>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.parser.remaining() > 0 {
            match self.next_step() {
                Ok(Some(res)) => return Some(Ok(res)),
                Ok(None) => { }
                Err(err) => return Some(Err(err)),
            }
        }
        None
    }
}

impl<'a, O: ParsedOptData<'a>> OptIter<'a, O> {
    fn next_step(&mut self) -> ParseResult<Option<O>> {
        let code = self.parser.parse_u16()?.into();
        let len = self.parser.parse_u16()? as usize;
        self.parser.set_limit(len)?;
        O::parse(code, &mut self.parser)
    }
}


//------------ OptData -------------------------------------------------------

pub trait OptData: Sized {
    fn compose<C: AsMut<Composer>>(&self, target: C) -> ComposeResult<()>;
}


pub trait ParsedOptData<'a>: OptData {
    fn parse(code: OptionCode, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>>;
}


