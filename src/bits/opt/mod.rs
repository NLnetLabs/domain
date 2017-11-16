//! Record data for OPT records.
//!
//! OPT records are meta records used by EDNS to convey additional data about
//! clients, servers, and the query being performed. Because these records are
//! fundamental for modern DNS operations, they are here instead of in the
//! `rdata` module and the types defined for operating on them differ from
//! how other record types are handled.

use bytes::{BufMut, Bytes};
use std::marker::PhantomData;
use ::iana::{OptionCode, Rtype};
use super::compose::{Composable, Compressable, Compressor};
use super::parse::{Parser, ShortParser};
use super::rdata::RecordData;


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
pub struct Opt {
    bytes: Bytes,
}

impl Opt {
    pub fn from_bytes(bytes: Bytes) -> Result<Self, ShortParser> {
        let mut parser = Parser::from_bytes(bytes);
        while parser.remaining() > 0 {
            parser.advance(2)?;
            let len = parser.parse_u16()?;
            parser.advance(len as usize)?;
        }
        Ok(Opt { bytes: parser.unwrap() })
    }

    pub fn iter<D: OptData>(&self) -> OptIter<D> {
        OptIter::new(self.bytes.clone())
    }
}

impl RecordData for Opt {
    type ParseErr = ShortParser;

    fn rtype(&self) -> Rtype {
        Rtype::Opt
    }

    fn parse(rtype: Rtype, rdlen: usize, parser: &mut Parser)
             -> Result<Option<Self>, Self::ParseErr> {
        if rtype != Rtype::Opt {
            return Ok(None)
        }
        Self::from_bytes(parser.parse_bytes(rdlen)?).map(Some)
    }
}

impl Composable for Opt {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.bytes.as_ref())
    }
}

impl Compressable for Opt {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortParser> {
        buf.compose(self)
    }
}


//------------ OptIter -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct OptIter<D: OptData> { 
    parser: Parser,
    marker: PhantomData<D>
}

impl<D: OptData> OptIter<D> {
    fn new(bytes: Bytes) -> Self {
        OptIter { parser: Parser::from_bytes(bytes), marker: PhantomData }
    }
}

impl<D: OptData> Iterator for OptIter<D> {
    type Item = Result<D, D::ParseErr>;

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

impl<D: OptData> OptIter<D> {
    fn next_step(&mut self) -> Result<Option<D>, D::ParseErr> {
        let code = self.parser.parse_u16().unwrap().into();
        let len = self.parser.parse_u16().unwrap() as usize;
        D::parse(code, len, &mut self.parser)
    }
}


//------------ OptData -------------------------------------------------------

pub trait OptData: Composable + Sized {
    type ParseErr;

    fn code(&self) -> OptionCode;

    fn parse(code: OptionCode, len: usize, parser: &mut Parser)
             -> Result<Option<Self>, Self::ParseErr>;
}


//------------ OptionParseError ---------------------------------------------

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum OptionParseError {
    InvalidLength(usize),
    ShortBuf,
}

impl From<ShortParser> for OptionParseError {
    fn from(_: ShortParser) -> Self {
        OptionParseError::ShortBuf
    }
}

