//! Record data from [RFC 2782].
//!
//! This RFC defines the Srv record type.
//!
//! [RFC 2782]: https://tools.ietf.org/html/rfc2782

use std::fmt;
use ::bits::{Composer, ComposeResult, DNameSlice, ParsedRecordData,
             Parser, ParseResult, RecordData, DName, DNameBuf, ParsedDName};
use ::iana::Rtype;
use ::master::{Scanner, ScanResult};


//------------ Srv ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Srv<N: DName> {
    priority: u16,
    weight: u16,
    port: u16,
    target: N
}

impl<N: DName> Srv<N> {
    pub fn new(priority: u16, weight: u16, port: u16, target: N) -> Self {
        Srv { priority: priority, weight: weight, port: port, target: target }
    }

    pub fn priority(&self) -> u16 { self.priority }
    pub fn weight(&self) -> u16 { self.weight }
    pub fn port(&self) -> u16 { self.port }
    pub fn target(&self) -> &N { &self.target }
}

impl<'a> Srv<ParsedDName<'a>> {
    fn parse_always(parser: &mut Parser<'a>) -> ParseResult<Self> {
        Ok(Self::new(try!(parser.parse_u16()),
                     try!(parser.parse_u16()),
                     try!(parser.parse_u16()),
                     try!(ParsedDName::parse(parser))))
    }
}

impl Srv<DNameBuf> {
    pub fn scan<S: Scanner>(scanner: &mut S, origin: Option<&DNameSlice>)
                            -> ScanResult<Self> {
        Ok(Self::new(try!(scanner.scan_u16()),
                     try!(scanner.scan_u16()),
                     try!(scanner.scan_u16()),
                     try!(DNameBuf::scan(scanner, origin))))
    }
}

impl<N: DName> RecordData for Srv<N> {
    fn rtype(&self) -> Rtype { Rtype::Srv }

    fn compose<C: AsMut<Composer>>(&self, mut target: C)
                                   -> ComposeResult<()> {
        target.as_mut().compose_u16(self.priority)?;
        target.as_mut().compose_u16(self.weight)?;
        target.as_mut().compose_u16(self.port)?;
        self.target.compose(target)
    }
}

impl<'a> ParsedRecordData<'a> for Srv<ParsedDName<'a>> {
    fn parse(rtype: Rtype, parser: &mut Parser<'a>) -> ParseResult<Option<Self>> {
        if rtype == Rtype::Srv { Srv::parse_always(parser).map(Some) }
        else { Ok(None) }
    }
}

impl<N: DName + fmt::Display> fmt::Display for Srv<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {}", self.priority, self.weight, self.port, self.target)
    }
}

