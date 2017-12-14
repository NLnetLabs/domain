//! Record data from [RFC 2782].
//!
//! This RFC defines the Srv record type.
//!
//! [RFC 2782]: https://tools.ietf.org/html/rfc2782

use std::{fmt, io};
use bytes::BufMut;
use ::bits::compose::{Compose, Compress, Compressor};
use ::bits::parse::{Parse, ParseAll, Parser, ParseOpenError, ShortBuf};
use ::bits::rdata::RtypeRecordData;
use ::master::print::{Print, Printer};
use ::master::scan::{CharSource, Scan, Scanner, ScanError};
use ::iana::Rtype;


//------------ Srv ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Srv<N> {
    priority: u16,
    weight: u16,
    port: u16,
    target: N
}

impl<N> Srv<N> {
    pub const RTYPE: Rtype = Rtype::Srv;

    pub fn new(priority: u16, weight: u16, port: u16, target: N) -> Self {
        Srv { priority: priority, weight: weight, port: port, target: target }
    }

    pub fn priority(&self) -> u16 { self.priority }
    pub fn weight(&self) -> u16 { self.weight }
    pub fn port(&self) -> u16 { self.port }
    pub fn target(&self) -> &N { &self.target }
}


//--- Parse, ParseAll, Compose and Compress

impl<N: Parse> Parse for Srv<N> {
    type Err = <N as Parse>::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ok(Self::new(u16::parse(parser)?, u16::parse(parser)?,
                     u16::parse(parser)?, N::parse(parser)?))
    }
}

impl<N: ParseAll> ParseAll for Srv<N> where N::Err: From<ParseOpenError> {
    type Err = N::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len < 7 {
            return Err(ParseOpenError::ShortField.into())
        }
        Ok(Self::new(u16::parse(parser)?, u16::parse(parser)?,
                     u16::parse(parser)?, N::parse_all(parser, len - 6)?))
    }
}

impl<N: Compose> Compose for Srv<N> {
    fn compose_len(&self) -> usize {
        self.target.compose_len() + 6
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.priority.compose(buf);
        self.weight.compose(buf);
        self.port.compose(buf);
        self.target.compose(buf);
    }
}

impl<N: Compress> Compress for Srv<N> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(&self.priority)?;
        buf.compose(&self.weight)?;
        buf.compose(&self.port)?;
        self.target.compress(buf)
    }
}


//--- RtypeRecordData

impl<N> RtypeRecordData for Srv<N> {
    const RTYPE: Rtype = Rtype::Srv;
}


//--- Scan, Print, and Display

impl<N: Scan> Scan for Srv<N> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        Ok(Self::new(u16::scan(scanner)?, u16::scan(scanner)?,
                     u16::scan(scanner)?, N::scan(scanner)?))
    }
}

impl<N: Print> Print for Srv<N> {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        self.priority.print(printer)?;
        self.weight.print(printer)?;
        self.port.print(printer)?;
        self.target.print(printer)
    }
}

impl<N: fmt::Display> fmt::Display for Srv<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {}", self.priority, self.weight, self.port,
               self.target)
    }
}


//------------ parsed --------------------------------------------------------

pub mod parsed {
    use ::bits::name::ParsedDname;

    pub type Srv = super::Srv<ParsedDname>;
}

