//! Record data from [RFC 3596].
//!
//! This RFC defines the Aaaa record type.
//!
//! [RFC 3596]: https://tools.ietf.org/html/rfc3596

use std::{fmt, io, ops};
use std::io::Write;
use std::net::Ipv6Addr;
use std::str::FromStr;
use bytes::BufMut;
use ::bits::compose::{Compose, Compress, Compressor};
use ::bits::parse::{Parse, ParseAll, Parser, ShortBuf};
use ::bits::rdata::RtypeRecordData;
use ::iana::Rtype;
use ::master::print::{Print, Printer};
use ::master::scan::{CharSource, Scan, Scanner, ScanError};


//------------ Aaaa ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Aaaa {
    addr: Ipv6Addr
}

impl Aaaa {
    pub fn new(addr: Ipv6Addr) -> Aaaa {
        Aaaa { addr: addr }
    }

    pub fn addr(&self) -> Ipv6Addr { self.addr }
    pub fn set_addr(&mut self, addr: Ipv6Addr) { self.addr = addr }
}


//--- From and FromStr

impl From<Ipv6Addr> for Aaaa {
    fn from(addr: Ipv6Addr) -> Self {
        Self::new(addr)
    }
}

impl From<Aaaa> for Ipv6Addr {
    fn from(data: Aaaa) -> Self {
        data.addr
    }
}

impl FromStr for Aaaa {
    type Err = <Ipv6Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv6Addr::from_str(s).map(Aaaa::new)
    }
}


//--- Parse, ParseAll, Compose, and Compress

impl Parse for Aaaa {
    type Err = <Ipv6Addr as Parse>::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        Ipv6Addr::parse(parser).map(Self::new)
    }
}

impl ParseAll for Aaaa {
    type Err = <Ipv6Addr as ParseAll>::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        Ipv6Addr::parse_all(parser, len).map(Self::new)
    }
}

impl Compose for Aaaa {
    fn compose_len(&self) -> usize {
        16
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.addr.compose(buf)
    }
}

impl Compress for Aaaa {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compose(self)
    }
}


//--- Scan and Print

impl Scan for Aaaa {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_string_phrase(|res| {
            Aaaa::from_str(&res).map_err(Into::into)
        })
    }
}

impl Print for Aaaa {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        write!(printer.item()?, "{}", self.addr)
    }
}


//--- RecordData

impl RtypeRecordData for Aaaa {
    const RTYPE: Rtype = Rtype::Aaaa;
}


//--- Deref and DerefMut

impl ops::Deref for Aaaa {
    type Target = Ipv6Addr;

    fn deref(&self) -> &Self::Target {
        &self.addr
    }
}

impl ops::DerefMut for Aaaa {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.addr
    }
}


//--- AsRef and AsMut

impl AsRef<Ipv6Addr> for Aaaa {
    fn as_ref(&self) -> &Ipv6Addr {
        &self.addr
    }
}

impl AsMut<Ipv6Addr> for Aaaa {
    fn as_mut(&mut self) -> &mut Ipv6Addr {
        &mut self.addr
    }
}


//--- Display

impl fmt::Display for Aaaa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}


//------------ parsed --------------------------------------------------------

pub mod parsed {
    pub use super::Aaaa;
}
