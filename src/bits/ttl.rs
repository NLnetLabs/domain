//! TTL values.

use std::{fmt, io};
use std::io::Write;
use bytes::BufMut;
use master::error::{ScanError};
use master::print::{Printable, Printer};
use master::scan::{CharSource, Scannable, Scanner};
use super::compose::Composable;
use super::error::ShortBuf;
use super::parse::{Parseable, Parser};


//------------ Ttl -----------------------------------------------------------

/// A Time-to-live value.
///
/// TTL values are defined as unsigned 16 bit integers that are never negative
/// by RFC 1035. This type is a thin wrapper around `i16` that enforces this
/// restriction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Ttl(i16);


//--- Parseable and Composable

impl Parseable for Ttl {
    type Err = ParseTtlError;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let res = parser.parse_i16()?;
        if res < 0 {
            Err(ParseTtlError::Negative(res))
        }
        else {
            Ok(Ttl(res))
        }
    }
}

impl Composable for Ttl {
    fn compose_len(&self) -> usize {
        2
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.0.compose(buf)
    }
}


//--- Scannable and Printable

impl Scannable for Ttl {
    fn scan<C: CharSource>(_scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        unimplemented!()
    }
}

impl Printable for Ttl {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        write!(printer.item()?, "{}", self)
    }
}


//--- Display

impl fmt::Display for Ttl {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
    }
}


//------------ ParseTtlError -------------------------------------------------

/// An error happend while parsing a TTL value.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum ParseTtlError {
    #[fail(display="unexpected end of buffer")]
    ShortBuf,

    #[fail(display="negative TTL {}", _0)]
    Negative(i16)
}

impl From<ShortBuf> for ParseTtlError {
    fn from(_: ShortBuf) -> Self {
        ParseTtlError::ShortBuf
    }
}
