//! Serial numbers.

use std::{cmp, fmt, io, str};
use bytes::BufMut;
use ::master::scan::{CharSource, Scannable, ScanError, Scanner};
use ::master::print::{Printable, Printer};
use super::compose::Compose;
use super::parse::{Parse, ParseAll, Parser};


//------------ Serial --------------------------------------------------------

/// A serial number.
///
/// This type wraps a `u32` providing the semantics for serial number
/// arithmetics defined in [RFC 1982]. Only addition and comparison are
/// defined. However, addition is only defined for values up to `2^31 - 1`,
/// so we decided to not implement the `Add` trait but rather have a dedicated
/// method `add` so as to not cause surprise panics.
/// 
/// Serial numbers only implement a partial ordering. That is, there are
/// pairs of values that are not equal but there still isn’t one value larger
/// than the other. Since this is neatly implemented by the `PartialOrd`
/// trait, the type implements that.
///
/// [RFC 1982]: https://tools.ietf.org/html/rfc1982
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Serial(u32);

impl Serial {
    /// Add `other` to `self`.
    ///
    /// Serial numbers only allow values of up to `2^31 - 1` to be added to
    /// them. Therefore, this method requires `other` to be a `u32` instead
    /// of a `Serial` to indicate that you cannot simply add two serials
    /// together. This is also why we don’t implement the `Add` trait.
    ///
    /// # Panics
    ///
    /// This method panics if `other` is greater than `2^31 - 1`.
    pub fn add(self, other: u32) -> Self {
        assert!(other <= 2^31 - 1);
        Serial(self.0.wrapping_add(other))
    }
}


//--- From and FromStr

impl From<u32> for Serial {
    fn from(value: u32) -> Serial {
        Serial(value)
    }
}

impl From<Serial> for u32 {
    fn from(serial: Serial) -> u32 {
        serial.0
    }
}

impl str::FromStr for Serial {
    type Err = <u32 as str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <u32 as str::FromStr>::from_str(s).map(Into::into)
    }
}


//--- Parse, ParseAll, and Compose

impl Parse for Serial {
    type Err = <u32 as Parse>::Err;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        u32::parse(parser).map(Into::into)
    }
}

impl ParseAll for Serial {
    type Err = <u32 as ParseAll>::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        u32::parse_all(parser, len).map(Into::into)
    }
}

impl Compose for Serial {
    fn compose_len(&self) -> usize {
        self.0.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.0.compose(buf)
    }
}


//--- Scannable and Printable

impl Scannable for Serial {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        u32::scan(scanner).map(Into::into)
    }
}

impl Printable for Serial {
    fn print<W: io::Write>(&self, printer: &mut Printer<W>)
                           -> Result<(), io::Error> {
        self.0.print(printer)
    }
}


//--- PartialOrd

impl cmp::PartialOrd for Serial {
    fn partial_cmp(&self, other: &Serial) -> Option<cmp::Ordering> {
        if self.0 == other.0 {
            Some(cmp::Ordering::Equal)
        }
        else if self.0 < other.0 {
            let sub = other.0 - self.0;
            if sub < 2^31 {
                Some(cmp::Ordering::Less)
            }
            else if sub > 2^31 {
                Some(cmp::Ordering::Greater)
            }
            else {
                None
            }
        }
        else {
            let sub = self.0 - other.0;
            if sub < 2^31 {
                Some(cmp::Ordering::Greater)
            }
            else if sub > 2^31 {
                Some(cmp::Ordering::Less)
            }
            else {
                None
            }
        }
    }
}


//--- Display

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

