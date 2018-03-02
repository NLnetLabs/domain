//! Serial numbers.
//!
//! This module define a type [`Serial`] that wraps a `u32` to provide
//! serial number arithmetics.
//!
//! [`Serial`]: struct.Serial.html

use std::{cmp, fmt, str};
use bytes::BufMut;
use ::master::scan::{CharSource, Scan, ScanError, Scanner};
use super::compose::Compose;
use super::parse::{Parse, ParseAll, Parser};


//------------ Serial --------------------------------------------------------

/// A serial number.
///
/// Serial numbers are used in DNS to track changes to resources. For
/// instance, the [`Soa`] record type provides a serial number that expresses
/// the version of the zone. Since these numbers are only 32 bits long, they
/// can wrap. [RFC 1982] defined the semantics for doing arithmetics in the
/// face of these wrap-arounds. This type implements these semantics atop a
/// native `u32`.
///
/// The RFC defines addition and comparison. Addition, however, is only
/// defined for values up to `2^31 - 1`, so we decided to not implement the
/// `Add` trait but rather have a dedicated method `add` so as to not cause
/// surprise panics.
/// 
/// Serial numbers only implement a partial ordering. That is, there are
/// pairs of values that are not equal but there still isn’t one value larger
/// than the other. Since this is neatly implemented by the `PartialOrd`
/// trait, the type implements that.
///
/// [RFC 1982]: https://tools.ietf.org/html/rfc1982
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Serial(pub u32);

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
        assert!(other <= 0x7FFF_FFFF);
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

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        u32::skip(parser)
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


//--- Scan and Display

impl Scan for Serial {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        u32::scan(scanner).map(Into::into)
    }
}

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
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
            if sub < 0x8000_0000 {
                Some(cmp::Ordering::Less)
            }
            else if sub > 0x8000_0000 {
                Some(cmp::Ordering::Greater)
            }
            else {
                None
            }
        }
        else {
            let sub = self.0 - other.0;
            if sub < 0x8000_0000 {
                Some(cmp::Ordering::Greater)
            }
            else if sub > 0x8000_0000 {
                Some(cmp::Ordering::Less)
            }
            else {
                None
            }
        }
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn good_addition() {
        assert_eq!(Serial(0).add(4), Serial(4));
        assert_eq!(Serial(0xFF00_0000).add(0x0F00_0000),
                   Serial(((0xFF00_0000u64 + 0x0F00_0000u64)
                           % 0x1_0000_0000) as u32));
    }

    #[test]
    #[should_panic]
    fn bad_addition() {
        let _ = Serial(0).add(0x8000_0000);
    }

    #[test]
    fn comparison() {
        use std::cmp::Ordering::*;

        assert_eq!(Serial(12), Serial(12));
        assert_ne!(Serial(12), Serial(112));

        assert_eq!(Serial(12).partial_cmp(&Serial(12)), Some(Equal));

        // s1 is said to be less than s2 if [...]
        // (i1 < i2 and i2 - i1 < 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(12).partial_cmp(&Serial(13)), Some(Less));
        assert_ne!(Serial(12).partial_cmp(&Serial(3_000_000_012)), Some(Less));

        // or (i1 > i2 and i1 - i2 > 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(3_000_000_012).partial_cmp(&Serial(12)), Some(Less));
        assert_ne!(Serial(13).partial_cmp(&Serial(12)), Some(Less));

        // s1 is said to be greater than s2 if [...]
        // (i1 < i2 and i2 - i1 > 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(12).partial_cmp(&Serial(3_000_000_012)),
                   Some(Greater));
        assert_ne!(Serial(12).partial_cmp(&Serial(13)), Some(Greater));

        // (i1 > i2 and i1 - i2 < 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(13).partial_cmp(&Serial(12)), Some(Greater));
        assert_ne!(Serial(3_000_000_012).partial_cmp(&Serial(12)),
                   Some(Greater));
        
        // Er, I think that’s what’s left.
        assert_eq!(Serial(1).partial_cmp(&Serial(0x8000_0001)), None);
        assert_eq!(Serial(0x8000_0001).partial_cmp(&Serial(1)), None);
    }
}
