//! Serial numbers.
//!
//! DNS uses 32 bit serial numbers in various places that are conceptionally
//! viewed as the 32 bit modulus of a larger number space. Because of that,
//! special rules apply when processing these values. This module provides
//! the type [`Serial`] that implements these rules.
//!
//! [`Serial`]: struct.Serial.html

use super::cmp::CanonicalOrd;
use super::octets::{
    Compose, OctetsBuilder, Parse, ParseError, Parser, ShortBuf,
};
#[cfg(feature = "master")]
use crate::master::scan::{
    CharSource, Scan, ScanError, Scanner, SyntaxError,
};
#[cfg(feature = "chrono")]
use chrono::{DateTime, TimeZone, Utc};
use core::cmp::Ordering;
use core::{cmp, fmt, str};
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

//------------ Serial --------------------------------------------------------

/// A serial number.
///
/// Serial numbers are used in DNS to track changes to resources. For
/// instance, the [`Soa`][crate::rdata::rfc1035::Soa] record type provides
/// a serial number that expresses the version of the zone. Since these
/// numbers are only 32 bits long, they
/// can wrap. [RFC 1982] defined the semantics for doing arithmetics in the
/// face of these wrap-arounds. This type implements these semantics atop a
/// native `u32`.
///
/// The RFC defines two operations: addition and comparison.
///
/// For addition, the amount added can only be a positive number of up to
/// `2^31 - 1`. Because of this, we decided to not implement the
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Serial(pub u32);

impl Serial {
    /// Returns a serial number for the current Unix time.
    #[cfg(feature = "std")]
    pub fn now() -> Self {
        let now = SystemTime::now();
        let value = match now.duration_since(UNIX_EPOCH) {
            Ok(value) => value,
            Err(_) => UNIX_EPOCH.duration_since(now).unwrap(),
        };
        Self(value.as_secs() as u32)
    }

    /// Returns the serial number as a raw integer.
    pub fn into_int(self) -> u32 {
        self.0
    }

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
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: u32) -> Self {
        assert!(other <= 0x7FFF_FFFF);
        Serial(self.0.wrapping_add(other))
    }

    /// Scan a serial represention signature time value.
    ///
    /// In [RRSIG] records, the expiration and inception times are given as
    /// serial values. Their master file format can either be the signature
    /// value or a specific date in `YYYYMMDDHHmmSS` format.
    ///
    /// [RRSIG]: ../../rdata/rfc4034/struct.Rrsig.html
    #[cfg(feature = "master")]
    pub fn scan_rrsig<C: CharSource>(
        scanner: &mut Scanner<C>,
    ) -> Result<Self, ScanError> {
        scanner.scan_phrase(
            (0, [0u8; 14]),
            |&mut (ref mut pos, ref mut buf), symbol| {
                let ch = symbol.into_digit(10)? as u8;
                if *pos == 14 {
                    return Err(SyntaxError::IllegalInteger); // XXX Not quite
                }
                buf[*pos] = ch;
                *pos += 1;
                Ok(())
            },
            |(pos, buf)| {
                if pos <= 10 {
                    // We have an integer. We generate it into a u64 to deal
                    // with possible overflows.
                    let mut res = 0u64;
                    for ch in &buf[..pos] {
                        res = res * 10 + (u64::from(*ch));
                    }
                    if res > u64::from(::std::u32::MAX) {
                        Err(SyntaxError::IllegalInteger)
                    } else {
                        Ok(Serial(res as u32))
                    }
                } else if pos == 14 {
                    let year = u32_from_buf(&buf[0..4]) as i32;
                    let month = u32_from_buf(&buf[4..6]);
                    let day = u32_from_buf(&buf[6..8]);
                    let hour = u32_from_buf(&buf[8..10]);
                    let minute = u32_from_buf(&buf[10..12]);
                    let second = u32_from_buf(&buf[12..14]);
                    match month {
                        1 | 3 | 5 | 7 | 8 | 10 | 12 => {
                            if month > 31 {
                                return Err(SyntaxError::IllegalInteger);
                            }
                        }
                        4 | 6 | 9 | 11 => {
                            if month > 30 {
                                return Err(SyntaxError::IllegalInteger);
                            }
                        }
                        2 => {
                            if year % 4 == 0 && year % 100 != 0 {
                                if month > 29 {
                                    return Err(SyntaxError::IllegalInteger);
                                }
                            } else if month > 28 {
                                return Err(SyntaxError::IllegalInteger);
                            }
                        }
                        _ => return Err(SyntaxError::IllegalInteger),
                    }
                    if month < 1 || hour > 23 || minute > 59 || second > 59 {
                        return Err(SyntaxError::IllegalInteger);
                    }
                    Ok(Serial(
                        Utc.ymd(year, month, day)
                            .and_hms(hour, minute, second)
                            .timestamp() as u32,
                    ))
                } else {
                    Err(SyntaxError::IllegalInteger) // XXX Still not quite.
                }
            },
        )
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

#[cfg(feature = "chrono")]
#[cfg_attr(docsrs, doc(cfg(feature = "chrono")))]
impl<T: TimeZone> From<DateTime<T>> for Serial {
    fn from(value: DateTime<T>) -> Self {
        Self(value.timestamp() as u32)
    }
}

impl str::FromStr for Serial {
    type Err = <u32 as str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <u32 as str::FromStr>::from_str(s).map(Into::into)
    }
}

//--- Parse and Compose

impl<T: AsRef<[u8]>> Parse<T> for Serial {
    fn parse(parser: &mut Parser<T>) -> Result<Self, ParseError> {
        u32::parse(parser).map(Into::into)
    }

    fn skip(parser: &mut Parser<T>) -> Result<(), ParseError> {
        u32::skip(parser)
    }
}

impl Compose for Serial {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        self.0.compose(target)
    }
}

//--- Scan and Display

#[cfg(feature = "master")]
impl Scan for Serial {
    fn scan<C: CharSource>(
        scanner: &mut Scanner<C>,
    ) -> Result<Self, ScanError> {
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
        match self.0.cmp(&other.0) {
            Ordering::Equal => Some(Ordering::Equal),
            Ordering::Less => {
                let sub = other.0 - self.0;
                match sub.cmp(&0x8000_0000) {
                    Ordering::Less => Some(Ordering::Less),
                    Ordering::Greater => Some(Ordering::Greater),
                    Ordering::Equal => None,
                }
            }
            Ordering::Greater => {
                let sub = self.0 - other.0;
                match sub.cmp(&0x8000_0000) {
                    Ordering::Less => Some(Ordering::Greater),
                    Ordering::Greater => Some(Ordering::Less),
                    Ordering::Equal => None,
                }
            }
        }
    }
}

impl CanonicalOrd for Serial {
    fn canonical_cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

//------------ Helper Functions ----------------------------------------------

#[cfg(feature = "master")]
fn u32_from_buf(buf: &[u8]) -> u32 {
    let mut res = 0;
    for ch in buf {
        res = res * 10 + (u32::from(*ch));
    }
    res
}

//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn good_addition() {
        assert_eq!(Serial(0).add(4), Serial(4));
        assert_eq!(
            Serial(0xFF00_0000).add(0x0F00_0000),
            Serial(
                ((0xFF00_0000u64 + 0x0F00_0000u64) % 0x1_0000_0000) as u32
            )
        );
    }

    #[test]
    #[should_panic]
    fn bad_addition() {
        let _ = Serial(0).add(0x8000_0000);
    }

    #[test]
    fn comparison() {
        use core::cmp::Ordering::*;

        assert_eq!(Serial(12), Serial(12));
        assert_ne!(Serial(12), Serial(112));

        assert_eq!(Serial(12).partial_cmp(&Serial(12)), Some(Equal));

        // s1 is said to be less than s2 if [...]
        // (i1 < i2 and i2 - i1 < 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(12).partial_cmp(&Serial(13)), Some(Less));
        assert_ne!(
            Serial(12).partial_cmp(&Serial(3_000_000_012)),
            Some(Less)
        );

        // or (i1 > i2 and i1 - i2 > 2^(SERIAL_BITS - 1))
        assert_eq!(
            Serial(3_000_000_012).partial_cmp(&Serial(12)),
            Some(Less)
        );
        assert_ne!(Serial(13).partial_cmp(&Serial(12)), Some(Less));

        // s1 is said to be greater than s2 if [...]
        // (i1 < i2 and i2 - i1 > 2^(SERIAL_BITS - 1))
        assert_eq!(
            Serial(12).partial_cmp(&Serial(3_000_000_012)),
            Some(Greater)
        );
        assert_ne!(Serial(12).partial_cmp(&Serial(13)), Some(Greater));

        // (i1 > i2 and i1 - i2 < 2^(SERIAL_BITS - 1))
        assert_eq!(Serial(13).partial_cmp(&Serial(12)), Some(Greater));
        assert_ne!(
            Serial(3_000_000_012).partial_cmp(&Serial(12)),
            Some(Greater)
        );

        // Er, I think that’s what’s left.
        assert_eq!(Serial(1).partial_cmp(&Serial(0x8000_0001)), None);
        assert_eq!(Serial(0x8000_0001).partial_cmp(&Serial(1)), None);
    }
}
