//! Serial numbers.
//!
//! DNS uses 32 bit serial numbers in various places that are conceptionally
//! viewed as the 32 bit modulus of a larger number space. Because of that,
//! special rules apply when processing these values. This module provides
//! the type [`Serial`] that implements these rules.
//!
//! [`Serial`]: struct.Serial.html

use super::cmp::CanonicalOrd;
use super::scan::{Scan, Scanner, ScannerError};
use super::wire::{Compose, Composer, Parse, ParseError};
#[cfg(feature = "chrono")]
use chrono::{DateTime, TimeZone};
use octseq::parse::Parser;
use core::cmp::Ordering;
use core::convert::TryFrom;
use core::str::FromStr;
use core::{cmp, fmt, str};
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};
use time::{Date, Month, PrimitiveDateTime, Time};

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

    pub fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Error> {
        u32::scan(scanner).map(Into::into)
    }

    /// Scan a serial represention signature time value.
    ///
    /// In [RRSIG] records, the expiration and inception times are given as
    /// serial values. Their representation format can either be the
    /// value or a specific date in `YYYYMMDDHHmmSS` format.
    ///
    /// [RRSIG]: ../../rdata/rfc4034/struct.Rrsig.html
    pub fn scan_rrsig<S: Scanner>(scanner: &mut S) -> Result<Self, S::Error> {
        let mut pos = 0;
        let mut buf = [0u8; 14];
        scanner.scan_symbols(|symbol| {
            if pos >= 14 {
                return Err(S::Error::custom("illegal signature time"));
            }
            buf[pos] = symbol
                .into_digit(10)
                .map_err(|_| S::Error::custom("illegal signature time"))?
                as u8;
            pos += 1;
            Ok(())
        })?;
        if pos <= 10 {
            // We have an integer. We generate it into a u64 to deal
            // with possible overflows.
            let mut res = 0u64;
            for ch in &buf[..pos] {
                res = res * 10 + (u64::from(*ch));
            }
            if res > u64::from(u32::MAX) {
                Err(S::Error::custom("illegal signature time"))
            } else {
                Ok(Serial(res as u32))
            }
        } else if pos == 14 {
            let year = u32_from_buf(&buf[0..4]) as i32;
            let month = Month::try_from(u8_from_buf(&buf[4..6]))
                .map_err(|_| S::Error::custom("illegal signature time"))?;
            let day = u8_from_buf(&buf[6..8]);
            let hour = u8_from_buf(&buf[8..10]);
            let minute = u8_from_buf(&buf[10..12]);
            let second = u8_from_buf(&buf[12..14]);
            Ok(Serial(
                PrimitiveDateTime::new(
                    Date::from_calendar_date(year, month, day).map_err(
                        |_| S::Error::custom("illegal signature time"),
                    )?,
                    Time::from_hms(hour, minute, second).map_err(|_| {
                        S::Error::custom("illegal signature time")
                    })?,
                )
                .assume_utc()
                .unix_timestamp() as u32,
            ))
        } else {
            Err(S::Error::custom("illegal signature time"))
        }
    }

    /// Parses a serial representing a time value from a string.
    ///
    /// In [RRSIG] records, the expiration and inception times are given as
    /// serial values. Their representation format can either be the
    /// value or a specific date in `YYYYMMDDHHmmSS` format.
    ///
    /// [RRSIG]: ../../rdata/rfc4034/struct.Rrsig.html
    pub fn rrsig_from_str(src: &str) -> Result<Self, IllegalSignatureTime> {
        if !src.is_ascii() {
            return Err(IllegalSignatureTime);
        }
        if src.len() == 14 {
            let year = u32::from_str(&src[0..4])
                .map_err(|_| IllegalSignatureTime)?
                as i32;
            let month = Month::try_from(
                u8::from_str(&src[4..6]).map_err(|_| IllegalSignatureTime)?,
            )
            .map_err(|_| IllegalSignatureTime)?;
            let day =
                u8::from_str(&src[6..8]).map_err(|_| IllegalSignatureTime)?;
            let hour = u8::from_str(&src[8..10])
                .map_err(|_| IllegalSignatureTime)?;
            let minute = u8::from_str(&src[10..12])
                .map_err(|_| IllegalSignatureTime)?;
            let second = u8::from_str(&src[12..14])
                .map_err(|_| IllegalSignatureTime)?;
            Ok(Serial(
                PrimitiveDateTime::new(
                    Date::from_calendar_date(year, month, day)
                        .map_err(|_| IllegalSignatureTime)?,
                    Time::from_hms(hour, minute, second)
                        .map_err(|_| IllegalSignatureTime)?,
                )
                .assume_utc()
                .unix_timestamp() as u32,
            ))
        } else {
            Serial::from_str(src).map_err(|_| IllegalSignatureTime)
        }
    }
}

/// # Parsing and Composing
///
impl Serial {
    pub const COMPOSE_LEN: u16 = u32::COMPOSE_LEN;

    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        u32::parse(parser).map(Into::into)
    }

    pub fn compose<Target: Composer + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.0.compose(target)
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

//--- Display

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

fn u8_from_buf(buf: &[u8]) -> u8 {
    let mut res = 0;
    for ch in buf {
        res = res * 10 + *ch;
    }
    res
}

fn u32_from_buf(buf: &[u8]) -> u32 {
    let mut res = 0;
    for ch in buf {
        res = res * 10 + (u32::from(*ch));
    }
    res
}

//============ Testing =======================================================

#[derive(Clone, Copy, Debug)]
pub struct IllegalSignatureTime;

impl fmt::Display for IllegalSignatureTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("illegal signature time")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IllegalSignatureTime {}

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
