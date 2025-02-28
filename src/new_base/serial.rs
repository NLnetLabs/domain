//! Serial number arithmetic.
//!
//! See [RFC 1982](https://datatracker.ietf.org/doc/html/rfc1982).

use core::{
    cmp::Ordering,
    fmt,
    ops::{Add, AddAssign},
};

use domain_macros::*;

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

use super::wire::U32;

//----------- Serial ---------------------------------------------------------

/// A serial number.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct Serial(U32);

//--- Construction

impl Serial {
    /// Measure the current time (in seconds) in serial number space.
    #[cfg(feature = "std")]
    pub fn unix_time() -> Self {
        use std::time::SystemTime;

        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("The current time is after the Unix Epoch");
        Self::from(time.as_secs() as u32)
    }
}

//--- Addition

impl Add<i32> for Serial {
    type Output = Self;

    fn add(self, rhs: i32) -> Self::Output {
        self.0.get().wrapping_add_signed(rhs).into()
    }
}

impl AddAssign<i32> for Serial {
    fn add_assign(&mut self, rhs: i32) {
        self.0 = self.0.get().wrapping_add_signed(rhs).into();
    }
}

//--- Ordering

impl PartialOrd for Serial {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let (lhs, rhs) = (self.0.get(), other.0.get());

        if lhs == rhs {
            Some(Ordering::Equal)
        } else if lhs.abs_diff(rhs) == 1 << 31 {
            None
        } else if (lhs < rhs) ^ (lhs.abs_diff(rhs) > (1 << 31)) {
            Some(Ordering::Less)
        } else {
            Some(Ordering::Greater)
        }
    }
}

//--- Conversion to and from native integer types

impl From<u32> for Serial {
    fn from(value: u32) -> Self {
        Self(U32::new(value))
    }
}

impl From<Serial> for u32 {
    fn from(value: Serial) -> Self {
        value.0.get()
    }
}

//--- Formatting

impl fmt::Display for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.get().fmt(f)
    }
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl Scan<'_> for Serial {
    fn scan(
        scanner: &mut Scanner<'_>,
        _alloc: &'_ bumpalo::Bump,
        _buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        use core::num::IntErrorKind;

        scanner
            .scan_plain_token()?
            .parse::<u32>()
            .map_err(|err| {
                ScanError::Custom(match err.kind() {
                    IntErrorKind::PosOverflow => {
                        "Specified serial number will overflow"
                    }
                    IntErrorKind::InvalidDigit => {
                        "Serial numbers can only contain digits"
                    }
                    IntErrorKind::NegOverflow => {
                        "Serial numbers must be non-negative"
                    }
                    // We have already checked for other kinds of errors.
                    _ => unreachable!(),
                })
            })
            .map(Self::from)
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::Serial;

    #[test]
    fn comparisons() {
        // TODO: Use property-based testing.
        assert!(Serial::from(u32::MAX) > Serial::from(u32::MAX / 2 + 1));
        assert!(Serial::from(0) > Serial::from(u32::MAX));
        assert!(Serial::from(1) > Serial::from(0));
    }

    #[test]
    fn operations() {
        // TODO: Use property-based testing.
        assert_eq!(u32::from(Serial::from(1) + 1), 2);
        assert_eq!(u32::from(Serial::from(u32::MAX) + 1), 0);
    }
}
