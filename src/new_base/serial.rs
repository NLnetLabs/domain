//! Serial number arithmetic.
//!
//! See [RFC 1982](https://datatracker.ietf.org/doc/html/rfc1982).

use core::{cmp::Ordering, fmt};

use domain_macros::*;

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
    ParseBytesZC,
    SplitBytes,
    SplitBytesZC,
    UnsizedCopy,
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

//--- Interaction

impl Serial {
    /// Increment this by a non-negative number.
    ///
    /// The number must be in the range `[0, 2^31 - 1]`.  An [`i32`] is used
    /// instead of a [`u32`] because it is easier to understand and implement
    /// a non-negative check versus the upper range check.
    ///
    /// # Panics
    ///
    /// Panics if the number is negative.
    pub fn inc(self, num: i32) -> Self {
        assert!(num >= 0, "Cannot subtract from a `Serial`");
        self.0.get().wrapping_add_signed(num).into()
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
        assert_eq!(u32::from(Serial::from(1).inc(1)), 2);
        assert_eq!(u32::from(Serial::from(u32::MAX).inc(1)), 0);
    }
}
