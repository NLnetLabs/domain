//! Serial number arithmetic.
//!
//! See [RFC 1982](https://datatracker.ietf.org/doc/html/rfc1982).

use core::{
    cmp::Ordering,
    fmt,
    ops::{Add, AddAssign},
};

use zerocopy::network_endian::U32;
use zerocopy_derive::*;

//----------- Serial ---------------------------------------------------------

/// A serial number.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    FromBytes,
    IntoBytes,
    KnownLayout,
    Immutable,
    Unaligned,
)]
#[repr(transparent)]
pub struct Serial(U32);

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
