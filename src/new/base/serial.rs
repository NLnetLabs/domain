//! Numeric types using RFC 1982 Sequence Space Arithmetic.
//!
//! This module includes types which work in the numberspace of 2^32. The
//! implementation reference is [RFC1982] which defines the "sequence space
//! arithmetic".
//!
//! The module contains three types:
//!
//! - [`SeqNumberU32`]
//! - [`SoaSerial`]
//! - [`Timestamp`]
//!
//! [`SeqNumberU32`] implements the arithmetics defined in [RFC1982] and
//! functions as the underlying datastructure for the other types.
//!
//! [`SoaSerial`], as the name suggests, is used as the version number in the
//! context of the DNS zone. [`SoaSerial`] is primarily used in the serial
//! field of the [`Soa`] record type. Additionally [`SoaSerial`] is used in
//! [`ZoneMD`].
//!
//! [`Timestamp`] is used to represent time since Unix Epoch modulo 2^32.
//! Therefore the type is not an accurate time representation but is rather
//! used to show relative differences in time. Apart from the usage in the
//! [`Rrsig`] record, the type is also used in the EDNS [`Cookie`].
//!
//! [`Cookie`]: crate::new::edns::Cookie
//! [`Rrsig`]: crate::new::rdata::Rrsig
//! [`Soa`]: crate::new::rdata::Soa
//! [`ZoneMD`]: crate::new::rdata::ZoneMD
//!
//! [RFC1982]: https://datatracker.ietf.org/doc/html/rfc1982

// This module includes all serial types because they have a logical
// connection and they are used throughout the crate. Therefore it is
// difficult to put them into one specific location together or each one
// separate.

use core::cmp::Ordering;
use core::fmt;
use core::time::Duration;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use domain_macros::*;

use super::wire::U32;

/// 2^32 is used to simplify expressions.
const POW_2_32: u64 = 1 << 32;

//----------- SoaSerial ------------------------------------------------------

/// Version number of a DNS zone.
///
/// The SOA serial number declares the version number of the associated zone.
/// It is used to determine the most recent revision of a zone.
///
/// [`SoaSerial`] commonly follows one of the following strategies to declare
/// [`SoaSerial`]:
///
/// - Counter, it starts at 1 and on each change the number gets increased by
///   one.
/// - Seconds since Unix Epoch, when the zone is changed the number gets set
///   to the current number of seconds since Unix Epoch.
/// - Date including counter, on change the number gets set to the current
///   date in the format (`YYYYMMDDXX`).
///
/// The mathematical operations are done using [`SeqNumberU32`]. The number
/// adheres to the mathematical properties of the "Serial Number Arithmetics"
/// see [RFC1982] with an unsigned 32 bit integer.
///
/// Basic operations performed with a [`SoaSerial`].
/// ```
/// # use domain::new::base::SoaSerial;
/// let mut soa_serial = SoaSerial::new(u32::MAX);
/// soa_serial = soa_serial.increment();
/// let value: u32 = soa_serial.get();
/// assert_eq!(value, 0);
/// ```
///
/// [RFC1982]: https://datatracker.ietf.org/doc/html/rfc1982
/// [RFC1035]: https://datatracker.ietf.org/doc/html/rfc1035
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
pub struct SoaSerial(SeqNumberU32);

impl SoaSerial {
    /// Construct a new [`SoaSerial`].
    #[must_use]
    pub const fn new(value: u32) -> Self {
        SoaSerial(SeqNumberU32::new(value))
    }

    /// The raw [`u32`] underlying this [`SoaSerial`].
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    /// Measure system time since Unix Epoch modulo 2^32.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn now() -> Self {
        let now = SystemTime::now();
        let diff = match now.duration_since(UNIX_EPOCH) {
            // Technically the `% POW_2_32` does the same as `diff as u32`
            // (see return expression) but it is done here explicitly.
            Ok(secs_after_epoch) => secs_after_epoch.as_secs() % POW_2_32,
            Err(secs_before_epoch) => {
                POW_2_32 - (secs_before_epoch.duration().as_secs() % POW_2_32)
            }
        };
        SoaSerial::new(diff as u32)
    }

    /// Increase [`SoaSerial`] by 1.
    ///
    /// Further details in [`SeqNumberU32::increment()`].
    #[must_use]
    pub const fn increment(self) -> Self {
        SoaSerial(self.0.increment())
    }
}

/// Comparison is forwarded to the underlying [`SeqNumberU32`].
///
/// Further details in the `PartialOrd` implementation of [`SeqNumberU32`].
impl PartialOrd for SoaSerial {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

/// Format [`SoaSerial`] in a human readable way.
///
/// All mentioned versioning strategies do not need special formatting or
/// computation. The string representation is therefore equivalent to the
/// decimal number representation.
///
/// ```
/// # use domain::new::base::SoaSerial;
/// assert_eq!(format!("{}", SoaSerial::new(42)), "42");
/// ```
impl fmt::Display for SoaSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

// --- From implementations

/// The raw [`u32`] underlying this [`SoaSerial`].
///
/// Equivalent to [`SoaSerial::get()`].
///
/// ```
/// # use domain::new::base::SoaSerial;
/// assert_eq!(42u32, SoaSerial::new(42).into());
/// ```
impl From<SoaSerial> for u32 {
    fn from(value: SoaSerial) -> u32 {
        value.get()
    }
}

/// Construct [`SoaSerial`] from [`u32`].
///
/// Equivalent to [`SoaSerial::new()`].
///
/// ```
/// # use domain::new::base::SoaSerial;
/// assert_eq!(SoaSerial::new(42), 42.into());
/// ```
impl From<u32> for SoaSerial {
    fn from(value: u32) -> Self {
        SoaSerial::new(value)
    }
}

//----------- Timestamp ---------------------------------------------------

/// Seconds since Unix Epoch modulo 2^32.
///
/// [`Timestamp`] stores the seconds since Unix Epoch modulo 2^32. It is used
/// in [`Rrsig`] to keep track of `inception` and `expiration` time and in the
/// EDNS [`Cookie::timestamp()`].
///
/// The imperfect timekeeping due to the limited number space does not matter
/// too much in those cases. But the limitations have to be kept in mind.
/// More details about that can be found in [Section 3.1.5 of RFC4034]
/// "Signature Expiration and Inception Fields" and [Section 4.3 of RFC9018].
///
/// [`Timestamp`] can be constructed using a [`jiff::Timestamp`] using a
/// [`Timestamp::from()`].
///
/// The mathematical operations are done using [`SeqNumberU32`]. The number
/// adheres to the mathematical properties of the "Serial Number Arithmetics"
/// see [RFC1982] with an unsigned 32 bit integer.
///
/// Basic operations performed with a [`Timestamp`].
/// ```
/// # use domain::new::base::Timestamp;
/// let timestamp: Timestamp = Timestamp::new(42);
/// let value: u32 = timestamp.as_seconds();
/// assert_eq!(value, 42);
/// ```
///
/// [`Cookie::timestamp()`]: crate::new::edns::Cookie::timestamp()
/// [`Rrsig`]: domain::new::rdata::Rrsig
///
/// [RFC1982]: https://datatracker.ietf.org/doc/html/rfc1982
/// [Section 3.1.5 of RFC4034]: https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.5
/// [Section 4.3 of RFC9018]: https://datatracker.ietf.org/doc/html/rfc9018#name-the-timestamp-sub-field
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
pub struct Timestamp(SeqNumberU32);

impl Timestamp {
    /// Construct a new [`Timestamp`].
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Timestamp(SeqNumberU32::new(value))
    }

    // This type has a specific unit, therefore the `get()` function was
    // renamed in favor of `as_seconds`.

    /// Underlying seconds since Unix Epoch modulo 2^32.
    #[must_use]
    pub const fn as_seconds(self) -> u32 {
        self.0.get()
    }

    /// Measure system time since Unix Epoch modulo 2^32.
    ///
    /// ```
    /// # use domain::new::base::Timestamp;
    /// # use std::time::{SystemTime, UNIX_EPOCH};
    /// let now = Timestamp::now();
    /// assert_eq!(
    ///     now.as_seconds(),
    ///     // `as u32` truncates the value down the same way `% 2^32` would.
    ///     (UNIX_EPOCH.elapsed().unwrap().as_secs()) as u32
    /// );
    /// ```
    #[cfg(feature = "std")]
    #[must_use]
    pub fn now() -> Self {
        let now = SystemTime::now();
        let diff = match now.duration_since(UNIX_EPOCH) {
            // Technically the `% POW_2_32` does the same as `diff as u32`
            // (see return expression) but it is done here explicitly.
            Ok(secs_after_epoch) => secs_after_epoch.as_secs() % POW_2_32,
            Err(secs_before_epoch) => {
                POW_2_32 - (secs_before_epoch.duration().as_secs() % POW_2_32)
            }
        };
        Timestamp::new(diff as u32)
    }

    /// Convert this [`Timestamp`] into [`SystemTime`] close to a reference
    /// time.
    ///
    /// This method may be used to sort [`Timestamp`] values or to display a
    /// [`Timestamp`] in a date and time format.
    ///
    /// The returned [`SystemTime`] meets the following requirements:
    ///
    /// 1) The [`SystemTime`] value has a duration since `UNIX_EPOCH` that
    ///    modulo `2**32` is equal to our [`Timestamp`] value.
    /// 2) The time difference between the [`SystemTime`] value and the
    ///    reference time fits in an [`i32`].
    #[must_use]
    #[cfg(feature = "std")]
    pub fn to_system_time(self, reference: SystemTime) -> Option<SystemTime> {
        // Timestamp is a 32-bit value. We cannot just add UNIX_EPOCH because
        // the timestamp may be too far in the future. We may have to add
        // n * 2**32 for some unknown value of n.
        //
        // Epoch                                 Reference              Future
        // |--------------------------------------- | -----------------------|
        //                                   [  i32 range   ]
        //
        // [   POW_2_32   ][   POW_2_32   ][ timestamp ]
        //
        // The goal is to find a [`SystemTime`] which is inside the i32 range.

        let mut timestamp_secs: i128 = self.as_seconds().into();
        let reference_secs: i128 = match reference.duration_since(UNIX_EPOCH)
        {
            Ok(secs) => secs.as_secs().into(),
            Err(e) => -(e.duration().as_secs() as i128),
        };

        // Apply the offset that the `reference_secs` has to the `UNIX_EPOCH`,
        // but without the lower 32-bit details. After that the value could
        // still to far away but it is around in the right region.
        timestamp_secs +=
            (reference_secs / POW_2_32 as i128) * POW_2_32 as i128;

        // The values could still be to far apart to fit into an i32 range.
        // Therefore an addition or substraction might be necessary.
        if timestamp_secs - reference_secs < i32::MIN as i128 {
            timestamp_secs += POW_2_32 as i128;
        } else if timestamp_secs - reference_secs > i32::MAX as i128 {
            timestamp_secs -= POW_2_32 as i128;
        }

        // Now that the timestamp has been calculated we have to check if it
        // is a negative or positive number and apply the correct function to
        // the `UNIX_EPOCH`.
        if timestamp_secs < 0 {
            UNIX_EPOCH.checked_sub(Duration::from_secs(
                timestamp_secs.unsigned_abs() as u64,
            ))
        } else {
            UNIX_EPOCH.checked_add(Duration::from_secs(timestamp_secs as u64))
        }
    }
}

/// Comparison is forwarded to the underlying [`SeqNumberU32`].
///
/// Further details in the `PartialOrd` implementation of [`SeqNumberU32`].
impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

/// Format [`Timestamp`] in a human readable way.
///
/// This implementation displays [`Timestamp`] as the elapsed second stored.
///
/// [`Timestamp`] is commonly displayed in one of two ways. The first, simple
/// way is to present it as the elapsed seconds since Unix Epoch modulo
/// 2^32 it stores. The more complex way to display [`Timestamp`] would be to
/// compute the precise date `self` refers to and display this date in the
/// form `YYYYMMDDHHmmSS`.
///
/// The first option is implemented because it requires less computation and
/// is more generally usable.
///
/// More details about the display variations can be found in [Section 3.2 of
/// RFC4034].
///
/// ```
/// # use domain::new::base::Timestamp;
/// assert_eq!(format!("{}", Timestamp::new(42)), "42");
/// ```
///
/// [Section 3.2 of RFC4034]: https://datatracker.ietf.org/doc/html/rfc4034#section-3.2
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_seconds())
    }
}

// --- From Implementations

/// Construct [`Timestamp`] from [`u32`].
///
/// Equivalent to [`Timestamp::as_seconds()`].
///
/// ```
/// # use domain::new::base::Timestamp;
/// assert_eq!(42u32, Timestamp::new(42).into());
/// ```
impl From<Timestamp> for u32 {
    fn from(value: Timestamp) -> u32 {
        value.as_seconds()
    }
}

/// The raw [`u32`] underlying this [`Timestamp`].
///
/// Equivalent to [`Timestamp::new()`].
///
/// ```
/// # use domain::new::base::Timestamp;
/// assert_eq!(Timestamp::new(42), 42.into());
/// ```
impl From<u32> for Timestamp {
    fn from(value: u32) -> Self {
        Timestamp::new(value)
    }
}

/// Construct [`Timestamp`] from a [`jiff::Timestamp`].
///
/// Precision is lost during the conversion because of the smaller storage
/// primitive.
/// ```
/// # use domain::new::base::Timestamp;
/// let ts = Timestamp::from(
///     jiff::Timestamp::new(u32::MAX as i64 + 10, 0).unwrap(),
/// );
/// assert_eq!(ts.as_seconds(), 9);
/// ```
impl From<jiff::Timestamp> for Timestamp {
    fn from(value: jiff::Timestamp) -> Self {
        Timestamp::new(value.as_second().rem_euclid(POW_2_32 as i64) as u32)
    }
}

// --- Compatibility for old base
// The following implementations are implemented to make the transition easier
// to new base but will be deprecated in the near future.

impl Timestamp {
    /// Returns the timestamp as a raw integer.
    #[must_use]
    pub fn into_int(self) -> u32 {
        self.as_seconds()
    }
}

impl From<Timestamp> for crate::rdata::dnssec::Timestamp {
    fn from(ts: Timestamp) -> Self {
        crate::rdata::dnssec::Timestamp::from(ts.as_seconds())
    }
}

//----------- SeqNumberU32 ---------------------------------------------------

/// 32-bit unsigned integer using [RFC1982] sequence number space arithmetic.
///
/// This type implements the mathematical properties defined in [RFC1982].
/// Section 3 in [RFC1982] defines that there are only two possible operations
/// on a Serial; addition and comparison.
///
/// The type is used as a backend for [`SoaSerial`] and [`Timestamp`].
///
/// ```
/// # use domain::new::base::SeqNumberU32;
/// let seq_number: SeqNumberU32 = SeqNumberU32::new(u32::MAX).increment();
/// let value: u32 = seq_number.get();
/// assert_eq!(value, 0);
/// ```
///
/// [RFC1982]: https://datatracker.ietf.org/doc/html/rfc1982
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
pub struct SeqNumberU32(U32);

impl SeqNumberU32 {
    /// Construct a new [`SeqNumberU32`].
    pub const fn new(value: u32) -> Self {
        SeqNumberU32(U32::new(value))
    }

    /// The raw [`u32`] underlying this [`SeqNumberU32`].
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl SeqNumberU32 {
    // Incrementing [`SeqNumberU32`] by more than one serves little purpose
    // and might be achieved easier by constructing it from a primitive
    // number.
    //
    // [RFC1982] states that the maximum allowed increment is `(2^31)-1`. A
    // function would therefore need to verify that the increment is smaller
    // than that and panic/fail if this is not satisfied. To avoid that
    // potential risk, the type only offers incrementation by 1.

    /// Increment [`SeqNumberU32`] by 1.
    #[must_use]
    pub const fn increment(self) -> Self {
        SeqNumberU32::new(self.0.get().wrapping_add(1))
    }
}

//--- Ordering

impl PartialOrd for SeqNumberU32 {
    /// The comparison of serial number values is defined in [Section 3.2 of
    /// RFC1982].
    ///
    /// The comparison is special because the sequence number might wrap
    /// around after reaching the maximum. The maximum difference between two
    /// numbers is limited to less than 2^31. If two numbers are exactly 2^31
    /// apart the order is undefined.
    ///
    /// [Section 3.2 of RFC1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
    /// ```
    /// # use domain::new::base::SeqNumberU32;
    /// # use std::cmp::Ordering;
    /// // The numbers are exactly 2^31 apart, this is not defined.
    /// assert_eq!(
    ///     SeqNumberU32::partial_cmp(&0.into(), &(1<<31).into()),
    ///     None
    /// );
    /// // Simple, both numbers are equal.
    /// assert_eq!(
    ///     SeqNumberU32::partial_cmp(&42.into(), &42.into()),
    ///     Some(Ordering::Equal)
    /// );
    ///
    /// // The left number is smaller and they are less than 2^31 apart.
    /// assert_eq!(
    ///     SeqNumberU32::partial_cmp(&42.into(), &43.into()),
    ///     Some(Ordering::Less)
    /// );
    ///
    /// // This is special; the left number is numerically speaking smaller,
    /// // but because the numbers are further apart than 2^31 it is assumed
    /// // that the order is swapped and the left number is actually bigger
    /// // because it has wrapped around.
    /// assert_eq!(
    ///     SeqNumberU32::partial_cmp(&42.into(), &u32::MAX.into()),
    ///     Some(Ordering::Greater)
    /// );
    /// ```
    // None -> this.abs_diff(other) == 2^31
    // Some(Ordering::Equal) -> this == other
    // Some(Ordering::Less) -> this < other and (other - this) < 2^31
    //                         // 1 < 10 and 10 - 1 < 2^31
    //                         or
    //                         this > other and (this - other) > 2^31
    //                         // u32::MAX > 1 and u32::MAX - 1 > 2^31
    // Some(Ordering::Greater) -> this > other and (this - other) < 2^31
    //                         // 10 > 1 and 10 - 1 < 2^31
    //                         or
    //                         this < other and (this - other) > 2^31
    //                         // 10 < u32::MAX and u32::MAX - 1 > 2^31
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let (lhs, rhs) = (self.0.get(), other.0.get());
        if lhs == rhs {
            Some(Ordering::Equal)
        } else if lhs.abs_diff(rhs) == (1 << 31) {
            None
        } else if (lhs < rhs) == (lhs.abs_diff(rhs) < (1 << 31)) {
            Some(Ordering::Less)
        } else {
            Some(Ordering::Greater)
        }
    }
}

// --- From implementations

/// Construct [`SeqNumberU32`] from [`u32`].
///
/// Equivalent to [`SeqNumberU32::get()`].
///
/// ```
/// # use domain::new::base::SeqNumberU32;
/// assert_eq!(42u32, SeqNumberU32::new(42).into());
/// ```
impl From<SeqNumberU32> for u32 {
    fn from(value: SeqNumberU32) -> u32 {
        value.get()
    }
}

/// The raw [`u32`] underlying this [`SeqNumberU32`].
///
/// Equivalent to [`SeqNumberU32::new()`].
///
/// ```
/// # use domain::new::base::SeqNumberU32;
/// assert_eq!(SeqNumberU32::new(42), 42.into());
/// ```
impl From<u32> for SeqNumberU32 {
    fn from(value: u32) -> Self {
        SeqNumberU32::new(value)
    }
}

#[cfg(test)]
mod serial_test {
    use core::{cmp::Ordering, time::Duration};
    use std::{println, time::UNIX_EPOCH};

    use super::{SeqNumberU32, SoaSerial, Timestamp};

    #[test]
    fn comparisons() {
        // TODO: Use property-based testing.
        assert!(
            SeqNumberU32::from(u32::MAX)
                > SeqNumberU32::from(u32::MAX / 2 + 1)
        );
        assert!(SeqNumberU32::from(0) > SeqNumberU32::from(u32::MAX));
        assert!(SeqNumberU32::from(1) > SeqNumberU32::from(0));

        assert!(
            SoaSerial::from(u32::MAX) > SoaSerial::from(u32::MAX / 2 + 1)
        );
        assert!(SoaSerial::from(0) > SoaSerial::from(u32::MAX));
        assert!(SoaSerial::from(1) > SoaSerial::from(0));

        assert!(
            Timestamp::from(u32::MAX) > Timestamp::from(u32::MAX / 2 + 1)
        );
        assert!(Timestamp::from(0) > Timestamp::from(u32::MAX));
        assert!(Timestamp::from(1) > Timestamp::from(0));

        assert_eq!(
            SeqNumberU32::new(0)
                .partial_cmp(&SeqNumberU32::new((1 << 31) - 1)),
            Some(Ordering::Less)
        );
        assert_eq!(
            SeqNumberU32::new(0)
                .partial_cmp(&SeqNumberU32::new((1 << 31) + 1)),
            Some(Ordering::Greater)
        );

        assert_eq!(
            SeqNumberU32::new(0).partial_cmp(&SeqNumberU32::new(1 << 31)),
            None
        );
    }

    #[test]
    fn operations() {
        // TODO: Use property-based testing.
        assert_eq!(u32::from(SeqNumberU32::from(1).increment()), 2);
        assert_eq!(u32::from(SeqNumberU32::from(u32::MAX).increment()), 0);

        assert_eq!(u32::from(SoaSerial::from(1).increment()), 2);
        assert_eq!(u32::from(SoaSerial::from(u32::MAX).increment()), 0);
    }

    #[test]
    fn test_to_system_time() {
        #[derive(Debug)]
        struct Params {
            ts: u32,
            ref_ts: i128,
            res: i128,
        }
        let tests = alloc::vec![
            // Simple cases, ts and ref_ts mod 2**32 are within 2*31-1.
            // First ts less than ref_ts mod 2**32.
            Params {
                ts: 0x0000_0000,
                ref_ts: 0x1_7fff_ffff,
                res: 0x1_0000_0000,
            },
            Params {
                ts: 0x7fff_ffff,
                ref_ts: 0x1_8000_0000,
                res: 0x1_7fff_ffff,
            },
            Params {
                ts: 0x8000_0000,
                ref_ts: 0x1_ffff_ffff,
                res: 0x1_8000_0000,
            },
            // Then ts larger than ref_ts mod 2**32.
            Params {
                ts: 0x7fff_ffff,
                ref_ts: 0x1_0000_0000,
                res: 0x1_7fff_ffff,
            },
            Params {
                ts: 0x8000_0000,
                ref_ts: 0x1_7fff_ffff,
                res: 0x1_8000_0000,
            },
            Params {
                ts: 0xffff_ffff,
                ref_ts: 0x1_8000_0000,
                res: 0x1_ffff_ffff,
            },
            // Next, cases where the difference between ts and ref_ts mod 2**32
            // are at least 2**31+1.
            Params {
                ts: 0x0000_0000,
                ref_ts: 0x1_8000_0001,
                res: 0x2_0000_0000,
            },
            Params {
                ts: 0x7fff_fffe,
                ref_ts: 0x1_ffff_ffff,
                res: 0x2_7fff_fffe,
            },
            Params {
                ts: 0x8000_0001,
                ref_ts: 0x1_0000_0000,
                res: 0x0_8000_0001,
            },
            Params {
                ts: 0xffff_ffff,
                ref_ts: 0x1_7fff_fffe,
                res: 0x0_ffff_ffff,
            },
            // Test cases where the difference is exactly 2**31.
            Params {
                ts: 0x0000_0000,
                ref_ts: 0x1_8000_0000,
                res: 0x1_0000_0000,
            },
            Params {
                ts: 0x7fff_ffff,
                ref_ts: 0x1_ffff_ffff,
                res: 0x1_7fff_ffff,
            },
            Params {
                ts: 0x8000_0000,
                ref_ts: 0x1_0000_0000,
                res: 0x0_8000_0000,
            },
            Params {
                ts: 0xffff_ffff,
                ref_ts: 0x1_7fff_ffff,
                res: 0x0_ffff_ffff,
            },
            // Special case: ERA 0. We *want* numbers before UNIX_EPOCH
            Params {
                ts: 0x8000_0001,
                ref_ts: 0x0_0000_0000,
                res: -0x7FFF_FFFF // 0x0_8000_0001,
            },
            Params {
                ts: 0xffff_ffff,
                ref_ts: 0x0_7fff_fffe,
                res: -1 // 0x0_ffff_ffff,
            },
            Params {
                ts: 0x8000_0000,
                ref_ts: 0x0_0000_0000,
                res: -0x0_8000_0000 // 0x0_8000_0000,
            },
            Params {
                ts: 0xffff_ffff,
                ref_ts: 0x0_7fff_ffff,
                res: -1 // 0x0_ffff_ffff,
            },
            Params {
                ts: 1,
                ref_ts: -1,
                res: 1
            },
            Params {
                ts: 1,
                ref_ts: -0x1_0000_0000, // 2^32 -1,
                res: -0x1_0000_0000 + 1
            },
            Params {
                ts: 1 + 0x8000_0000,
                ref_ts: -0x1_0000_0000, // 2^32 -1,
                res: -0x2_0000_0000 + (1 + 0x8000_0000)
            },
        ];

        for t in tests {
            println!("Test {:?}", t);
            let ts = Timestamp::new(t.ts);
            let ref_ts = if t.ref_ts < 0 {
                UNIX_EPOCH
                    .checked_sub(Duration::from_secs(
                        t.ref_ts.unsigned_abs() as u64
                    ))
                    .unwrap()
            } else {
                UNIX_EPOCH
                    .checked_add(Duration::from_secs(t.ref_ts as u64))
                    .unwrap()
            };
            let res = ts.to_system_time(ref_ts).unwrap();
            let res = match res.duration_since(UNIX_EPOCH) {
                Ok(o) => o.as_secs() as i128,
                Err(e) => -(e.duration().as_secs() as i128),
            };
            assert_eq!(res, t.res);
        }
    }
}
