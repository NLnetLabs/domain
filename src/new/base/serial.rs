//! Types which operate in the modulo 2^32 number space.
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
//! The [`SeqNumberU32`] implements the arithmetics defined in [RFC1982] and
//! functions as the underlying datastructure for the other types.
//!
//! The [`SoaSerial`], as the name suggests, is used as the version number in
//! the context of the DNS zone. The [`SoaSerial`] is primarily used in the
//! serial field of the [`Soa`] record type. Additionally the [`SoaSerial`] is
//! used in the [`ZoneMD`].
//!
//! The [`Timestamp`] is used to represent time since Unix Epoch modulo 2^32.
//! Therefore the type is not an accurate time representation but is rather
//! used to show relative differences in time. Apart from the usage in the
//! [`Rrsig`] record, the type is also used in the edns [`Cookie`].
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
// seperate.

use core::cmp::Ordering;
use core::fmt;
use core::time::Duration;
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use domain_macros::*;

use super::wire::U32;

/// 2^32 is used to simplify expressions.
const POW_2_32: u64 = 0x1_0000_0000;

//----------- SoaSerial ------------------------------------------------------

/// Version number of a DNS zone.
///
/// The SOA serial number declares the version number of the associated zone.
/// It is used to determine the most recent revision of a zone.
///
/// The [`SoaSerial`] commonly follows one of the following strategies to
/// declare the [`SoaSerial`]:
///
/// - Counter, it starts at 1 and on each change the number gets increased by
///   one.
/// - Seconds since Unix Epoch, when the zone is changed the number gets set
///   to the current number of seconds since Unix Epoch.
/// - Date including counter, on change the number gets set to the current
///   date in the format (`YYYYMMDD00`) if the number is smaller than the
///   previous version, the old serial gets increased by one.
///
/// The mathematical operations are done using the [`SeqNumberU32`]. The
/// number adheres to the mathematical properties of the "Serial Number
/// Arithmetics" see [RFC1982] with an unsigned 32 bit integer.
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

/// Comparision is forwarded to the underlying [`SeqNumberU32`].
///
/// Further details in the `PartialOrd` implementation of [`SeqNumberU32`].
impl PartialOrd for SoaSerial {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

/// Format the [`SoaSerial`] in a huaman readable way.
///
/// All mentioned versioning strategies do not need special formatting or
/// computation. The string representation is therefore equivelent to the
/// decimal number representation.
impl fmt::Display for SoaSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get())
    }
}

// --- From implementations

/// Construct [`SoaSerial`] from [`u32`].
///
/// Equivalent to [`SoaSerial::get()`].
impl From<SoaSerial> for u32 {
    fn from(value: SoaSerial) -> u32 {
        value.get()
    }
}

/// The raw [`u32`] underlying this [`SoaSerial`].
///
/// Equivalent to [`SoaSerial::new()`].
impl From<u32> for SoaSerial {
    fn from(value: u32) -> Self {
        SoaSerial::new(value)
    }
}

//----------- Timestamp ---------------------------------------------------

/// Seconds since Unix Epoch modulo 2^32.
///
/// The [`Timestamp`] stores the seconds since Unix Epoch modulo 2^32. It is
/// used in the [`Rrsig`] to keep track of `inception` and `expiration` time
/// and in the edns [`Cookie`] `timestamp`.
///
/// The inperfect timekeeping due to the limited numberspace does not matter
/// too much in those cases. But the limitations have to be keept in mind.
/// More details about that can be found in Section 3.1.5 of [RFC4034]
/// "Signature Expiration and Inception Fields" and Section 4.3 of [RFC9018].
///
/// The [`Timestamp`] can be constructed using a [`jiff::Timestamp`] using a
/// [`Timestamp::from()`].
///
/// The mathematical operations are done using the [`SeqNumberU32`]. The
/// number adheres to the mathematical properties of the "Serial Number
/// Arithmetics" see [RFC1982] with an unsigned 32 bit integer.
///
/// [`Cookie`]: crate::new::edns::Cookie
/// [`Rrsig`]: domain::new::rdata::Rrsig
///
/// [RFC1982]: https://datatracker.ietf.org/doc/html/rfc1982
/// [RFC4034]: https://datatracker.ietf.org/doc/html/rfc4034#section-3.1.5
/// [RFC9018]: https://datatracker.ietf.org/doc/html/rfc9018#name-the-timestamp-sub-field
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

    /// Underlying seconds since Unix Epoch modulo 2^32.
    // This type has a specific unit, therefore the `get()` function was
    // renamed in favor of `as_seconds`.
    #[must_use]
    pub const fn as_seconds(self) -> u32 {
        self.0.get()
    }

    /// Measure system time since Unix Epoch modulo 2^32.
    #[cfg(feature = "std")]
    #[must_use]
    pub fn now() -> Self {
        let now = SystemTime::now();
        let diff = match now.duration_since(UNIX_EPOCH) {
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
    pub fn to_system_time(self, reference: SystemTime) -> SystemTime {
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
        const POW_2_32: u64 = 0x1_0000_0000;
        let ref_secs =
            reference.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let k = ref_secs / POW_2_32;
        let ref_secs_mod = ref_secs % POW_2_32;
        let ts_secs = self.into_int() as u64;
        let ts_secs = if ts_secs < ref_secs_mod {
            if ref_secs_mod - ts_secs <= POW_2_32 / 2 {
                // Close enough, use k.
                ts_secs + k * POW_2_32
            } else {
                // ts_secs is really beyond ref_secs, use k+1.
                ts_secs + (k + 1) * POW_2_32
            }
        } else {
            // ts_secs >= ref_secs_mod
            if ts_secs - ref_secs_mod < POW_2_32 / 2 {
                // Close enough, use k.
                ts_secs + k * POW_2_32
            } else {
                // ts_secs is really old than ref_secs. Try to use k-1
                // but only if k is not zero.
                let k = if k > 0 { k - 1 } else { k };
                ts_secs + k * POW_2_32
            }
        };
        UNIX_EPOCH + Duration::from_secs(ts_secs)
    }
}

/// Comparision is forwarded to the underlying [`SeqNumberU32`].
///
/// Further details in the `PartialOrd` implementation of [`SeqNumberU32`].
impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

/// Format the [`Timestamp`] in a huaman readable way.
///
/// This implementation displays the [`Timestamp`] as the elapsed seconds
/// stored.
///
/// The [`Timestamp`] is commonly displayed in one of two ways. The first,
/// simple way is to present it as the elapsed seconds since Unix Epoch modulo
/// 2^32 it stores. The more complex way to display the [`Timestamp`] would be
/// to compute the precise date `self` refers to and display this date in the
/// form `YYYYMMDDHHmmSS`.
///
/// The first option is implemented because it requires less computation and
/// is more generally usable.
///
/// More details about the display variations can be found in Section 3.2 of
/// [RFC4034].
///
/// [RFC4034]: https://datatracker.ietf.org/doc/html/rfc4034#section-3.2
impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_seconds())
    }
}

// --- From Implementations

/// Construct [`Timestamp`] from [`u32`].
///
/// Equivalent to [`Timestamp::as_seconds()`].
impl From<Timestamp> for u32 {
    fn from(value: Timestamp) -> u32 {
        value.as_seconds()
    }
}

/// The raw [`u32`] underlying this [`Timestamp`].
///
/// Equivalent to [`Timestamp::new()`].
impl From<u32> for Timestamp {
    fn from(value: u32) -> Self {
        Timestamp::new(value)
    }
}

/// Construct [`Timestamp`] from a [`jiff::Timestamp`].
///
/// Precision is lost during the conversion because of the smaller storage
/// primitive.
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
/// on a Serial; addition and comparision.
///
/// The type is used as a backend for [`SoaSerial`] and [`Timestamp`].
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
    // Incrementing the [`SeqNumberU32`] by more than one serveres little
    // purpose and might be achived easier by constructing it from a primitive
    // number.
    //
    // [RFC1982] states that the maxmimum allowed increment is `(2^31)-1`. A
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
    /// The comparison of serial number values is defined in Section 3.2 of
    /// [RFC1982].
    ///
    /// The comparison is special because the sequence number might wrap
    /// around after reaching the maxima. The maximum difference between two
    /// numbers is limited to less than 2^31. If two numbers are exactly 2^31
    /// apart the order is undefined.
    ///
    /// None -> this.abs_diff(other) == 2^31
    /// Some(Ordering::Equal) -> this == other
    /// Some(Ordering::Less) -> this < other and (other - this) < 2^31
    ///                         // 1 < 10 and 10 - 1 < 2^31
    ///                         or
    ///                         this > other and (this - other) > 2^31
    ///                         // u32::MAX > 1 and u32::MAX - 1 > 2^31
    /// Some(Ordering::Greater) -> this > other and (this - other) < 2^31
    ///                         // 10 > 1 and 10 - 1 < 2^31
    ///                         or
    ///                         this < other and (this - other) > 2^31
    ///                         // 10 < u32::MAX and u32::MAX - 1 > 2^31
    ///
    /// [RFC1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
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
impl From<SeqNumberU32> for u32 {
    fn from(value: SeqNumberU32) -> u32 {
        value.get()
    }
}

/// The raw [`u32`] underlying this [`SeqNumberU32`].
///
/// Equivalent to [`SeqNumberU32::new()`].
impl From<u32> for SeqNumberU32 {
    fn from(value: u32) -> Self {
        SeqNumberU32::new(value)
    }
}

//----------- Serial ---------------------------------------------------------

/// Serial number arithmetic.
///
/// [`Serial`] implements the "Serial number arithmetic" defined in [RFC1982]
/// with a `SERIAL_BITS` value of 32.
///
/// [`Serial`] should not be used interchangably or be confused with the SOA
/// Serial Number, which is a [`Serial`] but not the sole user of "Serial
/// number arithmetic".
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
pub struct Serial(pub U32);

//--- Construction

impl Serial {
    /// Construct a new [`Serial`]
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Serial(U32::new(value))
    }

    /// Get [`u32`] value of [`Serial`]
    #[must_use]
    pub const fn get(&self) -> u32 {
        self.0.get()
    }

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
    /// The number must be in the range `[0, 2^31 - 1]`. An [`i32`] is used
    /// instead of a [`u32`] because it is easier to understand and implement
    /// a non-negative check versus the upper range check.
    ///
    /// Section 7 in [RFC1982] states, in particular for the SOA Serial
    /// Number, but for any Serial number using a "SERIAL_BITS" value of 32:
    /// "The maximum defined increment is 2147483647 (2^31 - 1)."
    ///
    /// # Panics
    ///
    /// Panics if the number is negative.
    ///
    /// [RFC1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-7
    pub fn inc(self, num: i32) -> Self {
        assert!(num >= 0, "Cannot subtract from a `Serial`");
        self.0.get().wrapping_add_signed(num).into()
    }
}

//--- Ordering

impl PartialOrd for Serial {
    /// The comparison of Serial Number values is defined in Section 3.2
    /// [RFC1982].
    ///
    /// [RFC1982]: https://datatracker.ietf.org/doc/html/rfc1982#section-3.2
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
