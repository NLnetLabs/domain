//! The RRSIG record data type.

use alloc::fmt;
use core::cmp::Ordering;
use std::cmp;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use domain_macros::*;

use crate::new::base::build::BuildInMessage;
use crate::new::base::name::{CanonicalName, Name, NameCompressor};
use crate::new::base::wire::{AsBytes, BuildBytes, TruncationError, U16};
use crate::new::base::{CanonicalRecordData, RType, Serial, TTL};

use super::SecAlg;

//----------- Rrsig ----------------------------------------------------------

/// A cryptographic signature on a DNS record set.
#[derive(Clone, Debug, PartialEq, Eq, Hash, BuildBytes, ParseBytes)]
pub struct Rrsig<'a> {
    /// The type of the RRset being signed.
    pub rtype: RType,

    /// The cryptographic algorithm used to construct the signature.
    pub algorithm: SecAlg,

    /// The number of labels in the signed RRset's owner name.
    pub labels: u8,

    /// The (original) TTL of the signed RRset.
    pub ttl: TTL,

    /// The point in time when the signature expires.
    pub expiration: Serial,

    /// The point in time when the signature was created.
    pub inception: Serial,

    /// The key tag of the key used to make the signature.
    pub keytag: U16,

    /// The name identifying the signer.
    pub signer: &'a Name,

    /// The serialized cryptographic signature.
    pub signature: &'a [u8],
}

//--- Interaction

impl Rrsig<'_> {
    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> Rrsig<'r> {
        use crate::utils::dst::copy_to_bump;

        Rrsig {
            signer: copy_to_bump(self.signer, bump),
            signature: bump.alloc_slice_copy(self.signature),
            ..self.clone()
        }
    }
}

//--- Canonical operations

impl CanonicalRecordData for Rrsig<'_> {
    fn cmp_canonical(&self, that: &Self) -> Ordering {
        let this_initial = (
            self.rtype,
            self.algorithm,
            self.labels,
            self.ttl,
            self.expiration.as_bytes(),
            self.inception.as_bytes(),
            self.keytag,
        );
        let that_initial = (
            that.rtype,
            that.algorithm,
            that.labels,
            that.ttl,
            that.expiration.as_bytes(),
            that.inception.as_bytes(),
            that.keytag,
        );
        this_initial
            .cmp(&that_initial)
            .then_with(|| self.signer.cmp_lowercase_composed(that.signer))
            .then_with(|| self.signature.cmp(that.signature))
    }
}

//--- Building in DNS messages

impl BuildInMessage for Rrsig<'_> {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let bytes = contents.get_mut(start..).ok_or(TruncationError)?;
        let rest = self.build_bytes(bytes)?.len();
        Ok(contents.len() - rest)
    }
}

//
// --- Functions to make it easier to transition for old base.
// These functions should be marked as deprecated when most the initial
// migration to new base has completed.
impl Rrsig<'_> {
    /// Return the RRtype that the signature covers.
    pub fn type_covered(&self) -> RType {
        self.rtype
    }

    /// Return the original TTL of signed RRset.
    pub fn original_ttl(&self) -> TTL {
        self.ttl
    }

    /// Return the key tag of the key that created the signature.
    pub fn key_tag(&self) -> u16 {
        self.keytag.into()
    }

    /// Return the expiration time of the signature.
    pub fn expiration(&self) -> Timestamp {
        Timestamp(self.expiration)
    }
}

//------------ Timestamp ------------------------------------------------------

/// A Timestamp for RRSIG Records.
///
/// DNS uses 32 bit timestamps that are conceptionally
/// viewed as the 32 bit modulus of a larger number space. Because of that,
/// special rules apply when processing these values.
///
/// [RFC 4034] defines Timestamps as the number of seconds elepased since
/// since 1 January 1970 00:00:00 UTC, ignoring leap seconds. Timestamps
/// are compared using so-called "Serial number arithmetic", as defined in
/// [RFC 1982].
///
/// The RFC defines the semantics for doing arithmetics in the
/// face of these wrap-arounds. This type implements these semantics atop a
/// native `u32`. The RFC defines two operations: addition and comparison.
///
/// For addition, the amount added can only be a positive number of up to
/// `2^31 - 1`. Because of this, we decided to not implement the
/// `Add` trait but rather have a dedicated method `add` so as to not cause
/// surprise panics.
///
/// Timestamps only implement a partial ordering. That is, there are
/// pairs of values that are not equal but there still isn’t one value larger
/// than the other. Since this is neatly implemented by the `PartialOrd`
/// trait, the type implements that.
///
/// [RFC 1982]: https://tools.ietf.org/html/rfc1982
/// [RFC 4034]: https://tools.ietf.org/html/rfc4034

#[derive(Clone, Copy, Debug, PartialEq)]
/*
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
*/
pub struct Timestamp(Serial);

impl Timestamp {
    /*
        /// Returns a serial number for the current Unix time.
        #[cfg(feature = "std")]
        #[must_use]
        pub fn now() -> Self {
            Self(Serial::now())
        }
    */

    /*
        /// Scan a serial represention signature time value.
        ///
        /// In [RRSIG] records, the expiration and inception times are given as
        /// serial values. Their representation format can either be the
        /// value or a specific date in `YYYYMMDDHHmmSS` format.
        ///
        /// [RRSIG]: Rrsig
        pub fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Error> {
            scanner.scan_ascii_str(|token| {
                if token.len() <= 10 {
                    let time = token.parse::<u32>().map_err(|_| {
                        S::Error::custom("illegal signature time")
                    })?;

                    Ok(Self(Serial(time)))
                } else if token.len() == 14 {
                    let time = jiff::fmt::strtime::parse("%Y%m%d%H%M%S", token)
                        .and_then(|mut time| {
                            // The timestamp did not explicitly state a time zone, so
                            // we have to manually mark it as UTC.
                            time.set_offset(Some(jiff::tz::Offset::UTC));
                            time.to_timestamp()
                        })
                        .map_err(|_| {
                            S::Error::custom("illegal signature time")
                        })?;

                    Ok(Self(Serial(time.as_second() as u32)))
                } else {
                    Err(S::Error::custom("illegal signature time"))
                }
            })
        }
    */

    /// Returns the timestamp as a raw integer.
    #[must_use]
    pub fn into_int(self) -> u32 {
        self.0.into()
    }

    /// Returns a [`SystemTime`] close to a reference time.
    ///
    /// The returned [`SystemTime`] meets the following requirements:
    ///
    /// 1) The [`SystemTime`] value has a duration since `UNIX_EPOCH` that
    ///    modulo `2**32` is equal to our [`Timestamp`] value.
    /// 2) The time difference between the [`SystemTime`] value and the
    ///    reference time fits in an [`i32`].
    ///
    /// This can be used to sort [`Timestamp`] values.
    #[must_use]
    #[cfg(feature = "std")]
    pub fn to_system_time(self, reference: SystemTime) -> SystemTime {
        // Timestamp is a 32-bit value. We cannot just add UNIX_EPOCH because
        // the timestamp may be too far in the future. We may have to add
        // n * 2**32 for some unknown value of n.
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

/*
/// # Parsing and Composing
///
impl Timestamp {
    pub const COMPOSE_LEN: u16 = Serial::COMPOSE_LEN;

    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<'_, Octs>,
    ) -> Result<Self, ParseError> {
        Serial::parse(parser).map(Self)
    }

    pub fn compose<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.0.compose(target)
    }
}
*/

//--- From and FromStr

impl From<u32> for Timestamp {
    fn from(item: u32) -> Self {
        Self(Serial::from(item))
    }
}

/*
impl str::FromStr for Timestamp {
    type Err = IllegalSignatureTime;

    /// Parses a timestamp value from a string.
    ///
    /// The presentation format can either be their integer value or a
    /// specific date in `YYYYMMDDHHmmSS` format.
    fn from_str(src: &str) -> Result<Self, Self::Err> {
        if !src.is_ascii() {
            return Err(IllegalSignatureTime(()));
        }
        if src.len() == 14 {
            let time = jiff::fmt::strtime::parse("%Y%m%d%H%M%S", src)
                .and_then(|mut time| {
                    // The timestamp did not explicitly state a time zone, so
                    // we have to manually mark it as UTC.
                    time.set_offset(Some(jiff::tz::Offset::UTC));
                    time.to_timestamp()
                })
                .map_err(|_| IllegalSignatureTime(()))?;

            Ok(Self(Serial(time.as_second() as u32)))
        } else {
            Serial::from_str(src)
                .map(Timestamp)
                .map_err(|_| IllegalSignatureTime(()))
        }
    }
}
*/

//--- Display

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

//--- ZonefileFmt

/*
impl ZonefileFmt for Timestamp {
    fn fmt(&self, p: &mut impl Formatter) -> zonefile_fmt::Result {
        p.write_token(self.0)
    }
}
*/

//--- PartialOrd and CanonicalOrd

impl cmp::PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

/*
impl CanonicalOrd for Timestamp {
    fn canonical_cmp(&self, other: &Self) -> cmp::Ordering {
        self.0.canonical_cmp(&other.0)
    }
}
*/

impl From<Timestamp> for crate::rdata::dnssec::Timestamp {
    fn from(ts: Timestamp) -> Self {
        let v: u32 = ts.0.into();
        v.into()
    }
}
