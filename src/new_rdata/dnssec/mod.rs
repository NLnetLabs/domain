//! Record types relating to DNSSEC.

use core::fmt;

use domain_macros::*;

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

//----------- Submodules -----------------------------------------------------

mod dnskey;
pub use dnskey::{DNSKey, DNSKeyFlags};

mod rrsig;
pub use rrsig::RRSig;

mod nsec;
pub use nsec::{NSec, TypeBitmaps};

mod nsec3;
pub use nsec3::{NSec3, NSec3Flags, NSec3HashAlg, NSec3Param};

mod ds;
pub use ds::{DigestType, Ds};

//----------- SecAlg ---------------------------------------------------------

/// A cryptographic algorithm for DNS security.
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct SecAlg {
    /// The algorithm code.
    pub code: u8,
}

//--- Associated Constants

impl SecAlg {
    /// The DSA/SHA-1 algorithm.
    pub const DSA_SHA1: Self = Self { code: 3 };

    /// The RSA/SHA-1 algorithm.
    pub const RSA_SHA1: Self = Self { code: 5 };
}

//--- Conversion to and from 'u8'

impl From<u8> for SecAlg {
    fn from(value: u8) -> Self {
        Self { code: value }
    }
}

impl From<SecAlg> for u8 {
    fn from(value: SecAlg) -> Self {
        value.code
    }
}

//--- Formatting

impl fmt::Debug for SecAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::DSA_SHA1 => "SecAlg::DSA_SHA1",
            Self::RSA_SHA1 => "SecAlg::RSA_SHA1",
            _ => return write!(f, "SecAlg({})", self.code),
        })
    }
}

//--- Scanning from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for SecAlg {
    fn scan(
        scanner: &mut Scanner<'_>,
        _alloc: &'a bumpalo::Bump,
        _buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        match scanner.scan_plain_token()? {
            "DSA" => Ok(Self::DSA_SHA1),
            "RSASHA1" => Ok(Self::RSA_SHA1),

            alg if alg.chars().all(|c| c.is_ascii_digit()) => {
                Ok(alg.parse::<u8>().unwrap().into())
            }

            _ => Err(ScanError::Custom("unrecognized DNSSEC algorithm")),
        }
    }
}
