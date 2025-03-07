//! Record types relating to DNSSEC.

use core::fmt;

use domain_macros::*;

//----------- Submodules -----------------------------------------------------

mod dnskey;
pub use dnskey::DNSKey;

mod rrsig;
pub use rrsig::RRSig;

mod nsec;
pub use nsec::{NSec, TypeBitmaps};

mod nsec3;
pub use nsec3::{NSec3, NSec3Flags, NSec3HashAlg};

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
