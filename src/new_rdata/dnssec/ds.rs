use core::fmt;

use domain_macros::*;

use crate::new_base::wire::U16;

use super::SecAlg;

//----------- Ds -------------------------------------------------------------

/// The signing key for a delegated zone.
#[derive(Debug, PartialEq, Eq, AsBytes, BuildBytes, ParseBytesByRef)]
#[repr(C)]
pub struct Ds {
    /// The key tag of the signing key.
    pub keytag: U16,

    /// The cryptographic algorithm used by the signing key.
    pub algorithm: SecAlg,

    /// The algorithm used to calculate the key digest.
    pub digest_type: DigestType,

    /// A serialized digest of the signing key.
    pub digest: [u8],
}

//----------- DigestType -----------------------------------------------------

/// A cryptographic digest algorithm.
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
pub struct DigestType {
    /// The algorithm code.
    pub code: u8,
}

//--- Associated Constants

impl DigestType {
    /// The SHA-1 algorithm.
    pub const SHA1: Self = Self { code: 1 };
}

//--- Formatting

impl fmt::Debug for DigestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::SHA1 => "DigestType::SHA1",
            _ => return write!(f, "DigestType({})", self.code),
        })
    }
}
