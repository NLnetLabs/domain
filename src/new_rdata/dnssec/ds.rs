//! The DS record data type.

use core::{cmp::Ordering, fmt};

use domain_macros::*;

use crate::new_base::build::{
    BuildInMessage, NameCompressor, TruncationError,
};
use crate::new_base::wire::{AsBytes, U16};
use crate::new_base::CanonicalRecordData;

use super::SecAlg;

//----------- Ds -------------------------------------------------------------

/// The signing key for a delegated zone.
#[derive(
    Debug, PartialEq, Eq, AsBytes, BuildBytes, ParseBytesZC, UnsizedCopy,
)]
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

//--- Canonical operations

impl CanonicalRecordData for Ds {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

//--- Building in DNS messages

impl BuildInMessage for Ds {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _name: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let bytes = self.as_bytes();
        let end = start + bytes.len();
        contents
            .get_mut(start..end)
            .ok_or(TruncationError)?
            .copy_from_slice(bytes);
        Ok(end)
    }
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
    ParseBytesZC,
    SplitBytes,
    SplitBytesZC,
    UnsizedCopy,
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
