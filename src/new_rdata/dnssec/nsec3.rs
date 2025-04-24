//! The NSEC3 and NSEC3PARAM record data types.

use core::{cmp::Ordering, fmt};

use domain_macros::*;

use crate::new_base::{
    wire::{AsBytes, SizePrefixed, U16},
    CanonicalRecordData,
};

use super::TypeBitmaps;

//----------- NSec3 ----------------------------------------------------------

/// An indication of the non-existence of a set of DNS records (version 3).
#[derive(Clone, Debug, PartialEq, Eq, BuildBytes, ParseBytes)]
pub struct NSec3<'a> {
    /// The algorithm used to hash names.
    pub algorithm: NSec3HashAlg,

    /// Flags modifying the behaviour of the record.
    pub flags: NSec3Flags,

    /// The number of iterations of the underlying hash function per name.
    pub iterations: U16,

    /// The salt used to randomize the hash function.
    pub salt: &'a SizePrefixed<u8, [u8]>,

    /// The name of the next existing DNS record.
    pub next: &'a SizePrefixed<u8, [u8]>,

    /// The types of the records that exist at this owner name.
    pub types: &'a TypeBitmaps,
}

//--- Interaction

impl NSec3<'_> {
    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> NSec3<'r> {
        use crate::utils::dst::copy_to_bump;

        NSec3 {
            algorithm: self.algorithm,
            flags: self.flags,
            iterations: self.iterations,
            salt: copy_to_bump(self.salt, bump),
            next: copy_to_bump(self.next, bump),
            types: copy_to_bump(self.types, bump),
        }
    }
}

//--- Canonical operations

impl CanonicalRecordData for NSec3<'_> {
    fn cmp_canonical(&self, that: &Self) -> Ordering {
        let this = (
            self.algorithm,
            self.flags.as_bytes(),
            self.iterations,
            self.salt.len(),
            self.salt,
            self.next.len(),
            self.next,
            self.types.as_bytes(),
        );
        let that = (
            that.algorithm,
            that.flags.as_bytes(),
            that.iterations,
            that.salt.len(),
            that.salt,
            that.next.len(),
            that.next,
            that.types.as_bytes(),
        );
        this.cmp(&that)
    }
}

//----------- NSec3Param -----------------------------------------------------

/// Parameters for computing [`NSec3`] records.
#[derive(
    Debug,
    PartialEq,
    Eq,
    AsBytes,
    BuildBytes,
    ParseBytesZC,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(C)]
pub struct NSec3Param {
    /// The algorithm used to hash names.
    pub algorithm: NSec3HashAlg,

    /// Flags modifying the behaviour of the record.
    pub flags: NSec3Flags,

    /// The number of iterations of the underlying hash function per name.
    pub iterations: U16,

    /// The salt used to randomize the hash function.
    pub salt: SizePrefixed<u8, [u8]>,
}

impl CanonicalRecordData for NSec3Param {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

//----------- NSec3HashAlg ---------------------------------------------------

/// The hash algorithm used with [`NSec3`] records.
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
pub struct NSec3HashAlg {
    /// The algorithm code.
    pub code: u8,
}

//--- Associated Constants

impl NSec3HashAlg {
    /// The SHA-1 algorithm.
    pub const SHA1: Self = Self { code: 1 };
}

//--- Formatting

impl fmt::Debug for NSec3HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::SHA1 => "NSec3HashAlg::SHA1",
            _ => return write!(f, "NSec3HashAlg({})", self.code),
        })
    }
}

//----------- NSec3Flags -----------------------------------------------------

/// Flags modifying the behaviour of an [`NSec3`] record.
#[derive(
    Copy,
    Clone,
    Default,
    Hash,
    PartialEq,
    Eq,
    AsBytes,
    BuildBytes,
    ParseBytes,
    ParseBytesZC,
    SplitBytes,
    SplitBytesZC,
    UnsizedCopy,
)]
#[repr(transparent)]
pub struct NSec3Flags {
    /// The raw flag bits.
    inner: u8,
}

//--- Interaction

impl NSec3Flags {
    /// Get the specified flag bit.
    fn get_flag(&self, pos: u32) -> bool {
        self.inner & (1 << pos) != 0
    }

    /// Set the specified flag bit.
    fn set_flag(mut self, pos: u32, value: bool) -> Self {
        self.inner &= !(1 << pos);
        self.inner |= (value as u8) << pos;
        self
    }

    /// The raw flags bits.
    pub fn bits(&self) -> u8 {
        self.inner
    }

    /// Whether unsigned delegations can exist in the covered range.
    pub fn is_optout(&self) -> bool {
        self.get_flag(0)
    }

    /// Allow unsigned delegations to exist in the covered raneg.
    pub fn set_optout(self, value: bool) -> Self {
        self.set_flag(0, value)
    }
}

//--- Formatting

impl fmt::Debug for NSec3Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NSec3Flags")
            .field("optout", &self.is_optout())
            .field("bits", &self.bits())
            .finish()
    }
}
