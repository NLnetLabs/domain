//! The NSEC3 and NSEC3PARAM record data types.

use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};

use domain_macros::*;

use crate::{
    new::base::{
        CanonicalRecordData,
        build::BuildInMessage,
        name::NameCompressor,
        wire::{AsBytes, BuildBytes, SizePrefixed, TruncationError, U16},
    },
    utils::dst::UnsizedCopy,
};

use super::TypeBitmaps;

//----------- Nsec3 ----------------------------------------------------------

/// An indication of the non-existence of a set of DNS records (version 3).
#[derive(Clone, Debug, PartialEq, Eq, Hash, BuildBytes, ParseBytes)]
pub struct Nsec3<'a> {
    /// The algorithm used to hash names.
    pub algorithm: Nsec3HashAlgorithm,

    /// Flags modifying the behaviour of the record.
    pub flags: Nsec3Flags,

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

impl Nsec3<'_> {
    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> Nsec3<'r> {
        use crate::utils::dst::copy_to_bump;

        Nsec3 {
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

impl CanonicalRecordData for Nsec3<'_> {
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

//--- Building in DNS messages

impl BuildInMessage for Nsec3<'_> {
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

//----------- Nsec3Param -----------------------------------------------------

/// Parameters for computing [`Nsec3`] records.
#[derive(
    Debug, AsBytes, BuildBytes, ParseBytesZC, SplitBytesZC, UnsizedCopy,
)]
#[repr(C)]
pub struct Nsec3Param {
    /// The algorithm used to hash names.
    pub algorithm: Nsec3HashAlgorithm,

    /// Flags modifying the behaviour of the record.
    pub flags: Nsec3Flags,

    /// The number of iterations of the underlying hash function per name.
    pub iterations: U16,

    /// The salt used to randomize the hash function.
    pub salt: SizePrefixed<u8, [u8]>,
}

impl CanonicalRecordData for Nsec3Param {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

//--- Building in DNS messages

impl BuildInMessage for Nsec3Param {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
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

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<Nsec3Param> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
    }
}

//--- Equality

impl PartialEq for Nsec3Param {
    fn eq(&self, other: &Self) -> bool {
        // All elements are compared bytewise.
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for Nsec3Param {}

//--- Hashing

impl Hash for Nsec3Param {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.as_bytes())
    }
}

//----------- Nsec3HashAlgorithm ---------------------------------------------

/// The hash algorithm used with [`Nsec3`] records.
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
pub struct Nsec3HashAlgorithm {
    /// The algorithm code.
    pub code: u8,
}

//--- Associated Constants

impl Nsec3HashAlgorithm {
    /// The SHA-1 algorithm.
    pub const SHA1: Self = Self { code: 1 };
}

//--- Formatting

impl fmt::Debug for Nsec3HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::SHA1 => "Nsec3HashAlgorithm::SHA1",
            _ => return write!(f, "Nsec3HashAlgorithm({})", self.code),
        })
    }
}

//----------- Nsec3Flags -----------------------------------------------------

/// Flags modifying the behaviour of an [`Nsec3`] record.
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
pub struct Nsec3Flags {
    /// The raw flag bits.
    inner: u8,
}

//--- Interaction

impl Nsec3Flags {
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

impl fmt::Debug for Nsec3Flags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Nsec3Flags")
            .field("optout", &self.is_optout())
            .field("bits", &self.bits())
            .finish()
    }
}

//
// --- Functions to make it easier to transition from old base.
// These functions should be marked as deprecated when most of the initial
// migration to new base has completed.
impl<'a> Nsec3<'a> {
    /// Constructor for Nsec3.
    pub fn new(hash_algorithm: Nsec3HashAlgorithm, flags: Nsec3Flags, iterations: u16, salt: &'a SizePrefixed<u8, [u8]>, next_owner: &'a SizePrefixed<u8, [u8]>, types: &'a TypeBitmaps) -> Self {
        Self { algorithm: hash_algorithm, flags, iterations: iterations.into(), salt, next: next_owner, types }
    }

    /// Return the RRtypes that are present.
    pub fn types(&self) -> &TypeBitmaps {
        self.types
    }

    /// Return the name of the next NSEC3 record in the chain.
    // TODO: define an OwnerHash wrapper type to avoid using just a squence
    // of bytes.
    pub fn next_owner(&self) -> &SizePrefixed<u8, [u8]> {
        self.next
    }
}

impl Nsec3Param {
    /// Return the hash algorithm.
    pub fn hash_algorithm(&self) -> Nsec3HashAlgorithm {
	self.algorithm
    }

    /// Return the flags.
    pub fn flags(&self) -> Nsec3Flags {
	self.flags
    }

    /// Return whether the opt-out flag is set.
    pub fn opt_out_flag(&self) -> bool {
	self.flags.is_optout()
    }

    /// Return the number of extra hash iterations.
    pub fn iterations(&self) -> u16 {
	self.iterations.into()
    }

    /// Return the salt.
    pub fn salt(&self) -> &SizePrefixed<u8, [u8]> {
	&self.salt
    }
}

