//! The DNSKEY record data type.

use core::{cmp::Ordering, fmt};

use domain_macros::*;

use crate::new::base::{
    build::BuildInMessage,
    name::NameCompressor,
    wire::{AsBytes, TruncationError, U16},
    CanonicalRecordData,
};

use super::SecAlg;

//----------- DNSKey ---------------------------------------------------------

/// A cryptographic key for DNS security.
#[derive(
    Debug, PartialEq, Eq, AsBytes, BuildBytes, ParseBytesZC, UnsizedCopy,
)]
#[repr(C)]
pub struct DNSKey {
    /// Flags describing the usage of the key.
    pub flags: DNSKeyFlags,

    /// The protocol version of the key.
    pub protocol: u8,

    /// The cryptographic algorithm used by this key.
    pub algorithm: SecAlg,

    /// The serialized public key.
    pub key: [u8],
}

//--- Canonical operations

impl CanonicalRecordData for DNSKey {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.as_bytes().cmp(other.as_bytes())
    }
}

//--- Building in DNS messages

impl BuildInMessage for DNSKey {
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

//----------- DNSKeyFlags ----------------------------------------------------

/// Flags describing a [`DNSKey`].
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
pub struct DNSKeyFlags {
    /// The raw flag bits.
    inner: U16,
}

//--- Interaction

impl DNSKeyFlags {
    /// Get the specified flag bit.
    fn get_flag(&self, pos: u32) -> bool {
        self.inner.get() & (1 << pos) != 0
    }

    /// Set the specified flag bit.
    fn set_flag(mut self, pos: u32, value: bool) -> Self {
        self.inner &= !(1 << pos);
        self.inner |= (value as u16) << pos;
        self
    }

    /// The raw flags bits.
    pub fn bits(&self) -> u16 {
        self.inner.get()
    }

    /// Whether this key is used for signing DNS records.
    pub fn is_zone_key(&self) -> bool {
        self.get_flag(8)
    }

    /// Make this key usable for signing DNS records.
    pub fn set_zone_key(self, value: bool) -> Self {
        self.set_flag(8, value)
    }

    /// Whether external entities are expected to point to this key.
    pub fn is_secure_entry_point(&self) -> bool {
        self.get_flag(0)
    }

    /// Expect external entities to point to this key.
    pub fn set_secure_entry_point(self, value: bool) -> Self {
        self.set_flag(0, value)
    }
}

//--- Formatting

impl fmt::Debug for DNSKeyFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DNSKeyFlags")
            .field("zone_key", &self.is_zone_key())
            .field("secure_entry_point", &self.is_secure_entry_point())
            .field("bits", &self.bits())
            .finish()
    }
}
