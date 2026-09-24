//! The DNSKEY record data type.

use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};

use crate::{
    new::base::{
        CanonicalRecordData, ParseRecordData, ParseRecordDataBytes, RType,
        build::BuildInMessage,
        name::NameCompressor,
        wire::{
            AsBytes, BuildBytes, ParseBytes, ParseBytesZC, ParseError,
            SplitBytes, SplitBytesZC, TruncationError, U16,
        },
    },
    utils::dst::UnsizedCopy,
};

use super::SecAlg;

//----------- DNSKey ---------------------------------------------------------

/// A cryptographic key for DNS security.
///
/// In DNSSEC, cryptographic key pairs are used to sign and validate resource
/// record sets (RRsets). The public part of the key pair is stored in a
/// [`DNSKey`] record.
///
/// There exist different variations of [`DNSKey`] records, which are
/// distinguished by their flags ([`DNSKeyFlags`]). The "Zone Key" flag
/// ([`DNSKeyFlags::is_zone_key()`]) and the "Secure Entry Point" flag
/// ([`DNSKeyFlags::is_secure_entry_point()`]) are commonly used.
///
/// Keys with the "Zone Key" flag set are used for signing RRsets. The
/// resulting signatures are stored in an [`Rrsig`] record. If the bit is not
/// set, the key must not be used to verify RRSIGs that cover RRsets.
///
/// Keys with the "Secure Entry Point" flag set are intended for creating a
/// trust chain from the parent zone downwards. This trust is achieved by
/// storing the keys hash in the parent zone, in a [`Ds`] record. The flag is
/// advisory: validators must not change their validation behaviour based on
/// it.
///
/// See [`DNSKeyFlags`] for more details.
///
/// [`DNSKey`] is specified by [RFC 4034, section 2.1].
///
/// ## Wire format
///
/// The wire format of a [`DNSKey`] record consists of two bytes of
/// [`DNSKeyFlags`], one byte of `protocol`, one byte of [`SecAlg`] and the
/// public key bytes, which occupy the rest of the record data.
///
/// The memory layout of the [`DNSKey`] type is identical to its serialization
/// in the wire format. This means that it can be parsed from the wire format
/// in a zero-copy fashion, avoiding a copy of the key material.
///
/// ## Usage
///
/// Because [`DNSKey`] is a record data type, it is usually handled within an
/// enum like [`RecordData`]. This section describes how to use it
/// independently.
///
/// [`DNSKey`] is an unsized type; it cannot be constructed directly. It has
/// to be parsed from its wire format.
///
/// ```
/// # use domain::new::base::wire::ParseBytesZC;
/// # use domain::new::rdata::{DNSKey, SecAlg};
/// #
/// // A key with the "Secure Entry Point" and "Zone Key" flags set, using the
/// // RSASHA256 algorithm. The public key data is zeroed out here, it's not a
/// // valid RSA key.
/// let bytes = b"\
///     \x01\x01\
///     \x03\
///     \x08\
///     \x00\x00\x00\x00\x00\x00\x00\x00";
///
/// // Parse the record data from the wire format.
/// let dnskey = DNSKey::parse_bytes_by_ref(bytes).unwrap();
///
/// assert!(dnskey.flags.is_zone_key());
/// assert!(dnskey.flags.is_secure_entry_point());
/// assert_eq!(dnskey.protocol, 3);
/// assert_eq!(dnskey.algorithm, SecAlg { code: 8 });
/// ```
///
/// To serialize a [`DNSKey`] back into the wire format, use
/// [`BuildInMessage`] (which writes into a DNS message) or [`BuildBytes`].
///
/// [RFC 4034, section 2.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-2.1
/// [`RecordData`]: crate::new::rdata::RecordData
/// [`Rrsig`]: super::Rrsig
/// [`Ds`]: super::Ds
#[derive(Debug, AsBytes, BuildBytes, ParseBytesZC, UnsizedCopy)]
#[repr(C)]
pub struct DNSKey {
    /// Flags describing the usage of the key.
    pub flags: DNSKeyFlags,

    /// The protocol field.
    ///
    /// The `protocol` value is always `3`. No other value is allowed, and a
    /// key with another value must be treated as invalid during signature
    /// verification. The `protocol` value exists for backwards compatibility.
    pub protocol: u8,

    /// The cryptographic algorithm used by this key.
    ///
    /// The [`SecAlg`] value determines the cryptographic algorithm and the
    /// format of the `key` field.
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

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<DNSKey> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
    }
}

//--- Equality

impl PartialEq for DNSKey {
    fn eq(&self, other: &Self) -> bool {
        // All elements are compared bytewise.
        self.as_bytes() == other.as_bytes()
    }
}

impl Eq for DNSKey {}

//--- Hashing

impl Hash for DNSKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.as_bytes())
    }
}

//--- Parsing record data

impl<'a> ParseRecordData<'a> for &'a DNSKey {}

impl<'a> ParseRecordDataBytes<'a> for &'a DNSKey {
    fn parse_record_data_bytes(
        bytes: &'a [u8],
        rtype: RType,
    ) -> Result<Self, ParseError> {
        match rtype {
            RType::DNSKEY => Self::parse_bytes(bytes),
            _ => Err(ParseError),
        }
    }
}

//----------- DNSKeyFlags ----------------------------------------------------

/// Flags describing a [`DNSKey`].
///
/// The full list of assigned flags is available in IANAs [DNSKEY Flags]
/// registry. These flags may be combined to achieve the keys desired purpose.
///
/// [DNSKEY Flags]: https://www.iana.org/assignments/dnskey-flags/dnskey-flags.xhtml
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
