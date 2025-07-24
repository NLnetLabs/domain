//! The DNSKEY record data type.

use core::{cmp::Ordering, fmt};

use crate::{
    new::base::{
        build::BuildInMessage,
        name::NameCompressor,
        wire::{
            AsBytes, BuildBytes, ParseBytes, ParseBytesZC, SplitBytes,
            SplitBytesZC, TruncationError, U16,
        },
        CanonicalRecordData,
    },
    utils::dst::UnsizedCopy,
};

#[cfg(feature = "zonefile")]
use crate::utils::decoding::Base64Dec;

#[cfg(feature = "zonefile")]
use crate::new::zonefile::scanner::{Scan, ScanError, Scanner};

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

//--- Scanning from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for &'a DNSKey {
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let flags = DNSKeyFlags::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let protocol = u8::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let algorithm = SecAlg::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }

        let start = buffer.len();
        buffer.extend_from_slice(flags.as_bytes());
        buffer.extend_from_slice(protocol.as_bytes());
        buffer.extend_from_slice(algorithm.as_bytes());

        let mut decoder = Base64Dec::new();
        while !scanner.is_empty() {
            let token = scanner.scan_plain_token()?;
            scanner.skip_ws();

            decoder.decode_to_vec(token.as_bytes(), buffer).map_err(
                |_| ScanError::Custom("invalid Base64 in DNSKEY material"),
            )?;
        }
        decoder.finish(&mut [], false).map_err(|_| {
            ScanError::Custom(
                "partial block in Base64-encoded DNSKEY material",
            )
        })?;

        let record = alloc.alloc_slice_copy(&buffer[start..]);
        let record = DNSKey::parse_bytes_by_ref(record)
            .expect("A valid 'DNSKey' has been built");
        buffer.truncate(start);

        Ok(record)
    }
}

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<DNSKey> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
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

//--- Conversion to and from 'u16'

impl From<u16> for DNSKeyFlags {
    fn from(value: u16) -> Self {
        Self {
            inner: U16::new(value),
        }
    }
}

impl From<DNSKeyFlags> for u16 {
    fn from(value: DNSKeyFlags) -> Self {
        value.inner.get()
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

//--- Scanning from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for DNSKeyFlags {
    fn scan(
        scanner: &mut Scanner<'_>,
        _alloc: &'a bumpalo::Bump,
        _buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        use core::num::IntErrorKind;

        scanner
            .scan_plain_token()?
            .parse::<u16>()
            .map_err(|err| {
                ScanError::Custom(match err.kind() {
                    IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => {
                        "invalid NSEC3 flags number"
                    }
                    IntErrorKind::InvalidDigit => {
                        "NSEC3 flags must be a number"
                    }
                    // We have already checked for other kinds of errors.
                    _ => unreachable!(),
                })
            })
            .map(Self::from)
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    #[cfg(feature = "zonefile")]
    #[test]
    fn scan() {
        use crate::new::zonefile::scanner::{Scan, ScanError, Scanner};

        use super::DNSKey;

        let cases = [
            (
                b"256 3 5 AQPSKmynfzW4kyBv015MUG2DeIQ3" as &[u8],
                Ok((
                    256,
                    3,
                    5,
                    b"\x01\x03\xD2\x2A\x6C\xA7\x7F\x35\xB8\x93\x20\x6F\xD3\x5E\x4C\x50\x6D\x83\x78\x84\x37" as &[u8],
                )),
            ),
            (b"256" as &[u8], Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            assert_eq!(
                <&DNSKey>::scan(&mut scanner, &alloc, &mut buffer).map(|r| (
                    r.flags.into(),
                    r.protocol,
                    r.algorithm.into(),
                    &r.key,
                )),
                expected
            );
        }
    }
}
