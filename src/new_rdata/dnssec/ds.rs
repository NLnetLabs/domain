use core::fmt;

use domain_macros::*;

use crate::new_base::wire::U16;

#[cfg(feature = "zonefile")]
use crate::{new_base::wire::ParseBytesByRef, utils::decoding::Base16Dec};

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

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

//--- Interaction

impl Ds {
    /// Copy this into the given [`Bump`] allocator.
    #[cfg(feature = "bumpalo")]
    #[allow(clippy::mut_from_ref)] // using a memory allocator
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> &'r mut Self {
        use crate::new_base::wire::{AsBytes, ParseBytesByRef};

        let bytes = bump.alloc_slice_copy(self.as_bytes());
        // SAFETY: 'ParseBytesByRef' and 'AsBytes' are inverses.
        unsafe { Self::parse_bytes_by_mut(bytes).unwrap_unchecked() }
    }
}

//--- Scanning from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for &'a Ds {
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let keytag = u16::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let algorithm = SecAlg::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let digest_type = DigestType::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }

        // Decode the digest from Base16 words.
        let start = buffer.len();
        let mut decoder = Base16Dec::new();
        while !scanner.is_empty() {
            let token = scanner.scan_plain_token()?;
            scanner.skip_ws();

            decoder
                .decode_to_vec(token.as_bytes(), buffer)
                .map_err(|_| ScanError::Custom("Invalid Base16 in digest"))?;
        }
        decoder.finish().map_err(|_| {
            ScanError::Custom("Partial byte in Base16-encoded digest")
        })?;

        // Allocate the record.
        let record =
            alloc.alloc_slice_fill_copy(4 + buffer.len() - start, 0u8);
        record[0..2].copy_from_slice(&keytag.to_be_bytes());
        record[2] = algorithm.into();
        record[3] = digest_type.into();
        record[4..].copy_from_slice(&buffer[start..]);

        buffer.truncate(start);
        Ok(Ds::parse_bytes_by_ref(record).unwrap())
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

//--- Conversion to and from 'u8'

impl From<u8> for DigestType {
    fn from(value: u8) -> Self {
        Self { code: value }
    }
}

impl From<DigestType> for u8 {
    fn from(value: DigestType) -> Self {
        value.code
    }
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

//--- Scanning from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for DigestType {
    fn scan(
        scanner: &mut Scanner<'_>,
        _alloc: &'a bumpalo::Bump,
        _buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        use core::num::IntErrorKind;

        scanner
            .scan_plain_token()?
            .parse::<u8>()
            .map_err(|err| {
                ScanError::Custom(match err.kind() {
                    IntErrorKind::PosOverflow | IntErrorKind::NegOverflow => {
                        "Invalid digest algorithm number"
                    }
                    IntErrorKind::InvalidDigit => {
                        "Digest algorithm must be a number"
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
        use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

        use super::Ds;

        let cases = [
            (
                b"60485 5 1 2BB183AF5F22588179A53B0A 98631FAD1A292118" as &[u8],
                Ok((
                    60485,
                    5,
                    1,
                    b"\x2B\xB1\x83\xAF\x5F\x22\x58\x81\x79\xA5\x3B\x0A\x98\x63\x1F\xAD\x1A\x29\x21\x18" as &[u8],
                )),
            ),
            (b"60000" as &[u8], Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            assert_eq!(
                <&Ds>::scan(&mut scanner, &alloc, &mut buffer).map(|ds| (
                    ds.keytag.get(),
                    ds.algorithm.into(),
                    ds.digest_type.into(),
                    &ds.digest
                )),
                expected
            );
        }
    }
}
