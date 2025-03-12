use core::fmt;

use domain_macros::*;

use crate::new_base::wire::{SizePrefixed, U16};

#[cfg(feature = "zonefile")]
use crate::{
    new_base::wire::{AsBytes, ParseBytesByRef},
    utils::decoding::{Base16Dec, Base32HexDec},
};

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

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
    /// Copy referenced data into the given [`Bump`] allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> NSec3<'r> {
        NSec3 {
            algorithm: self.algorithm,
            flags: self.flags,
            iterations: self.iterations,
            salt: self.salt.clone_to_bump(bump),
            next: self.next.clone_to_bump(bump),
            types: self.types.clone_to_bump(bump),
        }
    }
}

//--- Scanning from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for NSec3<'a> {
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let algorithm = Scan::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let flags = Scan::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let iterations = Scan::scan(scanner, alloc, buffer).map(U16::new)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }

        let start = buffer.len();
        buffer.push(0);
        let salt = scanner.scan_plain_token()?;
        if salt != "-" {
            let salt_len =
                Base16Dec::decode_all_to_vec(salt.as_bytes(), buffer)
                    .map_err(|_| {
                        ScanError::Custom("Invalid NSEC3 salt (base16)")
                    })?
                    .len();
            buffer[start] = salt_len as u8;
        }
        let salt = alloc.alloc_slice_copy(&buffer[start..]);
        let salt = SizePrefixed::parse_bytes_by_ref(salt)
            .expect("A valid size-prefixed slice has been built");
        buffer.truncate(start);
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }

        let start = buffer.len();
        buffer.push(0);
        let next = scanner.scan_plain_token()?;
        let next_len =
            Base32HexDec::decode_all_to_vec(next.as_bytes(), buffer, false)
                .map_err(|_| {
                    ScanError::Custom("Invalid next owner name (base32hex)")
                })?
                .len();
        buffer[start] = next_len as u8;
        let next = alloc.alloc_slice_copy(&buffer[start..]);
        let next = SizePrefixed::parse_bytes_by_ref(next)
            .expect("A valid size-prefixed slice has been built");
        buffer.truncate(start);
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }

        let types = <&'a TypeBitmaps>::scan(scanner, alloc, buffer)?;

        Ok(Self {
            algorithm,
            flags,
            iterations,
            salt,
            next,
            types,
        })
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
    ParseBytesByRef,
    SplitBytesByRef,
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

//--- Interaction

impl NSec3Param {
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
impl<'a> Scan<'a> for &'a NSec3Param {
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let algorithm = NSec3HashAlg::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let flags = NSec3Flags::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let iterations = u16::scan(scanner, alloc, buffer).map(U16::new)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }

        let start = buffer.len();
        buffer.extend_from_slice(algorithm.as_bytes());
        buffer.extend_from_slice(flags.as_bytes());
        buffer.extend_from_slice(iterations.as_bytes());

        let salt_start = buffer.len();
        buffer.push(0);
        let salt = scanner.scan_plain_token()?;
        if salt != "-" {
            let salt_len =
                Base16Dec::decode_all_to_vec(salt.as_bytes(), buffer)
                    .map_err(|_| {
                        ScanError::Custom("Invalid NSEC3 salt (base16)")
                    })?
                    .len();
            buffer[salt_start] = salt_len as u8;
        }

        let record = alloc.alloc_slice_copy(&buffer[start..]);
        let record = NSec3Param::parse_bytes_by_ref(record)
            .expect("A valid 'NSec3Param' has been built");
        buffer.truncate(start);

        Ok(record)
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
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
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

//--- Conversion to and from 'u8'

impl From<u8> for NSec3HashAlg {
    fn from(value: u8) -> Self {
        Self { code: value }
    }
}

impl From<NSec3HashAlg> for u8 {
    fn from(value: NSec3HashAlg) -> Self {
        value.code
    }
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

//--- Scanning from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for NSec3HashAlg {
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
                        "Invalid NSEC3 hash algorithm number"
                    }
                    IntErrorKind::InvalidDigit => {
                        "NSEC3 hash algorithm must be a number"
                    }
                    // We have already checked for other kinds of errors.
                    _ => unreachable!(),
                })
            })
            .map(Self::from)
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
    ParseBytesByRef,
    SplitBytes,
    SplitBytesByRef,
)]
#[repr(transparent)]
pub struct NSec3Flags {
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

//--- Conversion to and from 'u8'

impl From<u8> for NSec3Flags {
    fn from(value: u8) -> Self {
        Self { inner: value }
    }
}

impl From<NSec3Flags> for u8 {
    fn from(value: NSec3Flags) -> Self {
        value.inner
    }
}

//--- Scanning from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for NSec3Flags {
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
                        "Invalid NSEC3 flags number"
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
    use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

    #[cfg(feature = "zonefile")]
    #[test]
    fn scan() {
        use crate::{new_base::RType, utils::CmpIter};

        use super::NSec3;

        let cases = [
            (
                b"1 1 12 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr MX DNSKEY NS SOA NSEC3PARAM RRSIG" as &[u8],
                Ok((
                    1,
                    1,
                    12,
                    b"\xAA\xBB\xCC\xDD" as &[u8],
                    b"\x17\x4E\xB2\x40\x9F\xE2\x8B\xCB\x48\x87\xA1\x83\x6F\x95\x7F\x0A\x84\x25\xE2\x7B" as &[u8],
                    &const {[RType::NS, RType::SOA, RType::MX, RType::RRSIG, RType::DNSKEY, RType::NSEC3PARAM]} as &[RType],
                )),
            ),
            (b"1" as &[u8], Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            let actual = NSec3::scan(&mut scanner, &alloc, &mut buffer);

            assert_eq!(expected.as_ref().err(), actual.as_ref().err());
            if let (Ok(expected), Ok(actual)) = (expected, actual) {
                let (algorithm, flags, iterations, salt, next, types) =
                    expected;
                assert_eq!(algorithm, actual.algorithm.code);
                assert_eq!(flags, u8::from(actual.flags));
                assert_eq!(iterations, actual.iterations.get());
                assert_eq!(salt, &**actual.salt);
                assert_eq!(next, &**actual.next);
                assert_eq!(
                    CmpIter(types.iter().copied()),
                    CmpIter(actual.types)
                );
            }
        }
    }

    #[cfg(feature = "zonefile")]
    #[test]
    fn scan_param() {
        use super::NSec3Param;

        let cases = [
            (
                b"1 1 12 aabbccdd" as &[u8],
                Ok((1, 1, 12, b"\xAA\xBB\xCC\xDD" as &[u8])),
            ),
            (b"1" as &[u8], Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);

            assert_eq!(
                <&NSec3Param>::scan(&mut scanner, &alloc, &mut buffer).map(
                    |p| (
                        p.algorithm.code,
                        p.flags.into(),
                        p.iterations.get(),
                        &*p.salt
                    )
                ),
                expected
            );
        }
    }
}
