//! The NSEC record data type.

use core::iter::FusedIterator;
use core::ops::Range;
use core::{cmp::Ordering, fmt};

use crate::new::base::build::BuildInMessage;
use crate::new::base::name::{CanonicalName, Name, NameCompressor};
use crate::new::base::wire::*;
use crate::new::base::{CanonicalRecordData, RType};
use crate::utils::dst::UnsizedCopy;

#[cfg(feature = "zonefile")]
use crate::new::zonefile::scanner::{Scan, ScanError, Scanner};

//----------- NSec -----------------------------------------------------------

/// An indication of the non-existence of a set of DNS records (version 1).
#[derive(Clone, Debug, PartialEq, Eq, BuildBytes)]
pub struct NSec<'a> {
    /// The name of the next existing DNS record.
    pub next: &'a Name,

    /// The types of the records that exist at this owner name.
    pub types: &'a TypeBitmaps,
}

//--- Interaction

impl NSec<'_> {
    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> NSec<'r> {
        use crate::utils::dst::copy_to_bump;

        NSec {
            next: copy_to_bump(self.next, bump),
            types: copy_to_bump(self.types, bump),
        }
    }
}

//--- Canonical operations

impl CanonicalRecordData for NSec<'_> {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.next
            .cmp_composed(other.next)
            .then_with(|| self.types.as_bytes().cmp(other.types.as_bytes()))
    }
}

//--- Building in DNS messages

impl BuildInMessage for NSec<'_> {
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

//--- Parsing from byte sequences

impl<'a> ParseBytes<'a> for NSec<'a> {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (next, bytes) = <&Name>::split_bytes(bytes)?;
        if bytes.is_empty() {
            // An empty type bitmap is not allowed for NSEC.
            return Err(ParseError);
        }
        let types = <&TypeBitmaps>::parse_bytes(bytes)?;
        Ok(Self { next, types })
    }
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for NSec<'a> {
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let next = <&'a Name>::scan(scanner, alloc, buffer)?;
        if !scanner.skip_ws() {
            return Err(ScanError::Incomplete);
        }
        let types = <&'a TypeBitmaps>::scan(scanner, alloc, buffer)?;

        scanner.skip_ws();
        if scanner.is_empty() {
            Ok(Self { next, types })
        } else {
            Err(ScanError::Custom("unexpected data at end of SOA record"))
        }
    }
}

//----------- TypeBitmaps ----------------------------------------------------

/// A bitmap of DNS record types.
#[derive(PartialEq, Eq, AsBytes, BuildBytes, UnsizedCopy)]
#[repr(transparent)]
pub struct TypeBitmaps {
    /// The bitmap data, encoded in the wire format.
    octets: [u8],
}

//--- Inspection

impl TypeBitmaps {
    /// The types in this bitmap.
    pub fn iter(&self) -> impl Iterator<Item = RType> + Clone + '_ {
        self.into_iter()
    }
}

//--- Iteration

impl<'a> IntoIterator for &'a TypeBitmaps {
    type Item = RType;
    type IntoIter = TypeBitmapsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        TypeBitmapsIter {
            source: self,
            block: self.octets[0],
            offset: 2,
            bits: 0..(self.octets[1] as usize * 8),
        }
    }
}

/// An iterator over the types in a [`TypeBitmapsIter`].
#[derive(Clone)]
pub struct TypeBitmapsIter<'a> {
    /// The original bitmaps.
    source: &'a TypeBitmaps,

    /// The high bits of the current block.
    block: u8,

    /// The offset of the current block.
    offset: usize,

    /// The bits being tested in this block.
    bits: Range<usize>,
}

impl Iterator for TypeBitmapsIter<'_> {
    type Item = RType;

    fn next(&mut self) -> Option<Self::Item> {
        // Loop:
        // - 0 times: if there are no blocks left.
        // - 1 time:  if there is another bit set in the current block.
        // - 1 time:  if the current block is empty and is the last one.
        // - 2 times: if the current block is empty but another block exists.
        while self.offset < self.source.octets.len() {
            let octets = &self.source.octets[self.offset..];

            // Look for another bit within the current block.
            for pos in &mut self.bits {
                if (octets[pos / 8] & (1u8 << (pos % 8))) != 0 {
                    let value = u16::from_be_bytes([self.block, pos as u8]);
                    return Some(value.into());
                }
            }

            // Move to the next block, if any.
            self.offset += self.bits.end / 8;
            self.block = *self.source.octets.get(self.offset)?;
            let size = self.source.octets[self.offset + 1];
            self.bits = 0..(size as usize * 8);
            self.offset += 2;
        }

        None
    }
}

impl FusedIterator for TypeBitmapsIter<'_> {}

impl fmt::Debug for TypeBitmapsIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.clone()).finish()
    }
}

//--- Formatting

impl fmt::Debug for TypeBitmaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.iter()).finish()
    }
}

//--- Parsing

impl TypeBitmaps {
    /// Validate the given bytes as a bitmap in the wire format.
    fn validate_bytes(mut octets: &[u8]) -> Result<(), ParseError> {
        // NOTE: NSEC records require at least one type in the bitmap, while
        // NSEC3 records can have an empty bitmap (see RFC 6840, section 6.4).

        // The window number (i.e. the high byte of the type).
        let mut num = None;
        while let Some(&next) = octets.first() {
            // Make sure that the window number increases.
            // NOTE: 'None < Some(_)', for the first iteration.
            if num.replace(next) > Some(next) {
                return Err(ParseError);
            }

            octets = Self::validate_window_bytes(octets)?;
        }

        Ok(())
    }

    /// Validate the given bytes as a bitmap window in the wire format.
    fn validate_window_bytes(octets: &[u8]) -> Result<&[u8], ParseError> {
        let &[_num, len, ref rest @ ..] = octets else {
            return Err(ParseError);
        };

        // At most 32 bytes are necessary, to cover the 256 types that could
        // be stored in this window.  And empty windows are not allowed.
        if !(1..=32).contains(&len) || rest.len() < len as usize {
            return Err(ParseError);
        }

        // TODO(1.80): Use 'split_at_checked()' and eliminate the previous
        // conditional (move the range check into the 'let-else').
        let (bits, rest) = rest.split_at(len as usize);
        if bits.last() == Some(&0) {
            // Trailing zeros are not allowed.
            return Err(ParseError);
        }

        Ok(rest)
    }
}

// SAFETY: The implementations of 'parse_bytes_by_{ref,mut}()' always parse
// the entirety of the input on success, satisfying the safety requirements.
unsafe impl ParseBytesZC for TypeBitmaps {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        Self::validate_bytes(bytes)?;

        // SAFETY: 'TypeBitmaps' is 'repr(transparent)' to '[u8]', and so
        // references to '[u8]' can be transmuted to 'TypeBitmaps' soundly.
        unsafe { core::mem::transmute(bytes) }
    }
}

//--- Scanning from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for &'a TypeBitmaps {
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        // TODO: Re-use 'buffer' here.
        let mut rtypes = std::vec::Vec::<RType>::new();

        loop {
            rtypes.push(RType::scan(scanner, alloc, buffer)?);
            if scanner.is_empty() {
                break;
            } else {
                scanner.skip_ws();
            }
        }

        // Sort the records.
        rtypes.sort_unstable();

        // Build the bitmap in 'buffer'.
        let start = buffer.len();
        let mut rtypes = rtypes.iter().copied().peekable();
        while let Some(&first) = rtypes.peek() {
            // This is the first type in a new block.
            let block = first.code.get() >> 8;
            buffer.push(block as u8);
            buffer.push(0);
            let offset = buffer.len();

            // TODO: Check for duplicate items in the set?

            // Loop over the types in this block.
            while let Some(elem) =
                rtypes.next_if(|t| t.code.get() >> 8 == block)
            {
                let pos = elem.code.get() as u8;
                buffer.resize(offset + ((pos / 8) + 1) as usize, 0);
                *buffer.last_mut().unwrap() |= 1u8 << (pos % 8);
            }

            // Set the size of the block.
            debug_assert!(buffer.len() - offset <= 32);
            buffer[offset - 1] = (buffer.len() - offset) as u8;
        }

        // Copy the bitmap over to the allocator and finish up.
        let this = alloc.alloc_slice_copy(&buffer[start..]);
        buffer.truncate(start);

        Ok(TypeBitmaps::parse_bytes_by_ref(this).unwrap())
    }
}

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<TypeBitmaps> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    #[cfg(feature = "zonefile")]
    #[test]
    fn scan() {
        use crate::{
            new::base::{name::NameBuf, wire::U16, RType},
            new::zonefile::scanner::{Scan, ScanError, Scanner},
            utils::CmpIter,
        };

        use super::NSec;

        let cases = [
            (
                b"host.example.com. A MX RRSIG NSEC TYPE1234" as &[u8],
                Ok((
                    "host.example.com",
                    &const {
                        [
                            RType::A,
                            RType::MX,
                            RType::RRSIG,
                            RType::NSEC,
                            RType {
                                code: U16::new(1234),
                            },
                        ]
                    } as &[RType],
                )),
            ),
            (b"host.example.com." as &[u8], Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            let actual = NSec::scan(&mut scanner, &alloc, &mut buffer);

            assert_eq!(expected.as_ref().err(), actual.as_ref().err());
            if let (Ok(expected), Ok(actual)) = (expected, actual) {
                let (next, types) = expected;
                assert_eq!(&*next.parse::<NameBuf>().unwrap(), actual.next);
                assert_eq!(
                    CmpIter(types.iter().copied()),
                    CmpIter(actual.types),
                );
            }
        }
    }
}
