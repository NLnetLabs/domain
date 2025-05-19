//! The NSEC record data type.

use core::{cmp::Ordering, fmt, mem};

use crate::new_base::build::BuildInMessage;
use crate::new_base::name::{CanonicalName, Name, NameCompressor};
use crate::new_base::wire::*;
use crate::new_base::{CanonicalRecordData, RType};
use crate::utils::dst::UnsizedCopy;

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
    pub fn types(&self) -> impl Iterator<Item = RType> + '_ {
        fn split_window(octets: &[u8]) -> Option<(u8, &[u8], &[u8])> {
            let &[num, len, ref rest @ ..] = octets else {
                return None;
            };

            let (bits, rest) = rest.split_at(len as usize);
            Some((num, bits, rest))
        }

        core::iter::successors(split_window(&self.octets), |(_, _, rest)| {
            split_window(rest)
        })
        .flat_map(move |(num, bits, _)| {
            bits.iter().enumerate().flat_map(move |(i, &b)| {
                (0..8).filter(move |&j| ((b >> j) & 1) != 0).map(move |j| {
                    RType::from(u16::from_be_bytes([num, (i * 8 + j) as u8]))
                })
            })
        })
    }
}

//--- Formatting

impl fmt::Debug for TypeBitmaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.types()).finish()
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
            if mem::replace(&mut num, Some(next)) > Some(next) {
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
