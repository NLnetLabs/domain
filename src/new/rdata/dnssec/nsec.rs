//! The NSEC record data type.

use core::hash::{Hash, Hasher};
use core::{cmp::Ordering, fmt};

use crate::new::base::build::BuildInMessage;
use crate::new::base::name::{CanonicalName, Name, NameCompressor};
use crate::new::base::wire::*;
use crate::new::base::{CanonicalRecordData, RType};
use crate::utils::dst::UnsizedCopy;

//----------- Nsec -----------------------------------------------------------

/// Reference to the **N**ext **Sec**ure record (version 1).
///
/// The purpose of the [`Nsec`] record is to transparently show which
/// RRsets[^rrset] exist for this particular owner name and which owner name
/// is next in the canonically ordered list of records.
///
/// [`Nsec`] records are always accompanied by [`Rrsig`] records to
/// authenticate the data in the [`Nsec`] record.
///
/// [`Nsec`] in combination with [`Rrsig`] show and proof the following:
///
///  1) Which [`RType`]s exist under the current owner name ([`types`]). This
///     proves that any other RRset does not exist.
///  2) Which owner name is [`next`] in the canonical order of the zone. This
///     proves that any other owner name, which would be sorted in between
///     these names, does not exist.
///
/// [`Nsec`] records allows everyone to iterate over the records of a zone.
/// First it shows all the [`RType`]s that exist for an owner name and
/// additionally the next owner name. This is a security implication to beware
/// of.
///
/// [`Nsec3`] is an alternative record which solves the above issue.
///
/// ## Operational specifications
///
/// - The [`TTL`] of the [`Nsec`] record is either the value of the
///   [`Soa::minimum`] field or the [`Soa`] records [`TTL`] itself. Choose
///   which ever is lower. (See [Section 3.2, RFC 9077])
/// - Not all RRsets require an [`Nsec`] record. Authoritative and Delegation
///   RRsets require an [`Nsec`] record, Glue RRsets don't require one. (See
///   [Section 2.3, RFC 4035])
///
/// [Section 2.3, RFC 4035]: https://datatracker.ietf.org/doc/html/rfc4035#section-2.3
/// [Section 3.2, RFC 9077]: https://datatracker.ietf.org/doc/html/rfc9077#section-3.2
///
/// ## Wire format
///
/// The wire format of an [`Nsec`] record is the concatenation of its fields,
/// in the same order as the `struct` definition. The name in [`next`] cannot
/// be compressed in DNS messages. See [`TypeBitmaps`] for its wire format.
///
/// The memory layout of the [`Nsec`] type is identical to the wire format, so
/// it can be parsed in a zero-copy fashion, avoiding a copy of the data.
///
/// ## Usage
///
/// Because [`Nsec`] is a record data type, it is usually handled within an
/// enum like [`RecordData`]. This section describes how to use it
/// independently.
///
/// ```
/// # use domain::new::base::RType;
/// # use domain::new::base::name::NameBuf;
/// # use domain::new::base::wire::{ParseBytes, ParseBytesZC, U16};
/// # use domain::new::rdata::{Nsec, TypeBitmaps};
/// #
/// // Create the `Nsec` record data directly from the byte representation.
/// let nsec_raw_bytes = b"\
///     \x07example\x03com\x00\
///     \x00\x06\x40\x00\x00\x00\x00\x03\x01\x01\x40";
/// let nsec_from_bytes = Nsec::parse_bytes(nsec_raw_bytes).unwrap();
///
/// //--- Alternatively, construct from it's components.
///
/// let name: NameBuf = "example.com.".parse().unwrap();
///
/// // Create the `TypeBitmaps` data directly from the byte representation.
/// let typebitmaps_bytes = b"\x00\x06\x40\x00\x00\x00\x00\x03\x01\x01\x40";
/// let typebitmaps =
///     TypeBitmaps::parse_bytes_by_ref(typebitmaps_bytes).unwrap();
///
/// // Construct the `Nsec` record from the existing `name` and `typebitmaps`.
/// let nsec_manual = Nsec {
///     next: &name,
///     types: &typebitmaps,
/// };
///
/// assert_eq!(nsec_manual, nsec_from_bytes);
/// assert_eq!(
///     nsec_manual.types.types().collect::<Vec<_>>(),
///     vec![
///         RType::A,
///         RType::RRSIG,
///         RType::NSEC,
///         RType {
///             code: U16::new(257) // CAA record
///         }
///     ]
/// )
/// ```
///
/// [^rrset]: Resource Record Set; A group of records sharing the same
/// [`RType`], [`RClass`] and `owner name`.
///
/// [`Nsec3`]: crate::new::rdata::Nsec3
/// [`RClass`]: crate::new::base::RClass
/// [`RecordData`]: crate::new::rdata::RecordData
/// [`Rrsig`]: crate::new::rdata::Rrsig
/// [`Soa::minimum`]: crate::new::rdata::Soa::minimum
/// [`Soa`]: crate::new::rdata::Soa
/// [`TTL`]: crate::new::base::TTL
/// [`next`]: Self::next
/// [`types`]: Self::types
#[derive(Clone, Debug, PartialEq, Eq, Hash, BuildBytes)]
pub struct Nsec<'a> {
    /// Next owner name in canonically ordered zone.
    pub next: &'a Name,

    /// List of [`RType`]s present at this owner name.
    pub types: &'a TypeBitmaps,
}

//--- Interaction

impl Nsec<'_> {
    /// Copy referenced data into the given [`Bump`](bumpalo::Bump) allocator.
    #[cfg(feature = "bumpalo")]
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> Nsec<'r> {
        use crate::utils::dst::copy_to_bump;

        Nsec {
            next: copy_to_bump(self.next, bump),
            types: copy_to_bump(self.types, bump),
        }
    }
}

//--- Canonical operations

impl CanonicalRecordData for Nsec<'_> {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.next
            .cmp_composed(other.next)
            .then_with(|| self.types.as_bytes().cmp(other.types.as_bytes()))
    }
}

//--- Building in DNS messages

impl BuildInMessage for Nsec<'_> {
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

impl<'a> ParseBytes<'a> for Nsec<'a> {
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
                (0..8).filter(move |&j| ((b >> (7 - j)) & 1) != 0).map(
                    move |j| {
                        RType::from(u16::from_be_bytes([
                            num,
                            (i * 8 + j) as u8,
                        ]))
                    },
                )
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
        // be stored in this window. And empty windows are not allowed.
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

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<TypeBitmaps> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
    }
}

//--- Hashing

impl Hash for TypeBitmaps {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.octets)
    }
}

//
// --- Functions to make it easier to transition from old base.
// These functions should be marked as deprecated when most of the initial
// migration to new base has completed.
impl<'a> Nsec<'a> {
    /// Constructor for Nsec.
    pub fn new(next: &'a Name, types: &'a TypeBitmaps) -> Self {
        Self { next, types }
    }

    /// Return the RRtypes that are present.
    pub fn types(&self) -> &TypeBitmaps {
        self.types
    }

    /// Return the name of the next NSEC record in the chain.
    pub fn next_name(&self) -> &Name {
        self.next
    }
}

impl TypeBitmaps {
    /// Return an iterator for TypeBitmaps
    pub fn iter(&self) -> impl Iterator<Item = RType> {
        self.types()
    }

    /// Return whether the type bitmap contains a specific RRtype.
    // This is very inefficient. It should iterate over the bitmaps and
    // then directly check the relevant bit.
    pub fn contains(&self, rtype: RType) -> bool {
        // This is very inefficient.
        self.types().any(|t| t == rtype)
    }

    /// Return whether the type bitmap is empty.
    pub fn is_empty(&self) -> bool {
        self.types().next().is_none()
    }
}

// TODO: implement IntoIterator for TypeBitmaps.

//============ Tests =========================================================
#[cfg(test)]
mod tests {
    use crate::new::base::{RType, wire::ParseBytesZC};

    use super::TypeBitmaps;

    /// Test that [`TypeBitmaps`] parses correctly.
    ///
    /// Source of the example:
    /// https://datatracker.ietf.org/doc/html/rfc4034#section-4.3
    #[test]
    fn type_bitmaps_parse() {
        let bytes = b"\x00\x06\x40\x01\x00\x00\x00\x03\
                     \x04\x1b\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x20";

        let bitmaps = TypeBitmaps::parse_bytes_by_ref(bytes).unwrap();

        let expected = [
            RType::A,     // 0x0001
            RType::MX,    // 0x000F
            RType::RRSIG, // 0x002E
            RType::NSEC,  // 0x002F
            RType::from(0x04D2),
        ];

        assert!(
            bitmaps.types().eq(expected),
            "{bitmaps:?} did not match expectation {expected:?}"
        );
    }
}
