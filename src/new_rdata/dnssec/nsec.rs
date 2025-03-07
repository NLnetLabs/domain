use core::{fmt, mem};

use domain_macros::*;

use crate::new_base::{
    name::Name,
    wire::{ParseBytesByRef, ParseError},
    RType,
};

//----------- NSec -----------------------------------------------------------

/// An indication of the non-existence of a set of DNS records (version 1).
#[derive(Clone, Debug, PartialEq, Eq, BuildBytes, ParseBytes)]
pub struct NSec<'a> {
    /// The name of the next existing DNS record.
    pub next: &'a Name,

    /// The types of the records that exist at this owner name.
    pub types: &'a TypeBitmaps,
}

//----------- TypeBitmaps ----------------------------------------------------

/// A bitmap of DNS record types.
#[derive(PartialEq, Eq, AsBytes, BuildBytes)]
#[repr(transparent)]
pub struct TypeBitmaps {
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
    fn validate_bytes(mut octets: &[u8]) -> Result<(), ParseError> {
        // At least one bitmap is mandatory.
        let mut num = octets.first().ok_or(ParseError)?;
        octets = Self::validate_window_bytes(octets)?;

        while let Some(next) = octets.first() {
            if mem::replace(&mut num, next) >= next {
                return Err(ParseError);
            }

            octets = Self::validate_window_bytes(octets)?;
        }

        Ok(())
    }

    fn validate_window_bytes(octets: &[u8]) -> Result<&[u8], ParseError> {
        let &[_num, len, ref rest @ ..] = octets else {
            return Err(ParseError);
        };

        if !(1..=32).contains(&len) || rest.len() < len as usize {
            return Err(ParseError);
        }

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
unsafe impl ParseBytesByRef for TypeBitmaps {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        Self::validate_bytes(bytes)?;

        // SAFETY: 'TypeBitmaps' is 'repr(transparent)' to '[u8]', and so
        // references to '[u8]' can be transmuted to 'TypeBitmaps' soundly.
        unsafe { core::mem::transmute(bytes) }
    }

    fn parse_bytes_by_mut(bytes: &mut [u8]) -> Result<&mut Self, ParseError> {
        Self::validate_bytes(bytes)?;

        // SAFETY: 'TypeBitmaps' is 'repr(transparent)' to '[u8]', and so
        // references to '[u8]' can be transmuted to 'TypeBitmaps' soundly.
        unsafe { core::mem::transmute(bytes) }
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        self.octets.ptr_with_address(addr) as *const Self
    }
}
