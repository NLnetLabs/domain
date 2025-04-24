//! The TXT record data type.

use core::{cmp::Ordering, fmt};

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    wire::{ParseBytesByRef, ParseError, SplitBytes},
    CanonicalRecordData, CharStr,
};
use crate::utils::dst::UnsizedCopy;

//----------- Txt ------------------------------------------------------------

/// Free-form text strings about this domain.
#[derive(AsBytes, BuildBytes, UnsizedCopy)]
#[repr(transparent)]
pub struct Txt {
    /// The text strings, as concatenated [`CharStr`]s.
    ///
    /// The [`CharStr`]s begin with a length octet so they can be separated.
    content: [u8],
}

//--- Interaction

impl Txt {
    /// Iterate over the [`CharStr`]s in this record.
    pub fn iter(&self) -> impl Iterator<Item = &CharStr> + '_ {
        // NOTE: A TXT record always has at least one 'CharStr' within.
        let first = <&CharStr>::split_bytes(&self.content)
            .expect("'Txt' records always contain valid 'CharStr's");
        core::iter::successors(Some(first), |(_, rest)| {
            (!rest.is_empty()).then(|| {
                <&CharStr>::split_bytes(rest)
                    .expect("'Txt' records always contain valid 'CharStr's")
            })
        })
        .map(|(elem, _rest)| elem)
    }
}

//--- Canonical operations

impl CanonicalRecordData for Txt {
    fn cmp_canonical(&self, other: &Self) -> Ordering {
        self.content.cmp(&other.content)
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for Txt {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.content.build_into_message(builder)
    }
}

//--- Parsing from bytes

// SAFETY: The implementations of 'parse_bytes_by_{ref,mut}()' always parse
// the entirety of the input on success, satisfying the safety requirements.
unsafe impl ParseBytesZC for Txt {
    fn parse_bytes_zc(bytes: &[u8]) -> Result<&Self, ParseError> {
        // NOTE: The input must contain at least one 'CharStr'.
        let (_, mut rest) = <&CharStr>::split_bytes(bytes)?;
        while !rest.is_empty() {
            (_, rest) = <&CharStr>::split_bytes(rest)?;
        }

        // SAFETY: 'Txt' is 'repr(transparent)' to '[u8]'.
        Ok(unsafe { core::mem::transmute::<&[u8], &Self>(bytes) })
    }
}

//--- Formatting

impl fmt::Debug for Txt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Content<'a>(&'a Txt);
        impl fmt::Debug for Content<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.0.iter()).finish()
            }
        }

        f.debug_tuple("Txt").field(&Content(self)).finish()
    }
}

//--- Equality

impl PartialEq for Txt {
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for Txt {}
