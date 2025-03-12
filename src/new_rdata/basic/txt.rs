use core::fmt;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    wire::{ParseBytesByRef, ParseError, SplitBytes},
    CharStr,
};

#[cfg(feature = "zonefile")]
use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

//----------- Txt ------------------------------------------------------------

/// Free-form text strings about this domain.
#[derive(AsBytes, BuildBytes)]
#[repr(transparent)]
pub struct Txt {
    /// The text strings, as concatenated [`CharStr`]s.
    ///
    /// The [`CharStr`]s begin with a length octet so they can be separated.
    content: [u8],
}

//--- Interaction

impl Txt {
    /// Copy this into the given [`Bump`] allocator.
    #[cfg(feature = "bumpalo")]
    #[allow(clippy::mut_from_ref)] // using a memory allocator
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> &'r mut Self {
        use crate::new_base::wire::AsBytes;

        let bytes = bump.alloc_slice_copy(self.as_bytes());
        // SAFETY: 'ParseBytesByRef' and 'AsBytes' are inverses.
        unsafe { Self::parse_bytes_by_mut(bytes).unwrap_unchecked() }
    }

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

//--- Building into DNS messages

impl BuildIntoMessage for Txt {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.content.build_into_message(builder)
    }
}

//--- Parsing from bytes

impl Txt {
    /// Validate the given bytes as a 'Txt'.
    fn validate_bytes(bytes: &[u8]) -> Result<(), ParseError> {
        // NOTE: The input must contain at least one 'CharStr'.
        let (_, mut rest) = <&CharStr>::split_bytes(bytes)?;
        while !rest.is_empty() {
            (_, rest) = <&CharStr>::split_bytes(rest)?;
        }
        Ok(())
    }
}

// SAFETY: The implementations of 'parse_bytes_by_{ref,mut}()' always parse
// the entirety of the input on success, satisfying the safety requirements.
unsafe impl ParseBytesByRef for Txt {
    fn parse_bytes_by_ref(bytes: &[u8]) -> Result<&Self, ParseError> {
        Self::validate_bytes(bytes)?;

        // SAFETY: 'Txt' is 'repr(transparent)' to '[u8]'.
        Ok(unsafe { core::mem::transmute::<&[u8], &Self>(bytes) })
    }

    fn parse_bytes_by_mut(bytes: &mut [u8]) -> Result<&mut Self, ParseError> {
        Self::validate_bytes(bytes)?;

        // SAFETY: 'Txt' is 'repr(transparent)' to '[u8]'.
        Ok(unsafe { core::mem::transmute::<&mut [u8], &mut Self>(bytes) })
    }

    fn ptr_with_address(&self, addr: *const ()) -> *const Self {
        self.content.ptr_with_address(addr) as *const Self
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

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for &'a Txt {
    /// Scan the data for a TXT record.
    ///
    /// This parses the following syntax:
    ///
    /// ```text
    /// rdata-txt = char-str (ws+ char-str)* ws*
    /// ```
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let start = buffer.len();

        loop {
            if start < buffer.len() && !scanner.skip_ws() {
                break;
            }

            let cur = buffer.len();
            buffer.push(0u8);
            match scanner.scan_token(buffer)? {
                Some(token) if token.len() > 255 => {
                    buffer.truncate(start);
                    return Err(ScanError::Custom(
                        "Overlong character string",
                    ));
                }

                Some(token) => {
                    buffer[cur] = token.len() as u8;
                    if buffer.len() - start >= 65536 {
                        return Err(ScanError::Custom(
                            "TXT record has overflowed 64K bytes",
                        ));
                    }
                }

                None => {
                    buffer.truncate(cur);
                    break;
                }
            }
        }

        if start < buffer.len() && scanner.is_empty() {
            let bytes = alloc.alloc_slice_copy(&buffer[start..]);
            buffer.truncate(start);
            // SAFETY: 'buffer' contains a sequence of character strings.
            Ok(unsafe { core::mem::transmute::<&[u8], Self>(bytes) })
        } else if start == buffer.len() {
            Err(ScanError::Incomplete)
        } else {
            Err(ScanError::Custom("Unexpected data at end of TXT record"))
        }
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    #[cfg(feature = "zonefile")]
    #[test]
    fn scan() {
        use crate::new_zonefile::scanner::{Scan, ScanError, Scanner};

        use super::Txt;

        let cases = [
            (b"a b" as &[u8], Ok(&[b"a" as &[u8], b"b"] as &[_])),
            (b"a \"b c\" d", Ok(&[b"a" as &[u8], b"b c", b"d"])),
            (b"" as &[u8], Err(ScanError::Incomplete)),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            let result = <&Txt>::scan(&mut scanner, &alloc, &mut buffer);
            assert!(
                result.as_ref().err() == expected.as_ref().err(),
                "{result:?} == {expected:?}"
            );
            if let (Ok(result), Ok(expected)) = (result, expected) {
                assert!(
                    result
                        .iter()
                        .map(|s| &s.octets)
                        .eq(expected.iter().copied()),
                    "{result:?} == {expected:?}"
                );
            }
        }
    }
}
