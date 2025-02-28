use core::fmt;

use domain_macros::*;

use crate::new_base::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::ParseMessageBytes,
    wire::{ParseBytes, ParseError, SplitBytes},
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
    /// Iterate over the [`CharStr`]s in this record.
    pub fn iter(
        &self,
    ) -> impl Iterator<Item = Result<&CharStr, ParseError>> + '_ {
        // NOTE: A TXT record always has at least one 'CharStr' within.
        let first = <&CharStr>::split_bytes(&self.content);
        core::iter::successors(Some(first), |prev| {
            prev.as_ref()
                .ok()
                .map(|(_elem, rest)| <&CharStr>::split_bytes(rest))
        })
        .map(|result| result.map(|(elem, _rest)| elem))
    }
}

//--- Parsing from DNS messages

impl<'a> ParseMessageBytes<'a> for &'a Txt {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        Self::parse_bytes(&contents[start..])
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for Txt {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        self.content.build_into_message(builder)
    }
}

//--- Parsing from bytes

impl<'a> ParseBytes<'a> for &'a Txt {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        // NOTE: The input must contain at least one 'CharStr'.
        let (_, mut rest) = <&CharStr>::split_bytes(bytes)?;
        while !rest.is_empty() {
            (_, rest) = <&CharStr>::split_bytes(rest)?;
        }

        // SAFETY: 'Txt' is 'repr(transparent)' to '[u8]'.
        Ok(unsafe { core::mem::transmute::<&'a [u8], Self>(bytes) })
    }
}

//--- Formatting

impl fmt::Debug for Txt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Content<'a>(&'a Txt);
        impl fmt::Debug for Content<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut list = f.debug_list();
                for elem in self.0.iter() {
                    if let Ok(elem) = elem {
                        list.entry(&elem);
                    } else {
                        list.entry(&ParseError);
                    }
                }
                list.finish()
            }
        }

        f.debug_tuple("Txt").field(&Content(self)).finish()
    }
}

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
