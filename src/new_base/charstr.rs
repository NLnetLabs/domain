//! DNS "character strings".

use core::{fmt, ops::Range};

use zerocopy::IntoBytes;
use zerocopy_derive::*;

use super::{
    parse::{
        ParseError, ParseFrom, ParseFromMessage, SplitFrom, SplitFromMessage,
    },
    Message,
};

//----------- CharStr --------------------------------------------------------

/// A DNS "character string".
#[derive(Immutable, Unaligned)]
#[repr(transparent)]
pub struct CharStr {
    /// The underlying octets.
    pub octets: [u8],
}

//--- Parsing from DNS messages

impl<'a> SplitFromMessage<'a> for &'a CharStr {
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let bytes = &message.as_bytes()[start..];
        let (this, rest) = Self::split_from(bytes)?;
        Ok((this, bytes.len() - rest.len()))
    }
}

impl<'a> ParseFromMessage<'a> for &'a CharStr {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        message
            .as_bytes()
            .get(range)
            .ok_or(ParseError)
            .and_then(Self::parse_from)
    }
}

//--- Parsing from bytes

impl<'a> SplitFrom<'a> for &'a CharStr {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (&length, rest) = bytes.split_first().ok_or(ParseError)?;
        if length as usize > rest.len() {
            return Err(ParseError);
        }
        let (bytes, rest) = rest.split_at(length as usize);

        // SAFETY: 'CharStr' is 'repr(transparent)' to '[u8]'.
        Ok((unsafe { core::mem::transmute::<&[u8], Self>(bytes) }, rest))
    }
}

impl<'a> ParseFrom<'a> for &'a CharStr {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (&length, rest) = bytes.split_first().ok_or(ParseError)?;
        if length as usize != rest.len() {
            return Err(ParseError);
        }

        // SAFETY: 'CharStr' is 'repr(transparent)' to '[u8]'.
        Ok(unsafe { core::mem::transmute::<&[u8], Self>(rest) })
    }
}

//--- Equality

impl PartialEq for CharStr {
    fn eq(&self, other: &Self) -> bool {
        self.octets.eq_ignore_ascii_case(&other.octets)
    }
}

impl Eq for CharStr {}

//--- Formatting

impl fmt::Debug for CharStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use fmt::Write;

        struct Native<'a>(&'a [u8]);
        impl fmt::Debug for Native<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("b\"")?;
                for &b in self.0 {
                    f.write_str(match b {
                        b'"' => "\\\"",
                        b' ' => " ",
                        b'\n' => "\\n",
                        b'\r' => "\\r",
                        b'\t' => "\\t",
                        b'\\' => "\\\\",

                        _ => {
                            if b.is_ascii_graphic() {
                                f.write_char(b as char)?;
                            } else {
                                write!(f, "\\x{:02X}", b)?;
                            }
                            continue;
                        }
                    })?;
                }
                f.write_char('"')?;
                Ok(())
            }
        }

        f.debug_struct("CharStr")
            .field("content", &Native(&self.octets))
            .finish()
    }
}
