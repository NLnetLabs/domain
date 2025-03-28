//! DNS "character strings".

use core::fmt;

use domain_macros::UnsizedClone;

use super::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{BuildBytes, ParseBytes, ParseError, SplitBytes, TruncationError},
};

//----------- CharStr --------------------------------------------------------

/// A DNS "character string".
#[derive(UnsizedClone)]
#[repr(transparent)]
pub struct CharStr {
    /// The underlying octets.
    ///
    /// This is at most 255 bytes.  It does not include the length octet that
    /// precedes the character string when serialized in the wire format.
    pub octets: [u8],
}

//--- Inspection

impl CharStr {
    /// The length of the [`CharStr`].
    ///
    /// This is always less than 256 -- it is guaranteed to fit in a [`u8`].
    pub const fn len(&self) -> usize {
        self.octets.len()
    }

    /// Whether the [`CharStr`] is empty.
    pub const fn is_empty(&self) -> bool {
        self.octets.is_empty()
    }
}

//--- Parsing from DNS messages

impl<'a> SplitMessageBytes<'a> for &'a CharStr {
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        Self::split_bytes(&contents[start..])
            .map(|(this, rest)| (this, contents.len() - start - rest.len()))
    }
}

impl<'a> ParseMessageBytes<'a> for &'a CharStr {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        Self::parse_bytes(&contents[start..])
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for CharStr {
    fn build_into_message(
        &self,
        mut builder: build::Builder<'_>,
    ) -> BuildResult {
        builder.append_bytes(&[self.octets.len() as u8])?;
        builder.append_bytes(&self.octets)?;
        Ok(builder.commit())
    }
}

//--- Parsing from bytes

impl<'a> SplitBytes<'a> for &'a CharStr {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (&length, rest) = bytes.split_first().ok_or(ParseError)?;
        if length as usize > rest.len() {
            return Err(ParseError);
        }
        let (bytes, rest) = rest.split_at(length as usize);

        // SAFETY: 'CharStr' is 'repr(transparent)' to '[u8]'.
        Ok((unsafe { core::mem::transmute::<&[u8], Self>(bytes) }, rest))
    }
}

impl<'a> ParseBytes<'a> for &'a CharStr {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let (&length, rest) = bytes.split_first().ok_or(ParseError)?;
        if length as usize != rest.len() {
            return Err(ParseError);
        }

        // SAFETY: 'CharStr' is 'repr(transparent)' to '[u8]'.
        Ok(unsafe { core::mem::transmute::<&[u8], Self>(rest) })
    }
}

//--- Building into byte strings

impl BuildBytes for CharStr {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        let (length, bytes) =
            bytes.split_first_mut().ok_or(TruncationError)?;
        *length = self.octets.len() as u8;
        self.octets.build_bytes(bytes)
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

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::CharStr;

    use crate::new_base::wire::{
        BuildBytes, ParseBytes, ParseError, SplitBytes,
    };

    #[test]
    fn parse_build() {
        let bytes = b"\x05Hello!";
        let (charstr, rest) = <&CharStr>::split_bytes(bytes).unwrap();
        assert_eq!(&charstr.octets, b"Hello");
        assert_eq!(rest, b"!");

        assert_eq!(<&CharStr>::parse_bytes(bytes), Err(ParseError));
        assert!(<&CharStr>::parse_bytes(&bytes[..6]).is_ok());

        let mut buffer = [0u8; 6];
        assert_eq!(
            charstr.build_bytes(&mut buffer),
            Ok(&mut [] as &mut [u8])
        );
        assert_eq!(buffer, &bytes[..6]);
    }
}
