//! DNS "character strings".

use core::borrow::{Borrow, BorrowMut};
use core::fmt;
use core::ops::{Deref, DerefMut};
use core::str::FromStr;

use crate::utils::dst::{UnsizedCopy, UnsizedCopyFrom};

use super::{
    build::{self, BuildIntoMessage, BuildResult},
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{BuildBytes, ParseBytes, ParseError, SplitBytes, TruncationError},
};

//----------- CharStr --------------------------------------------------------

/// A DNS "character string".
#[derive(UnsizedCopy)]
#[repr(transparent)]
pub struct CharStr {
    /// The underlying octets.
    ///
    /// This is at most 255 bytes.  It does not include the length octet that
    /// precedes the character string when serialized in the wire format.
    pub octets: [u8],
}

//--- Construction

impl CharStr {
    /// Assume a byte sequence is a valid [`CharStr`].
    ///
    /// # Safety
    ///
    /// The byte sequence does not include the length octet; it simply must be
    /// 255 bytes in length or shorter.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'CharStr' is 'repr(transparent)' to '[u8]', so casting a
        // '[u8]' into a 'CharStr' is sound.
        core::mem::transmute(bytes)
    }

    /// Assume a mutable byte sequence is a valid [`CharStr`].
    ///
    /// # Safety
    ///
    /// The byte sequence does not include the length octet; it simply must be
    /// 255 bytes in length or shorter.
    pub unsafe fn from_bytes_unchecked_mut(bytes: &mut [u8]) -> &mut Self {
        // SAFETY: 'CharStr' is 'repr(transparent)' to '[u8]', so casting a
        // '[u8]' into a 'CharStr' is sound.
        core::mem::transmute(bytes)
    }
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

//--- Building into byte sequences

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

    fn built_bytes_size(&self) -> usize {
        1 + self.octets.len()
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

//----------- CharStrBuf -----------------------------------------------------

/// A 256-byte buffer for a character string.
#[derive(Clone)]
#[repr(C)] // make layout compatible with '[u8; 256]'
pub struct CharStrBuf {
    /// The length of the string, in bytes.
    size: u8,

    /// The string contents.
    data: [u8; 255],
}

//--- Construction

impl CharStrBuf {
    /// Construct an empty, invalid buffer.
    const fn empty() -> Self {
        Self {
            size: 0,
            data: [0u8; 255],
        }
    }

    /// Copy a [`CharStrBuf`] into a buffer.
    pub fn copy_from(string: &CharStr) -> Self {
        let mut this = Self::empty();
        this.size = string.len() as u8;
        this.data[..string.len()].copy_from_slice(&string.octets);
        this
    }
}

impl UnsizedCopyFrom for CharStrBuf {
    type Source = CharStr;

    fn unsized_copy_from(value: &Self::Source) -> Self {
        Self::copy_from(value)
    }
}

//--- Inspection

impl CharStrBuf {
    /// The wire format for this character string.
    pub fn wire_bytes(&self) -> &[u8] {
        let ptr = self as *const _ as *const u8;
        let len = self.len() + 1;
        // SAFETY: 'Self' is 'repr(C)' and contains no padding.  It can be
        // interpreted as a 256-byte array.
        unsafe { core::slice::from_raw_parts(ptr, len) }
    }
}

//--- Parsing from DNS messages

impl SplitMessageBytes<'_> for CharStrBuf {
    fn split_message_bytes(
        contents: &'_ [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        <&CharStr>::split_message_bytes(contents, start)
            .map(|(this, rest)| (Self::copy_from(this), rest))
    }
}

impl ParseMessageBytes<'_> for CharStrBuf {
    fn parse_message_bytes(
        contents: &'_ [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        <&CharStr>::parse_message_bytes(contents, start).map(Self::copy_from)
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for CharStrBuf {
    fn build_into_message(&self, builder: build::Builder<'_>) -> BuildResult {
        CharStr::build_into_message(self, builder)
    }
}

//--- Parsing from bytes

impl SplitBytes<'_> for CharStrBuf {
    fn split_bytes(bytes: &'_ [u8]) -> Result<(Self, &'_ [u8]), ParseError> {
        <&CharStr>::split_bytes(bytes)
            .map(|(this, rest)| (Self::copy_from(this), rest))
    }
}

impl ParseBytes<'_> for CharStrBuf {
    fn parse_bytes(bytes: &'_ [u8]) -> Result<Self, ParseError> {
        <&CharStr>::parse_bytes(bytes).map(Self::copy_from)
    }
}

//--- Building into byte sequences

impl BuildBytes for CharStrBuf {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        (**self).build_bytes(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        (**self).built_bytes_size()
    }
}

//--- Parsing from strings

impl FromStr for CharStrBuf {
    type Err = CharStrParseError;

    /// Parse a DNS "character-string" from a string.
    ///
    /// This is intended for easily constructing hard-coded character strings.
    /// This function cannot parse all valid character strings; if exceptional
    /// instances are needed, use [`CharStr::from_bytes_unchecked()`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.as_bytes().iter().any(|&c| c == b'\\') {
            Err(CharStrParseError::InvalidChar)
        } else if s.len() > 255 {
            Err(CharStrParseError::Overlong)
        } else {
            // SAFETY: 's' is 255 bytes or shorter.
            let s = unsafe { CharStr::from_bytes_unchecked(s.as_bytes()) };
            Ok(Self::copy_from(s))
        }
    }
}

//--- Access to the underlying 'CharStr'

impl Deref for CharStrBuf {
    type Target = CharStr;

    fn deref(&self) -> &Self::Target {
        let name = &self.data[..self.size as usize];
        // SAFETY: A 'CharStrBuf' always contains a valid 'CharStr'.
        unsafe { CharStr::from_bytes_unchecked(name) }
    }
}

impl DerefMut for CharStrBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let name = &mut self.data[..self.size as usize];
        // SAFETY: A 'CharStrBuf' always contains a valid 'CharStr'.
        unsafe { CharStr::from_bytes_unchecked_mut(name) }
    }
}

impl Borrow<CharStr> for CharStrBuf {
    fn borrow(&self) -> &CharStr {
        self
    }
}

impl BorrowMut<CharStr> for CharStrBuf {
    fn borrow_mut(&mut self) -> &mut CharStr {
        self
    }
}

impl AsRef<CharStr> for CharStrBuf {
    fn as_ref(&self) -> &CharStr {
        self
    }
}

impl AsMut<CharStr> for CharStrBuf {
    fn as_mut(&mut self) -> &mut CharStr {
        self
    }
}

//--- Forwarding equality and formatting

impl PartialEq for CharStrBuf {
    fn eq(&self, that: &Self) -> bool {
        **self == **that
    }
}

impl Eq for CharStrBuf {}

impl fmt::Debug for CharStrBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

//----------- CharStrParseError ----------------------------------------------

/// An error in parsing a [`CharStr`] from a string.
///
/// This can be returned by [`CharStrBuf::from_str()`].  It is not used when
/// parsing character strings from the zonefile format, which uses a different
/// mechanism.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CharStrParseError {
    /// The character string was too large.
    ///
    /// Valid character strings are between 0 and 255 bytes, inclusive.
    Overlong,

    /// The input contained an invalid character.
    InvalidChar,
}

// TODO(1.81.0): Use 'core::error::Error' instead.
#[cfg(feature = "std")]
impl std::error::Error for CharStrParseError {}

impl fmt::Display for CharStrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Overlong => "the character string was too long",
            Self::InvalidChar => {
                "the character string contained an invalid character"
            }
        })
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
