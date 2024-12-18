//! Domain names encoded in DNS messages.

use zerocopy_derive::*;

use crate::new_base::parse::{ParseError, ParseFrom, SplitFrom};

//----------- ParsedName -----------------------------------------------------

/// A domain name in a DNS message.
#[derive(Debug, IntoBytes, Immutable, Unaligned)]
#[repr(transparent)]
pub struct ParsedName([u8]);

//--- Constants

impl ParsedName {
    /// The maximum size of a parsed domain name in the wire format.
    ///
    /// This can occur if a compression pointer is used to point to a root
    /// name, even though such a representation is longer than copying the
    /// root label into the name.
    pub const MAX_SIZE: usize = 256;

    /// The root name.
    pub const ROOT: &'static Self = {
        // SAFETY: A root label is the shortest valid name.
        unsafe { Self::from_bytes_unchecked(&[0u8]) }
    };
}

//--- Construction

impl ParsedName {
    /// Assume a byte string is a valid [`ParsedName`].
    ///
    /// # Safety
    ///
    /// The byte string must be correctly encoded in the wire format, and
    /// within the size restriction (256 bytes or fewer).  It must end with a
    /// root label or a compression pointer.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'ParsedName' is 'repr(transparent)' to '[u8]', so casting a
        // '[u8]' into a 'ParsedName' is sound.
        core::mem::transmute(bytes)
    }
}

//--- Inspection

impl ParsedName {
    /// The size of this name in the wire format.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the root label.
    pub const fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    /// Whether this is a compression pointer.
    pub const fn is_pointer(&self) -> bool {
        self.0.len() == 2
    }

    /// The wire format representation of the name.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

//--- Parsing

impl<'a> SplitFrom<'a> for &'a ParsedName {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        // Iterate through the labels in the name.
        let mut index = 0usize;
        loop {
            if index >= ParsedName::MAX_SIZE || index >= bytes.len() {
                return Err(ParseError);
            }
            let length = bytes[index];
            if length == 0 {
                // This was the root label.
                index += 1;
                break;
            } else if length < 0x40 {
                // This was the length of the label.
                index += 1 + length as usize;
            } else if length >= 0xC0 {
                // This was a compression pointer.
                if index + 1 >= bytes.len() {
                    return Err(ParseError);
                }
                index += 2;
                break;
            } else {
                // This was a reserved or deprecated label type.
                return Err(ParseError);
            }
        }

        let (name, bytes) = bytes.split_at(index);
        // SAFETY: 'bytes' has been confirmed to be correctly encoded.
        Ok((unsafe { ParsedName::from_bytes_unchecked(name) }, bytes))
    }
}

impl<'a> ParseFrom<'a> for &'a ParsedName {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        Self::split_from(bytes).and_then(|(name, rest)| {
            rest.is_empty().then_some(name).ok_or(ParseError)
        })
    }
}

//--- Conversion to and from bytes

impl AsRef<[u8]> for ParsedName {
    /// The bytes in the name in the wire format.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a ParsedName> for &'a [u8] {
    fn from(name: &'a ParsedName) -> Self {
        name.as_bytes()
    }
}
