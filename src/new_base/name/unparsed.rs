//! Unparsed domain names.

use domain_macros::*;

use crate::new_base::{
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{ParseError, SplitBytes},
};

use super::Label;

//----------- UnparsedName ---------------------------------------------------

/// An unparsed domain name in a DNS message.
///
/// Within a DNS message, domain names are stored in conventional order (from
/// innermost to the root label), and may end with a compression pointer.  An
/// [`UnparsedName`] represents this incomplete domain name, exactly as stored
/// in a message.
#[derive(AsBytes)]
#[repr(transparent)]
pub struct UnparsedName([u8]);

//--- Constants

impl UnparsedName {
    /// The maximum size of an unparsed domain name.
    ///
    /// A domain name can be 255 bytes at most, but an unparsed domain name
    /// could replace the last byte (representing the root label) with a
    /// compression pointer to it.  Since compression pointers are 2 bytes,
    /// the total size becomes 256 bytes.
    pub const MAX_SIZE: usize = 256;

    /// The root name.
    pub const ROOT: &'static Self = {
        // SAFETY: A root label is the shortest valid name.
        unsafe { Self::from_bytes_unchecked(&[0u8]) }
    };
}

//--- Construction

impl UnparsedName {
    /// Assume a byte sequence is a valid [`UnparsedName`].
    ///
    /// # Safety
    ///
    /// The byte sequence must contain any number of encoded labels, ending
    /// with a root label or a compression pointer, as long as the size of the
    /// whole sequence is 256 bytes or less.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'UnparsedName' is 'repr(transparent)' to '[u8]', so casting
        // a '[u8]' into an 'UnparsedName' is sound.
        core::mem::transmute(bytes)
    }
}

//--- Inspection

impl UnparsedName {
    /// The size of this name in the wire format.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the root label.
    pub const fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    /// The value of this compression pointer.
    ///
    /// This returns [`Some`] if the name contains no labels, and only has a
    /// compression pointer.  The returned value is in the range 0..16384, as
    /// an offset from the start of the containing DNS message.
    pub const fn pointer_value(&self) -> Option<u16> {
        if let &[hi @ 0xC0..=0xFF, lo] = self.as_bytes() {
            Some(u16::from_be_bytes([hi, lo]) & 0x3FFF)
        } else {
            None
        }
    }

    /// A byte representation of the [`UnparsedName`].
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

//--- Interaction

impl UnparsedName {
    /// Split the first label from the name.
    pub fn split_first(&self) -> Option<(&Label, &Self)> {
        let (label, rest) = <&Label>::split_bytes(self.as_bytes())
            .ok()
            .filter(|(label, _)| !label.is_root())?;
        Some((label, unsafe { Self::from_bytes_unchecked(rest) }))
    }
}

//--- Parsing from DNS messages

impl<'a> SplitMessageBytes<'a> for &'a UnparsedName {
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        let bytes = &contents[start..];
        let mut offset = 0;
        let offset = loop {
            match bytes[offset..] {
                // This is the root label.
                [0, ..] => break offset + 1,

                // This looks like a regular label.
                [l, ref rest @ ..] if (1..64).contains(&l) => {
                    let length = l as usize;

                    if rest.len() < length || offset + 2 + length > 255 {
                        // The name is incomplete or too big.
                        return Err(ParseError);
                    }

                    offset += 1 + length;
                }

                // This is a compression pointer.
                [hi, lo, ..] if hi >= 0xC0 => {
                    let ptr = u16::from_be_bytes([hi, lo]);
                    if usize::from(ptr - 0xC000) >= start {
                        return Err(ParseError);
                    }
                    break offset + 2;
                }

                _ => return Err(ParseError),
            }
        };

        let bytes = &bytes[..offset];
        let rest = start + offset;
        Ok((unsafe { UnparsedName::from_bytes_unchecked(bytes) }, rest))
    }
}

impl<'a> ParseMessageBytes<'a> for &'a UnparsedName {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        match Self::split_message_bytes(contents, start) {
            Ok((this, rest)) if rest == contents.len() => Ok(this),
            _ => Err(ParseError),
        }
    }
}
