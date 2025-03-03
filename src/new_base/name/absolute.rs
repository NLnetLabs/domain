//! Absolute domain names.

use core::{
    fmt,
    hash::{Hash, Hasher},
};

use domain_macros::{AsBytes, BuildBytes};

use crate::new_base::wire::{ParseBytes, ParseError, SplitBytes};

use super::LabelIter;

//----------- Name -----------------------------------------------------------

/// An absolute domain name.
#[derive(AsBytes, BuildBytes)]
#[repr(transparent)]
pub struct Name([u8]);

//--- Constants

impl Name {
    /// The maximum size of a domain name.
    pub const MAX_SIZE: usize = 255;

    /// The root name.
    pub const ROOT: &'static Self = {
        // SAFETY: A root label is the shortest valid name.
        unsafe { Self::from_bytes_unchecked(&[0u8]) }
    };
}

//--- Construction

impl Name {
    /// Assume a byte string is a valid [`Name`].
    ///
    /// # Safety
    ///
    /// The byte string must represent a valid uncompressed domain name in the
    /// conventional wire format (a sequence of labels terminating with a root
    /// label, totalling 255 bytes or less).
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Name' is 'repr(transparent)' to '[u8]', so casting a
        // '[u8]' into a 'Name' is sound.
        core::mem::transmute(bytes)
    }

    /// Assume a mutable byte string is a valid [`Name`].
    ///
    /// # Safety
    ///
    /// The byte string must represent a valid uncompressed domain name in the
    /// conventional wire format (a sequence of labels terminating with a root
    /// label, totalling 255 bytes or less).
    pub unsafe fn from_bytes_unchecked_mut(bytes: &mut [u8]) -> &mut Self {
        // SAFETY: 'Name' is 'repr(transparent)' to '[u8]', so casting a
        // '[u8]' into a 'Name' is sound.
        core::mem::transmute(bytes)
    }
}

//--- Inspection

impl Name {
    /// The size of this name in the wire format.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the root label.
    pub const fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    /// A byte representation of the [`Name`].
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The labels in the [`Name`].
    ///
    /// Note that labels appear in reverse order to the _conventional_ format
    /// (it thus starts with the root label).
    pub const fn labels(&self) -> LabelIter<'_> {
        // SAFETY: A 'Name' always contains valid encoded labels.
        unsafe { LabelIter::new_unchecked(self.as_bytes()) }
    }
}

//--- Parsing from bytes

impl<'a> ParseBytes<'a> for &'a Name {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        match Self::split_bytes(bytes) {
            Ok((this, &[])) => Ok(this),
            _ => Err(ParseError),
        }
    }
}

impl<'a> SplitBytes<'a> for &'a Name {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let mut offset = 0usize;
        while offset < 255 {
            match *bytes.get(offset..).ok_or(ParseError)? {
                [0, ..] => {
                    // Found the root, stop.
                    let (name, rest) = bytes.split_at(offset + 1);

                    // SAFETY: 'name' follows the wire format and is 255 bytes
                    // or shorter.
                    let name = unsafe { Name::from_bytes_unchecked(name) };
                    return Ok((name, rest));
                }

                [l, ..] if l < 64 => {
                    // This looks like a regular label.

                    if bytes.len() < offset + 1 + l as usize {
                        // The input doesn't contain the whole label.
                        return Err(ParseError);
                    }

                    offset += 1 + l as usize;
                }

                _ => return Err(ParseError),
            }
        }

        Err(ParseError)
    }
}

//--- Equality

impl PartialEq for Name {
    fn eq(&self, that: &Self) -> bool {
        // Instead of iterating labels, blindly iterate bytes.  The locations
        // of labels don't matter since we're testing everything for equality.

        // NOTE: Label lengths (which are less than 64) aren't affected by
        // 'to_ascii_lowercase', so this method can be applied uniformly.
        let this = self.as_bytes().iter().map(u8::to_ascii_lowercase);
        let that = that.as_bytes().iter().map(u8::to_ascii_lowercase);

        this.eq(that)
    }
}

impl Eq for Name {}

//--- Hashing

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.as_bytes() {
            // NOTE: Label lengths (which are less than 64) aren't affected by
            // 'to_ascii_lowercase', so this method can be applied uniformly.
            state.write_u8(byte.to_ascii_lowercase())
        }
    }
}

//--- Formatting

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        self.labels().try_for_each(|label| {
            if !first {
                f.write_str(".")?;
            } else {
                first = false;
            }

            label.fmt(f)
        })
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Name")
            .field(&format_args!("{}", self))
            .finish()
    }
}
