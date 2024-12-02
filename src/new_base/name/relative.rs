//! Relative domain names.

use core::{
    cmp::min,
    hash::{Hash, Hasher},
};

use zerocopy_derive::*;

use crate::new_base::parse::{ParseError, ParseFrom, SplitFrom};

use super::Name;

//----------- RelName --------------------------------------------------------

/// A relative domain name.
#[derive(IntoBytes, Immutable, Unaligned)]
#[repr(transparent)]
pub struct RelName([u8]);

//--- Associated Constants

impl RelName {
    /// An empty relative name.
    pub const EMPTY: &'static Self =
        unsafe { Self::from_bytes_unchecked(&[]) };
}

//--- Construction

impl RelName {
    /// Assume a byte string is a valid [`RelName`].
    ///
    /// # Safety
    ///
    /// The byte string must be correctly encoded in the wire format, and
    /// within the size restriction (255 bytes or fewer).  It must be
    /// relative.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'RelName' is a 'repr(transparent)' wrapper around '[u8]',
        // so casting a '[u8]' into a 'RelName' is sound.
        core::mem::transmute(bytes)
    }
}

//--- Inspection

impl RelName {
    /// The size of this name in the wire format.
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this name contains no labels at all.
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The wire format representation of the name.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

//--- Parsing

impl<'a> SplitFrom<'a> for &'a RelName {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        // Iterate through labels in the name.
        let mut index = 0usize;
        loop {
            // Make sure we are still in bounds.
            if index >= min(255, bytes.len()) {
                return Err(ParseError);
            }

            let length = bytes[index];
            if (1..64).contains(&length) {
                // This was the length of the label, excluding the length
                // octet.
                index += 1 + length as usize;
            } else {
                // This is a root label or something else; stop.
                break;
            }
        }

        // SAFETY: the first 'index' bytes constitute a valid 'RelName'.
        let (name, rest) = bytes.split_at(index);
        Ok((unsafe { RelName::from_bytes_unchecked(name) }, rest))
    }
}

impl<'a> ParseFrom<'a> for &'a RelName {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() + 1 > Name::MAX_SIZE {
            // This can never become an absolute domain name.
            return Err(ParseError);
        }

        // Iterate through labels in the name.
        let mut index = 0usize;
        while index < bytes.len() {
            let length = bytes[index];
            if length == 0 {
                // Empty labels are not allowed.
                return Err(ParseError);
            } else if length >= 64 {
                // An invalid label length (or a compression pointer).
                return Err(ParseError);
            } else {
                // This was the length of the label, excluding the length
                // octet.
                index += 1 + length as usize;
            }
        }

        // We must land exactly at the end of the name, otherwise the previous
        // label reported a length that was too long.
        if index != bytes.len() {
            return Err(ParseError);
        }

        // SAFETY: 'bytes' has been confirmed to be correctly encoded.
        Ok(unsafe { RelName::from_bytes_unchecked(bytes) })
    }
}

//--- Equality

impl PartialEq for RelName {
    /// Compare labels by their canonical value.
    ///
    /// Canonicalized labels have uppercase ASCII characters lowercased, so
    /// this function compares the two names case-insensitively.
    ///
    // Runtime: `O(self.len())`, which is equal to `O(that.len())`.
    fn eq(&self, that: &Self) -> bool {
        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the entire byte string as ASCII.
        self.0.eq_ignore_ascii_case(&that.0)
    }
}

impl Eq for RelName {}

//--- Hash

impl Hash for RelName {
    /// Hash this label by its canonical value.
    ///
    /// The hasher is provided with the labels in this name with ASCII
    /// characters lowercased.  Each label is preceded by its length as `u8`.
    ///
    /// The same scheme is used by [`Name`] and [`Label`], so a tuple of any
    /// of these types will have the same hash as the concatenation of the
    /// labels.
    ///
    /// Runtime: `O(self.len())`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        // NOTE: Label lengths are not affected by 'to_ascii_lowercase()'
        // since they are always less than 64.  As such, we don't need to
        // iterate over the labels manually; we can just give them to the
        // hasher as-is.

        // The default 'std' hasher actually buffers 8 bytes of input before
        // processing them.  There's no point trying to chunk the input here.
        self.as_bytes()
            .iter()
            .map(|&b| b.to_ascii_lowercase())
            .for_each(|b| state.write_u8(b));
    }
}

//--- Conversion to bytes

impl AsRef<[u8]> for RelName {
    /// The bytes in the name in the wire format.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a RelName> for &'a [u8] {
    fn from(name: &'a RelName) -> Self {
        name.as_bytes()
    }
}
