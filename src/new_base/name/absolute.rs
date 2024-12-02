//! Absolute domain names.

use core::hash::{Hash, Hasher};

use zerocopy_derive::*;

use crate::new_base::parse::{ParseError, ParseFrom, SplitFrom};

use super::RelName;

//----------- Name -----------------------------------------------------------

/// An absolute domain name.
#[derive(IntoBytes, Immutable, Unaligned)]
#[repr(transparent)]
pub struct Name([u8]);

//--- Constants

impl Name {
    /// The maximum size of an absolute domain name in the wire format.
    pub const MAX_SIZE: usize = 255;

    /// The root name.
    pub const ROOT: &'static Self =
        unsafe { Self::from_bytes_unchecked(&[0u8]) };
}

//--- Construction

impl Name {
    /// Assume a byte string is a valid [`Name`].
    ///
    /// # Safety
    ///
    /// The byte string must be correctly encoded in the wire format, and
    /// within the size restriction (255 bytes or fewer).  It must be
    /// absolute.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Name' is a 'repr(transparent)' wrapper around '[u8]', so
        // casting a '[u8]' into a 'Name' is sound.
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

    /// The wire format representation of the name.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

//--- Parsing

impl<'a> SplitFrom<'a> for &'a Name {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (name, rest) = <&RelName>::split_from(bytes)?;
        if let Some((&0, rest)) = rest.split_first() {
            // SAFETY: 'bytes' is a 'RelName' followed by a root label.
            let name = &bytes[..name.len() + 1];
            Ok((unsafe { Name::from_bytes_unchecked(name) }, rest))
        } else {
            Err(ParseError)
        }
    }
}

impl<'a> ParseFrom<'a> for &'a Name {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        // Without the last byte, this should be a relative name.
        let (root, rel_name) = bytes.split_last().ok_or(ParseError)?;

        if <&RelName>::parse_from(rel_name).is_err() {
            return Err(ParseError);
        } else if *root != 0u8 {
            // The last byte must be a root label.
            return Err(ParseError);
        }

        // SAFETY: 'bytes' has been confirmed to be correctly encoded.
        Ok(unsafe { Name::from_bytes_unchecked(bytes) })
    }
}

//--- Equality

impl PartialEq for Name {
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

impl Eq for Name {}

//--- Hash

impl Hash for Name {
    /// Hash this label by its canonical value.
    ///
    /// The hasher is provided with the labels in this name with ASCII
    /// characters lowercased.  Each label is preceded by its length as `u8`.
    ///
    /// The same scheme is used by [`RelName`] and [`Label`], so a tuple of
    /// any of these types will have the same hash as the concatenation of the
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

impl AsRef<[u8]> for Name {
    /// The bytes in the name in the wire format.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a Name> for &'a [u8] {
    fn from(name: &'a Name) -> Self {
        name.as_bytes()
    }
}
