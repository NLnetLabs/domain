//! Domain name labels.

use core::{
    cmp, fmt,
    hash::{Hash, Hasher},
    iter, str,
};

use zerocopy_derive::*;

use crate::new_base::parse::{ParseError, ParseFrom, SplitFrom};

//----------- Label ----------------------------------------------------------

/// A label in a domain name.
#[derive(Immutable, Unaligned)]
#[repr(transparent)]
pub struct Label([u8]);

//--- Constants

impl Label {
    /// The maximum size of a label in the wire format.
    pub const MAX_SIZE: usize = 63;

    /// The root label.
    pub const ROOT: &'static Self =
        unsafe { Self::from_bytes_unchecked(b"") };

    /// The wildcard label.
    pub const WILDCARD: &'static Self =
        unsafe { Self::from_bytes_unchecked(b"*") };
}

//--- Construction

impl Label {
    /// Assume a byte string is a valid [`Label`].
    ///
    /// # Safety
    ///
    /// The byte string must be within the size restriction (63 bytes or
    /// fewer).
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Label' is a 'repr(transparent)' wrapper around '[u8]', so
        // casting a '[u8]' into a 'Label' is sound.
        core::mem::transmute(bytes)
    }

    /// Assume a mutable byte string is a valid [`Label`].
    ///
    /// # Safety
    ///
    /// The byte string must be within the size restriction (63 bytes or
    /// fewer).
    pub unsafe fn from_bytes_unchecked_mut(bytes: &mut [u8]) -> &mut Self {
        // SAFETY: 'Label' is a 'repr(transparent)' wrapper around '[u8]', so
        // casting a '[u8]' into a 'Label' is sound.
        core::mem::transmute(bytes)
    }
}

//--- Inspection

impl Label {
    /// Whether this is the root label.
    pub const fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether this is the wildcard label.
    pub const fn is_wildcard(&self) -> bool {
        // NOTE: 'self.0 == *b"*"' is not const.
        self.0.len() == 1 && self.0[0] == b'*'
    }

    /// The size of this name in the wire format.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// The wire format representation of the name.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

//--- Parsing

impl<'a> SplitFrom<'a> for &'a Label {
    /// Parse a [`Label`] from the beginning of a byte string.
    ///
    /// The input should begin with a length octet.
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (&length, bytes) = bytes.split_first().ok_or(ParseError)?;
        if length < 64 && bytes.len() >= length as usize {
            let (label, bytes) = bytes.split_at(length as usize);
            // SAFETY: 'label' is known be to less than 64 bytes in size.
            Ok((unsafe { Label::from_bytes_unchecked(label) }, bytes))
        } else {
            // Overlong label (or compression pointer).
            Err(ParseError)
        }
    }
}

impl<'a> ParseFrom<'a> for &'a Label {
    /// Parse a [`Label`] from a byte string.
    ///
    /// The input should not begin with a length octet.
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        if bytes.len() > Label::MAX_SIZE {
            // The label was too long to be used.
            return Err(ParseError);
        }

        Ok(unsafe { Label::from_bytes_unchecked(bytes) })
    }
}

//--- Equality

impl PartialEq for Label {
    /// Compare labels by their canonical value.
    ///
    /// Canonicalized labels have uppercase ASCII characters lowercased, so this
    /// function compares the two names ASCII-case-insensitively.
    ///
    // Runtime: `O(self.len())`, which is equal to `O(that.len())`.
    fn eq(&self, that: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&that.0)
    }
}

impl Eq for Label {}

//--- Ordering

impl PartialOrd for Label {
    /// Compare labels by their canonical value.
    ///
    /// Canonicalized labels have uppercase ASCII characters lowercased, so
    /// this function compares the two names ASCII-case-insensitively.
    ///
    // Runtime: `O(self.len())`, which is equal to `O(that.len())`.
    fn partial_cmp(&self, that: &Self) -> Option<cmp::Ordering> {
        Some(Ord::cmp(self, that))
    }
}

impl Ord for Label {
    /// Compare labels by their canonical value.
    ///
    /// Canonicalized labels have uppercase ASCII characters lowercased, so
    /// this function compares the two names ASCII-case-insensitively.
    ///
    // Runtime: `O(self.len())`, which is equal to `O(that.len())`.
    fn cmp(&self, that: &Self) -> cmp::Ordering {
        let this_bytes = self.as_bytes().iter().copied();
        let that_bytes = that.as_bytes().iter().copied();
        iter::zip(this_bytes, that_bytes)
            .find(|(l, r)| !l.eq_ignore_ascii_case(r))
            .map_or(Ord::cmp(&self.len(), &that.len()), |(l, r)| {
                Ord::cmp(&l.to_ascii_lowercase(), &r.to_ascii_lowercase())
            })
    }
}

//--- Hashing

impl Hash for Label {
    /// Hash this label by its canonical value.
    ///
    /// The hasher is provided with the labels in this name with ASCII
    /// characters lowercased.  Each label is preceded by its length as `u8`.
    ///
    /// The same scheme is used by [`Name`] and [`RelName`], so a tuple of any
    /// of these types will have the same hash as the concatenation of the
    /// labels.
    ///
    /// [`Name`]: super::Name
    /// [`RelName`]: super::RelName
    ///
    /// Runtime: `O(self.len())`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Individual labels and names should hash in the same way.
        state.write_u8(self.len() as u8);

        // The default 'std' hasher actually buffers 8 bytes of input before
        // processing them.  There's no point trying to chunk the input here.
        for &b in self.as_bytes() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

//--- Formatting

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Escape unusual characters (esp. non-ASCII ones).
        let mut label = self.as_bytes();
        while !label.is_empty() {
            if let Some(index) = label
                .iter()
                .position(|&b| !b.is_ascii_alphanumeric() && b != b'-')
            {
                let (head, tail) = label.split_at(index);
                // SAFETY: Every byte is an ASCII alphanumeric value.
                f.write_str(unsafe { str::from_utf8_unchecked(head) })?;
                // Write the invalid character manually.
                write!(f, "\\{:03o}", tail[0])?;
                // Process the rest of the label.
                label = &tail[1..];
            } else {
                // SAFETY: Every byte is an ASCII alphanumeric value.
                f.write_str(unsafe { str::from_utf8_unchecked(label) })?;
                break;
            }
        }

        Ok(())
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_bytes().fmt(f)
    }
}

//--- Conversion to bytes

impl AsRef<[u8]> for Label {
    /// The raw bytes in this name, with no length octet.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a Label> for &'a [u8] {
    fn from(label: &'a Label) -> Self {
        label.as_bytes()
    }
}
