use core::{
    fmt,
    hash::{Hash, Hasher},
};

use super::{Label, Name};

/// A relative domain name.
#[repr(transparent)]
pub struct RelName([u8]);

impl RelName {
    /// Assume a byte string is a valid [`RelName`].
    ///
    /// # Safety
    ///
    /// The byte string must be correctly encoded in the wire format, and within
    /// the size restriction (255 bytes or fewer).  It must be relative.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'RelName' is a 'repr(transparent)' wrapper around '[u8]', so
        // casting a '[u8]' into a 'RelName' is sound.
        core::mem::transmute(bytes)
    }

    /// Try converting a byte string into a [`RelName`].
    ///
    /// The byte string is confirmed to be correctly encoded in the wire format.
    /// If it is not properly encoded, an error is returned.
    ///
    /// Runtime: `O(bytes.len())`.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self, RelNameError> {
        if bytes.len() + 1 > Name::MAX_SIZE {
            // This can never become an absolute domain name.
            return Err(RelNameError);
        }

        // Iterate through labels in the name.
        let mut index = 0usize;
        while index < bytes.len() {
            let length = bytes[index];
            if length == 0 {
                // Empty labels are not allowed.
                return Err(RelNameError);
            } else if length >= 64 {
                // An invalid label length (or a compression pointer).
                return Err(RelNameError);
            } else {
                // This was the length of the label, excluding the length octet.
                index += 1 + length as usize;
            }
        }

        // We must land exactly at the end of the name, otherwise the previous
        // label reported a length that was too long.
        if index != bytes.len() {
            return Err(RelNameError);
        }

        // SAFETY: 'bytes' has been confirmed to be correctly encoded.
        Ok(unsafe { Self::from_bytes_unchecked(bytes) })
    }

    /// Treat a single label as a [`RelName`].
    ///
    /// Runtime: `O(1)`.
    pub fn from_label(label: &Label) -> &Self {
        // SAFETY: 'bytes' is a valid label and always fits within a name.
        unsafe { Self::from_bytes_unchecked(label.as_bytes()) }
    }
}

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

    /// The parent of this name, if any.
    ///
    /// The name containing all but the first label is returned.  If there are
    /// no remaining labels, [`None`] is returned.
    ///
    /// Runtime: `O(1)`.
    pub fn parent(&self) -> Option<&Self> {
        if self.is_empty() {
            return None;
        }

        let bytes = self.as_bytes();
        let bytes = &bytes[1 + bytes[0] as usize..];

        // SAFETY: 'bytes' is 253 bytes or smaller and has valid labels.
        Some(unsafe { Self::from_bytes_unchecked(bytes) })
    }

    /// Whether this name starts with a particular relative name.
    ///
    /// Runtime: `O(prefix.len())`, which is less than `O(self.len())`.
    pub fn starts_with(&self, prefix: &RelName) -> bool {
        if self.len() < prefix.len() {
            return false;
        }

        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the byte strings as ASCII.
        self.as_bytes()[..prefix.len()]
            .eq_ignore_ascii_case(prefix.as_bytes())
    }

    /// Whether this name ends with a particular relative name.
    ///
    /// Runtime: `O(self.len())`, which is more than `O(suffix.len())`.
    pub fn ends_with(&self, suffix: &Self) -> bool {
        if self.len() < suffix.len() {
            return false;
        }

        // We want to compare the last bytes of the current name to the given
        // candidate.  To do so, we need to ensure that those last bytes start
        // at a valid label boundary.

        let mut index = 0usize;
        let offset = self.len() - suffix.len();
        while index < offset {
            index += 1 + self.0[index] as usize;
        }

        if index != offset {
            return false;
        }

        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the byte strings as ASCII.
        self.as_bytes()[offset..].eq_ignore_ascii_case(suffix.as_bytes())
    }
}

impl RelName {
    /// Split this name into a label and the rest.
    ///
    /// If the name is empty, [`None`] is returned.  The returned label will
    /// always be non-empty.
    ///
    /// Runtime: `O(1)`.
    pub fn split_first(&self) -> Option<(&Label, &Self)> {
        if self.is_empty() {
            return None;
        }

        let bytes = self.as_bytes();
        let (label, rest) = bytes[1..].split_at(1 + bytes[0] as usize);

        // SAFETY: 'self' only contains valid labels.
        let label = unsafe { Label::from_bytes_unchecked(label) };
        // SAFETY: 'rest' is 252 bytes or smaller and has valid labels.
        let rest = unsafe { Self::from_bytes_unchecked(rest) };

        Some((label, rest))
    }

    /// Strip a prefix from this name.
    ///
    /// If this name has the given prefix (see [`Self::starts_with()`]), the
    /// rest of the name without the prefix is returned.  Otherwise, [`None`] is
    /// returned.
    ///
    /// Runtime: `O(prefix.len())`, which is less than `O(self.len())`.
    pub fn strip_prefix<'a>(&'a self, prefix: &RelName) -> Option<&'a Self> {
        if self.starts_with(prefix) {
            let bytes = &self.as_bytes()[prefix.len()..];

            // SAFETY: 'self' and 'prefix' consist of whole labels, and 'self'
            // start with the same labels as 'prefix'; removing those labels
            // still leaves 'self' with whole labels.
            Some(unsafe { Self::from_bytes_unchecked(bytes) })
        } else {
            None
        }
    }

    /// Strip a suffix from this name.
    ///
    /// If this name has the given suffix (see [`Self::ends_with()`]), the rest
    /// of the name without the suffix is returned.  Otherwise, [`None`] is
    /// returned.
    ///
    /// Runtime: `O(self.len())`, which is more than `O(suffix.len())`.
    pub fn strip_suffix<'a>(&'a self, suffix: &Self) -> Option<&'a Self> {
        if self.ends_with(suffix) {
            let bytes = &self.as_bytes()[..self.len() - suffix.len()];

            // SAFETY: 'self' and 'suffix' consist of whole labels, and 'self'
            // ended with the same labels as 'suffix'; removing those labels
            // still leaves 'self' with whole labels.
            Some(unsafe { Self::from_bytes_unchecked(bytes) })
        } else {
            None
        }
    }

    /// Canonicalize this domain name.
    ///
    /// All uppercase ASCII characters in the name will be lowercased.
    ///
    /// Runtime: `O(self.len())`.
    pub fn canonicalize(&mut self) {
        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the entire byte string as ASCII.
        self.0.make_ascii_lowercase()
    }
}

impl PartialEq for RelName {
    /// Compare labels by their canonical value.
    ///
    /// Canonicalized labels have uppercase ASCII characters lowercased, so this
    /// function compares the two names ASCII-case-insensitively.
    ///
    // Runtime: `O(self.len())`, which is equal to `O(that.len())`.
    fn eq(&self, that: &Self) -> bool {
        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the entire byte string as ASCII.
        self.0.eq_ignore_ascii_case(&that.0)
    }
}

impl Eq for RelName {}

impl Hash for RelName {
    /// Hash this label by its canonical value.
    ///
    /// The hasher is provided with the labels in this name with ASCII
    /// characters lowercased.  Each label is preceded by its length as `u8`.
    ///
    /// The same scheme is used by [`Name`] and [`Label`], so a tuple of any of
    /// these types will have the same hash as the concatenation of the labels.
    ///
    /// Runtime: `O(self.len())`.
    fn hash<H: Hasher>(&self, state: &mut H) {
        // NOTE: Label lengths are not affected by 'to_ascii_lowercase()' since
        // they are always less than 64.  As such, we don't need to iterate over
        // the labels manually; we can just give them to the hasher as-is.

        // The default 'std' hasher actually buffers 8 bytes of input before
        // processing them.  There's no point trying to chunk the input here.
        self.as_bytes()
            .iter()
            .map(|&b| b.to_ascii_lowercase())
            .for_each(|b| state.write_u8(b));
    }
}

impl AsRef<[u8]> for RelName {
    /// The bytes in the name in the wire format.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a Label> for &'a RelName {
    fn from(label: &'a Label) -> Self {
        RelName::from_label(label)
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a RelName {
    type Error = RelNameError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        RelName::from_bytes(bytes)
    }
}

impl<'a> From<&'a RelName> for &'a [u8] {
    fn from(name: &'a RelName) -> Self {
        name.as_bytes()
    }
}

/// An error in constructing a [`RelName`].
#[derive(Clone, Debug)]
pub struct RelNameError;

impl fmt::Display for RelNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("could not parse a relative domain name")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RelNameError {}
