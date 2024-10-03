//! Domain names.
//!
//! A _domain name_ is a sequence of _labels_ that names an entity within a
//! hierarchy.  In the domain name `www.example.org.`, the hierarchy is: `.`
//! (the root) -> `org.` -> `example.org.` -> `www.example.org.`.  Labels are
//! stored in reverse order, from innermost to outermost.

use core::{
    cmp,
    hash::{Hash, Hasher},
    iter,
};

/// An absolute domain name.
#[repr(transparent)]
pub struct Name([u8]);

impl Name {
    /// The maximum size of an absolute domain name in the wire format.
    pub const MAX_SIZE: usize = 255;

    /// The root name.
    pub const ROOT: &Self = unsafe { Self::from_bytes_unchecked(&[0u8]) };
}

impl Name {
    /// Assume a byte string is a valid [`Name`].
    ///
    /// # Safety
    ///
    /// The byte string must be correctly encoded in the wire format, and within
    /// the size restriction (255 bytes or fewer).  It must be absolute.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Name' is a 'repr(transparent)' wrapper around '[u8]', so
        // casting a '[u8]' into a 'Name' is sound.
        core::mem::transmute(bytes)
    }

    /// Try converting a byte string into a [`Name`].
    ///
    /// The byte string is confirmed to be correctly encoded in the wire format.
    /// If it is not properly encoded, an error is returned.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self, NameError> {
        // Without the last byte, this should be a relative name.
        let (root, rel_name) = bytes.split_last().ok_or(NameError)?;

        if RelName::from_bytes(rel_name).is_err() {
            return Err(NameError);
        } else if *root != 0u8 {
            // The last byte must be a root label.
            return Err(NameError);
        }

        // SAFETY: 'bytes' has been confirmed to be correctly encoded.
        Ok(unsafe { Self::from_bytes_unchecked(bytes) })
    }
}

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

    /// The parent of this name, if any.
    ///
    /// The name containing all but the first label is returned.  If this is a
    /// root name, [`None`] is returned.
    pub fn parent(&self) -> Option<&Self> {
        if self.is_root() {
            return None;
        }

        let bytes = self.as_bytes();
        let bytes = &bytes[1 + bytes[0] as usize..];

        // SAFETY: 'bytes' is 253 bytes or smaller and has valid labels.
        Some(unsafe { Self::from_bytes_unchecked(bytes) })
    }

    /// The whole name without the root label.
    ///
    /// If this is a root name, an empty relative name is returned.
    ///
    /// This is equivalent to `self.strip_suffix(Name::ROOT).unwrap()`.
    pub fn without_root(&self) -> &RelName {
        let bytes = &self.as_bytes()[..self.len() - 1];
        // SAFETY: A slice of labels (as from 'self') is a relative name.
        unsafe { RelName::from_bytes_unchecked(bytes) }
    }

    /// Whether this name starts with a particular relative name.
    pub fn starts_with(&self, that: &RelName) -> bool {
        if self.len() < that.len() {
            return false;
        }

        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the byte strings as ASCII.
        self.as_bytes()[..that.len()].eq_ignore_ascii_case(that.as_bytes())
    }

    /// Whether this name ends with a particular absolute name.
    pub fn ends_with(&self, that: &Self) -> bool {
        if self.len() < that.len() {
            return false;
        }

        // We want to compare the last bytes of the current name to the given
        // candidate.  To do so, we need to ensure that those last bytes start
        // at a valid label boundary.

        let mut index = 0usize;
        let offset = self.len() - that.len();
        while index < offset {
            index += 1 + self.0[index] as usize;
        }

        if index != offset {
            return false;
        }

        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the byte strings as ASCII.
        self.as_bytes()[offset..].eq_ignore_ascii_case(that.as_bytes())
    }
}

impl Name {
    /// Split this name into a label and the rest.
    ///
    /// If this is the root name, [`None`] is returned.  The returned label will
    /// always be non-empty.
    pub fn split_first(&self) -> Option<(&Label, &Self)> {
        if self.is_root() {
            return None;
        }

        let bytes = self.as_bytes();
        let (label, rest) = bytes[1..].split_at(1 + bytes[0] as usize);

        // SAFETY: 'self' only contains valid labels.
        let label = unsafe { Label::from_bytes_unchecked(label) };
        // SAFETY: 'rest' is 253 bytes or smaller and has valid labels.
        let rest = unsafe { Self::from_bytes_unchecked(rest) };

        Some((label, rest))
    }

    /// Strip a prefix from this name.
    ///
    /// If this name has the given prefix (see [`Self::starts_with()`]), the
    /// rest of the name without the prefix is returned.  Otherwise, [`None`] is
    /// returned.
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
    pub fn canonicalize(&mut self) {
        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the entire byte string as ASCII.
        self.0.make_ascii_lowercase()
    }
}

impl PartialEq for Name {
    fn eq(&self, that: &Self) -> bool {
        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the entire byte string as ASCII.
        self.0.eq_ignore_ascii_case(&that.0)
    }
}

impl Eq for Name {}

impl PartialOrd for Name {
    fn partial_cmp(&self, that: &Self) -> Option<cmp::Ordering> {
        Some(Ord::cmp(self, that))
    }
}

impl Ord for Name {
    fn cmp(&self, that: &Self) -> cmp::Ordering {
        // We want to find a shared suffix between the two names, and the labels
        // immediately before that shared suffix.  However, we can't determine
        // label boundaries when working backward.  So, we find a shared suffix
        // (even if it crosses partially between labels), then iterate through
        // both names until we find their label boundaries up to the suffix.

        let this_iter = self.as_bytes().iter().rev();
        let that_iter = that.as_bytes().iter().rev();
        let suffix = iter::zip(this_iter, that_iter)
            .position(|(l, r)| l.eq_ignore_ascii_case(r));

        if let Some(suffix) = suffix {
            // Iterate through the labels in both names until both have a tail
            // of equal size within the shared suffix we found.

            // SAFETY: At least one unequal byte exists in both names, and it
            // cannot be the root label, so there must be at least one non-root
            // label in both names.
            let (mut this_head, mut this_tail) =
                unsafe { self.split_first().unwrap_unchecked() };
            let (mut that_head, mut that_tail) =
                unsafe { self.split_first().unwrap_unchecked() };

            loop {
                let (this_len, that_len) = (this_tail.len(), that_tail.len());

                if this_len == that_len && this_len < suffix {
                    // We have found the shared suffix of labels.  Now, we must
                    // have two unequal head labels; we compare them (ASCII case
                    // insensitively).
                    break Ord::cmp(this_head, that_head);
                }

                // If one tail is longer than the other, it will be shortened.
                // Any tail longer than the suffix will also be shortened.

                if this_len > that_len || this_len > suffix {
                    // SAFETY: 'this_tail' has strictly more than one byte.
                    (this_head, this_tail) =
                        unsafe { this_tail.split_first().unwrap_unchecked() };
                }

                if that_len > this_len || that_len > suffix {
                    // SAFETY: 'that_tail' has strictly more than one byte.
                    (that_head, that_tail) =
                        unsafe { that_tail.split_first().unwrap_unchecked() };
                }
            }
        } else {
            // The shorter name is a suffix of the longer one.  If the names are
            // of equal length, they are equal; otherwise, the longer one has
            // more labels, and is greater than the shorter one.
            Ord::cmp(&self.len(), &that.len())
        }
    }
}

impl Hash for Name {
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

impl AsRef<[u8]> for Name {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

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
    pub fn starts_with(&self, that: &RelName) -> bool {
        if self.len() < that.len() {
            return false;
        }

        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the byte strings as ASCII.
        self.as_bytes()[..that.len()].eq_ignore_ascii_case(that.as_bytes())
    }

    /// Whether this name ends with a particular relative name.
    pub fn ends_with(&self, that: &Self) -> bool {
        if self.len() < that.len() {
            return false;
        }

        // We want to compare the last bytes of the current name to the given
        // candidate.  To do so, we need to ensure that those last bytes start
        // at a valid label boundary.

        let mut index = 0usize;
        let offset = self.len() - that.len();
        while index < offset {
            index += 1 + self.0[index] as usize;
        }

        if index != offset {
            return false;
        }

        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the byte strings as ASCII.
        self.as_bytes()[offset..].eq_ignore_ascii_case(that.as_bytes())
    }
}

impl RelName {
    /// Split this name into a label and the rest.
    ///
    /// If the name is empty, [`None`] is returned.  The returned label will
    /// always be non-empty.
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
    pub fn canonicalize(&mut self) {
        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the entire byte string as ASCII.
        self.0.make_ascii_lowercase()
    }
}

impl PartialEq for RelName {
    fn eq(&self, that: &Self) -> bool {
        // Label lengths are never ASCII characters, because they start from
        // byte value 65.  So we can treat the entire byte string as ASCII.
        self.0.eq_ignore_ascii_case(&that.0)
    }
}

impl Eq for RelName {}

impl Hash for RelName {
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
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A label in a domain name.
#[repr(transparent)]
pub struct Label([u8]);

impl Label {
    /// The maximum size of a label in the wire format.
    pub const MAX_SIZE: usize = 63;

    /// The root label.
    pub const ROOT: &Self = unsafe { Self::from_bytes_unchecked(&[]) };
}

impl Label {
    /// Assume a byte string is a valid [`Label`].
    ///
    /// # Safety
    ///
    /// The byte string must be within the size restriction (63 bytes or fewer).
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Label' is a 'repr(transparent)' wrapper around '[u8]', so
        // casting a '[u8]' into a 'Label' is sound.
        core::mem::transmute(bytes)
    }

    /// Try converting a byte string into a [`Label`].
    ///
    /// If the byte string is too long, an error is returned.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self, LabelError> {
        if bytes.len() > Self::MAX_SIZE {
            // The label was too long to be used.
            return Err(LabelError);
        }

        Ok(unsafe { Self::from_bytes_unchecked(bytes) })
    }

    /// Extract a label from the start of a byte string.
    ///
    /// A label encoded in the wire format will be extracted from the beginning
    /// of the given byte string.  If a valid label cannot be extracted, or the
    /// byte string is simply empty, an error is returned.  The extracted label
    /// and the remainder of the byte string are returned.
    pub fn split_off(bytes: &[u8]) -> Result<(&Self, &[u8]), LabelError> {
        let (&length, bytes) = bytes.split_first().ok_or(LabelError)?;
        if length < 64 && bytes.len() >= length as usize {
            let (label, bytes) = bytes.split_at(length as usize);
            // SAFETY: 'label' is known be to less than 64 bytes in size.
            Ok((unsafe { Self::from_bytes_unchecked(label) }, bytes))
        } else {
            // Overlong label (or compression pointer).
            Err(LabelError)
        }
    }
}

impl Label {
    /// Whether this is the root label.
    pub const fn is_root(&self) -> bool {
        self.0.is_empty()
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

impl Label {
    /// Canonicalize this label.
    ///
    /// All uppercase ASCII characters in the label will be lowercased.
    pub fn canonicalize(&mut self) {
        self.0.make_ascii_lowercase()
    }
}

impl PartialEq for Label {
    fn eq(&self, that: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&that.0)
    }
}

impl Eq for Label {}

impl PartialOrd for Label {
    fn partial_cmp(&self, that: &Self) -> Option<cmp::Ordering> {
        Some(Ord::cmp(self, that))
    }
}

impl Ord for Label {
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

impl Hash for Label {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Individual labels and names should hash in the same way.
        state.write_u8(self.len() as u8);

        // The default 'std' hasher actually buffers 8 bytes of input before
        // processing them.  There's no point trying to chunk the input here.
        self.as_bytes()
            .iter()
            .map(|&b| b.to_ascii_lowercase())
            .for_each(|b| state.write_u8(b));
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An error in costructing a [`Name`].
pub struct NameError;

/// An error in constructing a [`RelName`].
pub struct RelNameError;

/// An error in constructing a [`Label`].
pub struct LabelError;
