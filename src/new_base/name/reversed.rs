//! Reversed DNS names.

use core::{
    borrow::Borrow,
    cmp::Ordering,
    hash::{Hash, Hasher},
    ops::Deref,
};

use zerocopy_derive::*;

use super::LabelIter;

//----------- RevName --------------------------------------------------------

/// A domain name in reversed order.
///
/// Domain names are conventionally presented and encoded from the innermost
/// label to the root label.  This ordering is inconvenient and difficult to
/// use, making many common operations (e.g. comparing and ordering domain
/// names) more computationally expensive.  A [`RevName`] stores the labels in
/// reversed order for more efficient use.
#[derive(Immutable, Unaligned)]
#[repr(transparent)]
pub struct RevName([u8]);

//--- Constants

impl RevName {
    /// The maximum size of a (reversed) domain name.
    ///
    /// This is the same as the maximum size of a regular domain name.
    pub const MAX_SIZE: usize = 255;

    /// The root name.
    pub const ROOT: &'static Self = {
        // SAFETY: A root label is the shortest valid name.
        unsafe { Self::from_bytes_unchecked(&[0u8]) }
    };
}

//--- Construction

impl RevName {
    /// Assume a byte string is a valid [`RevName`].
    ///
    /// # Safety
    ///
    /// The byte string must begin with a root label (0-value byte).  It must
    /// be followed by any number of encoded labels, as long as the size of
    /// the whole string is 255 bytes or less.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'RevName' is 'repr(transparent)' to '[u8]', so casting a
        // '[u8]' into a 'RevName' is sound.
        core::mem::transmute(bytes)
    }
}

//--- Inspection

impl RevName {
    /// The size of this name in the wire format.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the root label.
    pub const fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    /// A byte representation of the [`RevName`].
    ///
    /// Note that labels appear in reverse order to the _conventional_ format
    /// (it thus starts with the root label).
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The labels in the [`RevName`].
    ///
    /// Note that labels appear in reverse order to the _conventional_ format
    /// (it thus starts with the root label).
    pub const fn labels(&self) -> LabelIter<'_> {
        // SAFETY: A 'RevName' always contains valid encoded labels.
        unsafe { LabelIter::new_unchecked(self.as_bytes()) }
    }
}

//--- Equality

impl PartialEq for RevName {
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

impl Eq for RevName {}

//--- Comparison

impl PartialOrd for RevName {
    fn partial_cmp(&self, that: &Self) -> Option<Ordering> {
        Some(self.cmp(that))
    }
}

impl Ord for RevName {
    fn cmp(&self, that: &Self) -> Ordering {
        // Unfortunately, names cannot be compared bytewise.  Labels are
        // preceded by their length octets, but a longer label can be less
        // than a shorter one if its first bytes are less.  We are forced to
        // compare lexicographically over labels.
        self.labels().cmp(that.labels())
    }
}

//--- Hashing

impl Hash for RevName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.as_bytes() {
            // NOTE: Label lengths (which are less than 64) aren't affected by
            // 'to_ascii_lowercase', so this method can be applied uniformly.
            state.write_u8(byte.to_ascii_lowercase())
        }
    }
}

//----------- RevNameBuf -----------------------------------------------------

/// A 256-byte buffer containing a [`RevName`].
#[derive(Immutable, Unaligned)]
#[repr(C)] // make layout compatible with '[u8; 256]'
pub struct RevNameBuf {
    /// The position of the root label in the buffer.
    offset: u8,

    /// The buffer containing the [`RevName`].
    buffer: [u8; 255],
}

//--- Construction

impl RevNameBuf {
    /// Copy a [`RevName`] into a buffer.
    pub fn copy_from(name: &RevName) -> Self {
        let offset = 255 - name.len() as u8;
        let mut buffer = [0u8; 255];
        buffer[offset as usize..].copy_from_slice(name.as_bytes());
        Self { offset, buffer }
    }
}

//--- Access to the underlying 'RevName'

impl Deref for RevNameBuf {
    type Target = RevName;

    fn deref(&self) -> &Self::Target {
        let name = &self.buffer[self.offset as usize..];
        // SAFETY: A 'RevNameBuf' always contains a valid 'RevName'.
        unsafe { RevName::from_bytes_unchecked(name) }
    }
}

impl Borrow<RevName> for RevNameBuf {
    fn borrow(&self) -> &RevName {
        self
    }
}

impl AsRef<RevName> for RevNameBuf {
    fn as_ref(&self) -> &RevName {
        self
    }
}

//--- Forwarding equality, comparison, and hashing

impl PartialEq for RevNameBuf {
    fn eq(&self, that: &Self) -> bool {
        **self == **that
    }
}

impl Eq for RevNameBuf {}

impl PartialOrd for RevNameBuf {
    fn partial_cmp(&self, that: &Self) -> Option<Ordering> {
        Some(self.cmp(that))
    }
}

impl Ord for RevNameBuf {
    fn cmp(&self, that: &Self) -> Ordering {
        (**self).cmp(&**that)
    }
}

impl Hash for RevNameBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}
