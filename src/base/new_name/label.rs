use core::{
    cmp, fmt,
    hash::{Hash, Hasher},
    iter,
};

use super::{Octets, Owned, SmallOctets};

/// A label in a domain name.
#[repr(transparent)]
pub struct Label([u8]);

impl Label {
    /// The maximum size of a label in the wire format.
    pub const MAX_SIZE: usize = 63;

    /// The root label.
    pub const ROOT: &Self = unsafe { Self::from_bytes_unchecked(b"") };

    /// The wildcard label.
    pub const WILDCARD: &Self = unsafe { Self::from_bytes_unchecked(b"*") };
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
    ///
    /// Runtime: `O(bytes.len())`.
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
    ///
    /// Runtime: `O(1)`.
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

    /// Whether this is an internationalized label.
    ///
    /// If the label begins with the ACE (ASCII Compatible Encoding) prefix
    /// `xn--`, it is assumed to be a Unicode string encoded into ASCII using
    /// the Nameprep and Punycode algorithms.
    pub fn is_internationalized(&self) -> bool {
        self.as_bytes().starts_with(b"xn--")
    }
}

impl Label {
    /// Canonicalize this label.
    ///
    /// All uppercase ASCII characters in the label will be lowercased.
    ///
    /// Runtime: `O(self.len())`.
    pub fn canonicalize(&mut self) {
        self.0.make_ascii_lowercase()
    }
}

unsafe impl Octets for Label {
    unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        Label::from_bytes_unchecked(bytes)
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

unsafe impl<Buffer> SmallOctets<Buffer> for Label where
    Buffer: AsRef<[u8; 64]> + AsRef<[u8]>
{
}

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

impl PartialOrd for Label {
    /// Compare labels by their canonical value.
    ///
    /// Canonicalized labels have uppercase ASCII characters lowercased, so this
    /// function compares the two names ASCII-case-insensitively.
    ///
    // Runtime: `O(self.len())`, which is equal to `O(that.len())`.
    fn partial_cmp(&self, that: &Self) -> Option<cmp::Ordering> {
        Some(Ord::cmp(self, that))
    }
}

impl Ord for Label {
    /// Compare labels by their canonical value.
    ///
    /// Canonicalized labels have uppercase ASCII characters lowercased, so this
    /// function compares the two names ASCII-case-insensitively.
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
        self.as_bytes()
            .iter()
            .map(|&b| b.to_ascii_lowercase())
            .for_each(|b| state.write_u8(b));
    }
}

impl AsRef<[u8]> for Label {
    /// The raw bytes in this name, with no length octet.
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> TryFrom<&'a [u8]> for &'a Label {
    type Error = LabelError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        Label::from_bytes(bytes)
    }
}

impl<'a> From<&'a Label> for &'a [u8] {
    fn from(label: &'a Label) -> Self {
        label.as_bytes()
    }
}

/// An owned label.
pub type OwnedLabel = Owned<[u8; 64], Label>;

/// An error in constructing a [`Label`].
#[derive(Clone, Debug)]
pub struct LabelError;

impl fmt::Display for LabelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("could not parse a domain name label")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LabelError {}
