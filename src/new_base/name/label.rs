//! Labels in domain names.

use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    iter::FusedIterator,
};

use domain_macros::AsBytes;

use crate::new_base::wire::{ParseBytes, ParseError, SplitBytes};

//----------- Label ----------------------------------------------------------

/// A label in a domain name.
///
/// A label contains up to 63 bytes of arbitrary data.
#[derive(AsBytes)]
#[repr(transparent)]
pub struct Label([u8]);

//--- Associated Constants

impl Label {
    /// The root label.
    pub const ROOT: &'static Self = {
        // SAFETY: All slices of 63 bytes or less are valid.
        unsafe { Self::from_bytes_unchecked(b"") }
    };

    /// The wildcard label.
    pub const WILDCARD: &'static Self = {
        // SAFETY: All slices of 63 bytes or less are valid.
        unsafe { Self::from_bytes_unchecked(b"*") }
    };
}

//--- Construction

impl Label {
    /// Assume a byte slice is a valid label.
    ///
    /// # Safety
    ///
    /// The byte slice must have length 63 or less.
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Label' is 'repr(transparent)' to '[u8]'.
        unsafe { core::mem::transmute(bytes) }
    }
}

//--- Parsing

impl<'a> SplitBytes<'a> for &'a Label {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let (&size, rest) = bytes.split_first().ok_or(ParseError)?;
        if size < 64 && rest.len() >= size as usize {
            let (label, rest) = rest.split_at(size as usize);
            // SAFETY: 'label' is 'size < 64' bytes in size.
            Ok((unsafe { Label::from_bytes_unchecked(label) }, rest))
        } else {
            Err(ParseError)
        }
    }
}

impl<'a> ParseBytes<'a> for &'a Label {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        Self::split_bytes(bytes).and_then(|(this, rest)| {
            rest.is_empty().then_some(this).ok_or(ParseError)
        })
    }
}

//--- Inspection

impl Label {
    /// The length of this label, in bytes.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the root label.
    pub const fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether this is a wildcard label.
    pub const fn is_wildcard(&self) -> bool {
        // NOTE: '==' for byte slices is not 'const'.
        self.0.len() == 1 && self.0[0] == b'*'
    }

    /// The bytes making up this label.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

//--- Access to the underlying bytes

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<'a> From<&'a Label> for &'a [u8] {
    fn from(value: &'a Label) -> Self {
        &value.0
    }
}

//--- Comparison

impl PartialEq for Label {
    /// Compare two labels for equality.
    ///
    /// Labels are compared ASCII-case-insensitively.
    fn eq(&self, other: &Self) -> bool {
        let this = self.as_bytes().iter().map(u8::to_ascii_lowercase);
        let that = other.as_bytes().iter().map(u8::to_ascii_lowercase);
        this.eq(that)
    }
}

impl Eq for Label {}

//--- Ordering

impl PartialOrd for Label {
    /// Determine the order between labels.
    ///
    /// Any uppercase ASCII characters in the labels are treated as if they
    /// were lowercase.  The first unequal byte between two labels determines
    /// its ordering: the label with the smaller byte value is the lesser.  If
    /// two labels have all the same bytes, the shorter label is lesser; if
    /// they are the same length, they are equal.
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Label {
    /// Determine the order between labels.
    ///
    /// Any uppercase ASCII characters in the labels are treated as if they
    /// were lowercase.  The first unequal byte between two labels determines
    /// its ordering: the label with the smaller byte value is the lesser.  If
    /// two labels have all the same bytes, the shorter label is lesser; if
    /// they are the same length, they are equal.
    fn cmp(&self, other: &Self) -> Ordering {
        let this = self.as_bytes().iter().map(u8::to_ascii_lowercase);
        let that = other.as_bytes().iter().map(u8::to_ascii_lowercase);
        this.cmp(that)
    }
}

//--- Hashing

impl Hash for Label {
    /// Hash this label.
    ///
    /// All uppercase ASCII characters are lowercased beforehand.  This way,
    /// the hash of a label is case-independent, consistent with how labels
    /// are compared and ordered.
    ///
    /// The label is hashed as if it were a name containing a single label --
    /// the length octet is thus included.  This makes the hashing consistent
    /// between names and tuples (not slices!) of labels.
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u8(self.len() as u8);
        for &byte in self.as_bytes() {
            state.write_u8(byte.to_ascii_lowercase())
        }
    }
}

//--- Formatting

impl fmt::Display for Label {
    /// Print a label.
    ///
    /// The label is printed in the conventional zone file format, with bytes
    /// outside printable ASCII formatted as `\\DDD` (a backslash followed by
    /// three zero-padded decimal digits), and `.` and `\\` simply escaped by
    /// a backslash.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_bytes().iter().try_for_each(|&byte| {
            if b".\\".contains(&byte) {
                write!(f, "\\{}", byte as char)
            } else if byte.is_ascii_graphic() {
                write!(f, "{}", byte as char)
            } else {
                write!(f, "\\{:03}", byte)
            }
        })
    }
}

impl fmt::Debug for Label {
    /// Print a label for debugging purposes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Label")
            .field(&format_args!("{}", self))
            .finish()
    }
}

//----------- LabelIter ------------------------------------------------------

/// An iterator over encoded [`Label`]s.
#[derive(Clone)]
pub struct LabelIter<'a> {
    /// The buffer being read from.
    ///
    /// It is assumed to contain valid encoded labels.
    bytes: &'a [u8],
}

//--- Construction

impl<'a> LabelIter<'a> {
    /// Construct a new [`LabelIter`].
    ///
    /// # Safety
    ///
    /// The byte string must contain a sequence of valid encoded labels.
    pub const unsafe fn new_unchecked(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

//--- Inspection

impl<'a> LabelIter<'a> {
    /// The remaining labels.
    pub const fn remaining(&self) -> &'a [u8] {
        self.bytes
    }
}

//--- Iteration

impl<'a> Iterator for LabelIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }

        // SAFETY: 'bytes' is assumed to only contain valid labels.
        let (head, tail) =
            unsafe { <&Label>::split_bytes(self.bytes).unwrap_unchecked() };
        self.bytes = tail;
        Some(head)
    }
}

impl FusedIterator for LabelIter<'_> {}

//--- Formatting

impl fmt::Debug for LabelIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct Labels<'a>(&'a LabelIter<'a>);

        impl fmt::Debug for Labels<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_list().entries(self.0.clone()).finish()
            }
        }

        f.debug_tuple("LabelIter").field(&Labels(self)).finish()
    }
}
