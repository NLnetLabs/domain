//! Labels in domain names.

use core::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
};

use zerocopy_derive::*;

//----------- Label ----------------------------------------------------------

/// A label in a domain name.
///
/// A label contains up to 63 bytes of arbitrary data.
#[derive(IntoBytes, Immutable, Unaligned)]
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
