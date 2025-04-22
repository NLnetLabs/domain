//! Labels in domain names.

use core::{
    borrow::{Borrow, BorrowMut},
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    iter::FusedIterator,
    ops::{Deref, DerefMut},
    str::FromStr,
};

use crate::new_base::build::{BuildIntoMessage, BuildResult, Builder};
use crate::new_base::parse::{ParseMessageBytes, SplitMessageBytes};
use crate::new_base::wire::{
    AsBytes, BuildBytes, ParseBytes, ParseError, SplitBytes, TruncationError,
};
use crate::utils::dst::{UnsizedCopy, UnsizedCopyFrom};

//----------- Label ----------------------------------------------------------

/// A label in a domain name.
///
/// A label contains up to 63 bytes of arbitrary data.
#[derive(AsBytes, UnsizedCopy)]
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

    /// Assume a mutable byte slice is a valid label.
    ///
    /// # Safety
    ///
    /// The byte slice must have length 63 or less.
    pub unsafe fn from_bytes_unchecked_mut(bytes: &mut [u8]) -> &mut Self {
        // SAFETY: 'Label' is 'repr(transparent)' to '[u8]'.
        unsafe { core::mem::transmute(bytes) }
    }
}

//--- Parsing from DNS messages

impl<'a> ParseMessageBytes<'a> for &'a Label {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        Self::parse_bytes(&contents[start..])
    }
}

impl<'a> SplitMessageBytes<'a> for &'a Label {
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        Self::split_bytes(&contents[start..])
            .map(|(this, rest)| (this, contents.len() - start - rest.len()))
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for Label {
    fn build_into_message(&self, mut builder: Builder<'_>) -> BuildResult {
        builder.append_with(self.len() + 1, |buf| {
            buf[0] = self.len() as u8;
            buf[1..].copy_from_slice(self.as_bytes());
        })?;
        Ok(builder.commit())
    }
}

//--- Parsing from bytes

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
        match Self::split_bytes(bytes) {
            Ok((this, &[])) => Ok(this),
            _ => Err(ParseError),
        }
    }
}

//--- Building into byte sequences

impl BuildBytes for Label {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        let (size, data) = bytes.split_first_mut().ok_or(TruncationError)?;
        let rest = self.as_bytes().build_bytes(data)?;
        *size = self.len() as u8;
        Ok(rest)
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

//----------- LabelBuf -------------------------------------------------------

/// A 64-byte buffer holding a [`Label`].
#[derive(Clone)]
#[repr(C)] // make layout compatible with '[u8; 64]'
pub struct LabelBuf {
    /// The size of the label, in bytes.
    ///
    /// This value is guaranteed to be in the range '0..64'.
    size: u8,

    /// The underlying label data.
    data: [u8; 63],
}

//--- Construction

impl LabelBuf {
    /// Copy a [`Label`] into a buffer.
    pub fn copy_from(label: &Label) -> Self {
        let size = label.len() as u8;
        let mut data = [0u8; 63];
        data[..size as usize].copy_from_slice(label.as_bytes());
        Self { size, data }
    }
}

impl UnsizedCopyFrom for LabelBuf {
    type Source = Label;

    fn unsized_copy_from(value: &Self::Source) -> Self {
        Self::copy_from(value)
    }
}

//--- Parsing from strings

impl FromStr for LabelBuf {
    type Err = LabelParseError;

    /// Parse a label from a string.
    ///
    /// This is intended for easily constructing hard-coded labels.  The input
    /// is not expected to be in the zonefile format; it should simply contain
    /// 1 to 63 characters, each being a plain ASCII alphanumeric or a hyphen.
    /// To construct a label containing bytes outside this range, use
    /// [`Label::from_bytes_unchecked()`].  To construct a root label, use
    /// [`Label::ROOT`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "*" {
            Ok(Self::copy_from(Label::WILDCARD))
        } else if !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            Err(LabelParseError::InvalidChar)
        } else if s.is_empty() {
            Err(LabelParseError::Empty)
        } else if s.len() > 63 {
            Err(LabelParseError::Overlong)
        } else {
            let bytes = s.as_bytes();
            // SAFETY: 'bytes' is 63 bytes in size or smaller.
            let label = unsafe { Label::from_bytes_unchecked(bytes) };
            Ok(Self::copy_from(label))
        }
    }
}

//--- Parsing from DNS messages

impl ParseMessageBytes<'_> for LabelBuf {
    fn parse_message_bytes(
        contents: &'_ [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        Self::parse_bytes(&contents[start..])
    }
}

impl SplitMessageBytes<'_> for LabelBuf {
    fn split_message_bytes(
        contents: &'_ [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        Self::split_bytes(&contents[start..])
            .map(|(this, rest)| (this, contents.len() - start - rest.len()))
    }
}

//--- Building into DNS messages

impl BuildIntoMessage for LabelBuf {
    fn build_into_message(&self, builder: Builder<'_>) -> BuildResult {
        (**self).build_into_message(builder)
    }
}

//--- Parsing from byte sequences

impl ParseBytes<'_> for LabelBuf {
    fn parse_bytes(bytes: &[u8]) -> Result<Self, ParseError> {
        <&Label>::parse_bytes(bytes).map(Self::copy_from)
    }
}

impl SplitBytes<'_> for LabelBuf {
    fn split_bytes(bytes: &'_ [u8]) -> Result<(Self, &'_ [u8]), ParseError> {
        <&Label>::split_bytes(bytes)
            .map(|(label, rest)| (Self::copy_from(label), rest))
    }
}

//--- Building into byte sequences

impl BuildBytes for LabelBuf {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        (**self).build_bytes(bytes)
    }
}

//--- Access to the underlying 'Label'

impl Deref for LabelBuf {
    type Target = Label;

    fn deref(&self) -> &Self::Target {
        let label = &self.data[..self.size as usize];
        // SAFETY: A 'LabelBuf' always contains a valid 'Label'.
        unsafe { Label::from_bytes_unchecked(label) }
    }
}

impl DerefMut for LabelBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let label = &mut self.data[..self.size as usize];
        // SAFETY: A 'LabelBuf' always contains a valid 'Label'.
        unsafe { Label::from_bytes_unchecked_mut(label) }
    }
}

impl Borrow<Label> for LabelBuf {
    fn borrow(&self) -> &Label {
        self
    }
}

impl BorrowMut<Label> for LabelBuf {
    fn borrow_mut(&mut self) -> &mut Label {
        self
    }
}

impl AsRef<Label> for LabelBuf {
    fn as_ref(&self) -> &Label {
        self
    }
}

impl AsMut<Label> for LabelBuf {
    fn as_mut(&mut self) -> &mut Label {
        self
    }
}

//--- Forwarding equality, comparison, and hashing

impl PartialEq for LabelBuf {
    fn eq(&self, that: &Self) -> bool {
        **self == **that
    }
}

impl Eq for LabelBuf {}

impl PartialOrd for LabelBuf {
    fn partial_cmp(&self, that: &Self) -> Option<Ordering> {
        Some(self.cmp(that))
    }
}

impl Ord for LabelBuf {
    fn cmp(&self, that: &Self) -> Ordering {
        (**self).cmp(&**that)
    }
}

impl Hash for LabelBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
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
    /// The byte sequence must contain a sequence of valid encoded labels.
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

//------------ LabelParseError -----------------------------------------------

/// An error in parsing a [`Label`] from a string.
///
/// This can be returned by [`LabelBuf::from_str()`].  It is not used when
/// parsing labels from the zonefile format, which uses a different mechanism.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabelParseError {
    /// The label was too large.
    ///
    /// Valid labels are between 1 and 63 bytes, inclusive.
    Overlong,

    /// The label was empty.
    ///
    /// While root labels do exist, they can only be found at the end of a
    /// domain name, and cannot be parsed using [`LabelBuf::from_str()`].
    Empty,

    /// An invalid character was used.
    ///
    /// Only alphanumeric characters and hyphens are allowed in labels.  This
    /// prevents the encoding of perfectly valid labels containing non-ASCII
    /// bytes, but they're fairly rare anyway.
    InvalidChar,
}

#[cfg(feature = "std")]
impl std::error::Error for LabelParseError {}

impl fmt::Display for LabelParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Overlong => "the label was too large",
            Self::Empty => "the label was empty",
            Self::InvalidChar => "the label contained an invalid character",
        })
    }
}
