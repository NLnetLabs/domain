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

use crate::new::base::build::{BuildInMessage, NameCompressor};
use crate::new::base::parse::{ParseMessageBytes, SplitMessageBytes};
use crate::new::base::wire::{
    AsBytes, BuildBytes, ParseBytes, ParseError, SplitBytes, TruncationError,
};
use crate::utils::dst::{UnsizedCopy, UnsizedCopyFrom};

//----------- Label ----------------------------------------------------------

/// A label in a domain name.
///
/// A label consists of 0 to 63 (inclusive) bytes of arbitrary data, prefixed
/// by its own length (also between 0 and 63).
#[derive(AsBytes, UnsizedCopy)]
#[repr(transparent)]
pub struct Label([u8]);

//--- Associated Constants

impl Label {
    /// The root label.
    pub const ROOT: &'static Self = {
        // SAFETY: This is a correctly encoded label.
        unsafe { Self::from_bytes_unchecked(&[0]) }
    };

    /// The wildcard label.
    pub const WILDCARD: &'static Self = {
        // SAFETY: This is a correctly encoded label.
        unsafe { Self::from_bytes_unchecked(&[1, b'*']) }
    };
}

//--- Construction

impl Label {
    /// Assume a byte slice is a valid label.
    ///
    /// # Safety
    ///
    /// The following conditions must hold for this call to be sound:
    /// - `bytes.len() <= 64`
    /// - `bytes[0] as usize + 1 == bytes.len()`
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Label' is 'repr(transparent)' to '[u8]'.
        unsafe { core::mem::transmute(bytes) }
    }

    /// Assume a mutable byte slice is a valid label.
    ///
    /// # Safety
    ///
    /// The following conditions must hold for this call to be sound:
    /// - `bytes.len() <= 64`
    /// - `bytes[0] as usize + 1 == bytes.len()`
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

impl BuildInMessage for Label {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        _compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        let bytes = &self.0;
        let end = start + bytes.len();
        contents
            .get_mut(start..end)
            .ok_or(TruncationError)?
            .copy_from_slice(bytes);
        Ok(end)
    }
}

//--- Parsing from bytes

impl<'a> SplitBytes<'a> for &'a Label {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let &size = bytes.first().ok_or(ParseError)?;
        if size < 64 && bytes.len() > size as usize {
            let (label, rest) = bytes.split_at(1 + size as usize);
            // SAFETY:
            // - 'label.len() = 1 + size <= 64'
            // - 'label[0] = size + 1 == label.len()'
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
        self.0.build_bytes(bytes)
    }

    fn built_bytes_size(&self) -> usize {
        self.0.len()
    }
}

//--- Inspection

impl Label {
    /// Whether this is the root label.
    pub const fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    /// Whether this is a wildcard label.
    pub const fn is_wildcard(&self) -> bool {
        matches!(self.0, [1, b'*'])
    }

    /// The bytes making up this label.
    ///
    /// This includes the leading length octet.
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The contents of the label.
    ///
    /// This does not include the leading length octet.
    pub fn contents(&self) -> &[u8] {
        &self.0[1..]
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

//--- Cloning

#[cfg(feature = "alloc")]
impl Clone for alloc::boxed::Box<Label> {
    fn clone(&self) -> Self {
        (*self).unsized_copy_into()
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
        self.contents().iter().try_for_each(|&byte| {
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
#[repr(transparent)]
pub struct LabelBuf {
    /// The label bytes.
    data: [u8; 64],
}

//--- Construction

impl LabelBuf {
    /// Copy a [`Label`] into a buffer.
    pub fn copy_from(label: &Label) -> Self {
        let bytes = label.as_bytes();
        let mut data = [0u8; 64];
        data[..bytes.len()].copy_from_slice(bytes);
        Self { data }
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
            let mut data = [0u8; 64];
            data[0] = bytes.len() as u8;
            data[1..1 + bytes.len()].copy_from_slice(bytes);
            Ok(Self { data })
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

impl BuildInMessage for LabelBuf {
    fn build_in_message(
        &self,
        contents: &mut [u8],
        start: usize,
        compressor: &mut NameCompressor,
    ) -> Result<usize, TruncationError> {
        Label::build_in_message(self, contents, start, compressor)
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

    fn built_bytes_size(&self) -> usize {
        (**self).built_bytes_size()
    }
}

//--- Access to the underlying 'Label'

impl Deref for LabelBuf {
    type Target = Label;

    fn deref(&self) -> &Self::Target {
        let size = self.data[0] as usize;
        let label = &self.data[..1 + size];
        // SAFETY: A 'LabelBuf' always contains a valid 'Label'.
        unsafe { Label::from_bytes_unchecked(label) }
    }
}

impl DerefMut for LabelBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let size = self.data[0] as usize;
        let label = &mut self.data[..1 + size];
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

    /// Whether the iterator is empty.
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
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

// TODO(1.81.0): Use 'core::error::Error' instead.
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
