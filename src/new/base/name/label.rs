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

#[cfg(feature = "zonefile")]
use crate::new::zonefile::scanner::{Scan, ScanError, Scanner};

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

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl<'a> Scan<'a> for &'a Label {
    /// Scan a domain name label.
    ///
    /// This parses a domain name label, following the [specification].
    ///
    /// [specification]: crate::new::zonefile#specification
    fn scan(
        scanner: &mut Scanner<'_>,
        alloc: &'a bumpalo::Bump,
        buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        let label = LabelBuf::scan(scanner, alloc, buffer)?;
        let bytes = alloc.alloc_slice_copy(label.as_bytes());
        Ok(unsafe { Label::from_bytes_unchecked(bytes) })
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
    /// three zero-padded decimal digits), and uncommon ASCII characters just
    /// escaped by a backslash.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_wildcard() {
            return f.write_str("*");
        }

        self.contents().iter().try_for_each(|&byte| {
            if byte.is_ascii_alphanumeric() || b"-_".contains(&byte) {
                write!(f, "{}", byte as char)
            } else if byte.is_ascii_graphic() {
                write!(f, "\\{}", byte as char)
            } else {
                write!(f, "\\{:03}", byte)
            }
        })
    }
}

impl fmt::Debug for Label {
    /// Print a label for debugging purposes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Label({self})")
    }
}

//--- Serialize

#[cfg(feature = "serde")]
impl serde::Serialize for Label {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use std::string::ToString;

        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct("Label", &self.to_string())
        } else {
            serializer.serialize_newtype_struct("Label", self.contents())
        }
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

//--- Interaction

impl LabelBuf {
    /// Append some bytes to the [`Label`].
    ///
    /// If the label would grow too large, [`TruncationError`] is returned.
    #[cfg(feature = "zonefile")]
    fn append(&mut self, bytes: &[u8]) -> Result<(), TruncationError> {
        let len = self.data[0] as usize;
        if len + bytes.len() > 63 {
            return Err(TruncationError);
        }

        self.data[1 + len..][..bytes.len()].copy_from_slice(bytes);
        self.data[0] += bytes.len() as u8;
        Ok(())
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

//--- Formatting

impl fmt::Display for LabelBuf {
    /// Print a label.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl fmt::Debug for LabelBuf {
    /// Print a label for debugging purposes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
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

//--- Parsing from strings

impl LabelBuf {
    /// Parse a label from the zonefile format.
    pub fn parse_str(mut s: &[u8]) -> Result<(Self, &[u8]), LabelParseError> {
        if let &[b'*', ref rest @ ..] = s {
            return Ok((Self::copy_from(Label::WILDCARD), rest));
        }

        // The buffer we'll fill into.
        let mut this = Self { data: [0u8; 64] };

        // Parse character by character.
        loop {
            let full = s;
            let &[b, ref rest @ ..] = s else { break };
            s = rest;
            let value = if b.is_ascii_alphanumeric() || b"-_".contains(&b) {
                // A regular label character.
                b
            } else if b == b'\\' {
                // An escape character.
                let &[b, ref rest @ ..] = s else { break };
                s = rest;
                if b.is_ascii_digit() {
                    let digits = rest
                        .get(..3)
                        .ok_or(LabelParseError::PartialEscape)?;
                    let digits = core::str::from_utf8(digits)
                        .map_err(|_| LabelParseError::InvalidEscape)?;
                    digits
                        .parse()
                        .map_err(|_| LabelParseError::InvalidEscape)?
                } else if b.is_ascii_graphic() {
                    b
                } else {
                    return Err(LabelParseError::InvalidEscape);
                }
            } else if b". \n\r\t".contains(&b) {
                // The label has ended.
                s = full;
                break;
            } else {
                return Err(LabelParseError::InvalidChar);
            };

            let off = this.data[0] as usize + 1;
            this.data[0] += 1;
            let ptr =
                this.data.get_mut(off).ok_or(LabelParseError::Overlong)?;
            *ptr = value;
        }

        if this.data[0] == 0 {
            return Err(LabelParseError::Empty);
        }

        Ok((this, s))
    }
}

impl FromStr for LabelBuf {
    type Err = LabelParseError;

    /// Parse a label from a string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Self::parse_str(s.as_bytes()) {
            Ok((this, &[])) => Ok(this),
            Ok(_) => Err(LabelParseError::InvalidChar),
            Err(err) => Err(err),
        }
    }
}

//--- Parsing from the zonefile format

#[cfg(feature = "zonefile")]
impl Scan<'_> for LabelBuf {
    /// Scan a domain name label.
    ///
    /// This parses a domain name label, following the [specification].
    ///
    /// [specification]: crate::new::zonefile#specification
    fn scan(
        scanner: &mut Scanner<'_>,
        _alloc: &'_ bumpalo::Bump,
        _buffer: &mut std::vec::Vec<u8>,
    ) -> Result<Self, ScanError> {
        // Try parsing a wildcard label.
        if let [b'*', b' ' | b'\t' | b'\r' | b'\n' | b'.', ..] | [b'*'] =
            scanner.remaining()
        {
            scanner.consume(1);
            return Ok(Self::copy_from(Label::WILDCARD));
        }

        // The buffer we'll fill into.
        let mut this = Self { data: [0u8; 64] };

        // Loop through non-special chunks and special sequences.
        loop {
            let (chunk, first) = scanner.scan_unquoted_chunk(|&c| {
                !c.is_ascii_alphanumeric() && !b"-_".contains(&c)
            });

            // Copy the non-special chunk into the buffer.
            this.append(chunk).map_err(|_| {
                ScanError::Custom("a domain label exceeded 63 bytes")
            })?;

            // Determine the nature of the special sequence.
            match first {
                Some(b'"') => {
                    return Err(ScanError::Custom(
                        "a domain label was quoted",
                    ))
                }

                Some(b'\\') => {
                    // An escape sequence.
                    scanner.consume(1);
                    this.append(&[scanner.scan_escape()?]).map_err(|_| {
                        ScanError::Custom("a domain label exceeded 63 bytes")
                    })?;
                }

                _ => break,
            }
        }

        // Parse the result as a label.
        if this.data[0] == 0 {
            return Err(ScanError::Incomplete);
        }
        Ok(this)
    }
}

//--- Serialize, Deserialize

#[cfg(feature = "serde")]
impl serde::Serialize for LabelBuf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        (**self).serialize(serializer)
    }
}

#[cfg(feature = "serde")]
impl<'a> serde::Deserialize<'a> for LabelBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        if deserializer.is_human_readable() {
            struct V;

            impl serde::de::Visitor<'_> for V {
                type Value = LabelBuf;

                fn expecting(
                    &self,
                    f: &mut fmt::Formatter<'_>,
                ) -> fmt::Result {
                    f.write_str("a label, in the DNS zonefile format")
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    v.parse().map_err(|err| E::custom(err))
                }
            }

            struct NV;

            impl<'a> serde::de::Visitor<'a> for NV {
                type Value = LabelBuf;

                fn expecting(
                    &self,
                    f: &mut fmt::Formatter<'_>,
                ) -> fmt::Result {
                    f.write_str("a DNS label")
                }

                fn visit_newtype_struct<D>(
                    self,
                    deserializer: D,
                ) -> Result<Self::Value, D::Error>
                where
                    D: serde::Deserializer<'a>,
                {
                    deserializer.deserialize_str(V)
                }
            }

            deserializer.deserialize_newtype_struct("Label", NV)
        } else {
            struct V;

            impl serde::de::Visitor<'_> for V {
                type Value = LabelBuf;

                fn expecting(
                    &self,
                    f: &mut fmt::Formatter<'_>,
                ) -> fmt::Result {
                    f.write_str("a label, in the DNS wire format")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    LabelBuf::parse_bytes(v).map_err(|_| {
                        E::custom(
                            "misformatted label for the DNS wire format",
                        )
                    })
                }
            }

            struct NV;

            impl<'a> serde::de::Visitor<'a> for NV {
                type Value = LabelBuf;

                fn expecting(
                    &self,
                    f: &mut fmt::Formatter<'_>,
                ) -> fmt::Result {
                    f.write_str("a DNS label")
                }

                fn visit_newtype_struct<D>(
                    self,
                    deserializer: D,
                ) -> Result<Self::Value, D::Error>
                where
                    D: serde::Deserializer<'a>,
                {
                    deserializer.deserialize_bytes(V)
                }
            }

            deserializer.deserialize_newtype_struct("Label", NV)
        }
    }
}

#[cfg(feature = "serde")]
impl<'a> serde::Deserialize<'a> for std::boxed::Box<Label> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        LabelBuf::deserialize(deserializer)
            .map(|this| this.unsized_copy_into())
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

    /// A partial escape was used.
    ///
    /// An escape must be `\\DDD`, where `DDD` are 3 ASCII decimal digits
    /// representing an unsigned 8-bit integer; or `\\X`, where `X` is a
    /// graphical, non-digit ASCII character.
    PartialEscape,

    /// An invalid escape was used.
    ///
    /// An escape must be `\\DDD`, where `DDD` are 3 ASCII decimal digits
    /// representing an unsigned 8-bit integer; or `\\X`, where `X` is a
    /// graphical, non-digit ASCII character.
    InvalidEscape,
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
            Self::PartialEscape => "the label contained an incomplete escape",
            Self::InvalidEscape => "the label contained an invalid escape",
        })
    }
}

//============ Unit tests ====================================================

#[cfg(test)]
mod test {
    #[cfg(feature = "zonefile")]
    #[test]
    fn scan() {
        use crate::new::zonefile::scanner::{Scan, ScanError, Scanner};

        use super::LabelBuf;

        let cases = [
            (b"" as &[u8], Err(ScanError::Incomplete)),
            (b"a", Ok(b"a" as &[u8])),
            (b"xn--hello", Ok(b"xn--hello")),
            (b"a\\010b", Ok(b"a\nb")),
            (b"a\\000", Ok(b"a\0")),
            (b"a\\", Err(ScanError::IncompleteEscape)),
            (b"a\\00", Err(ScanError::IncompleteEscape)),
            (b"a\\256", Err(ScanError::InvalidDecimalEscape)),
            (b"\\065", Ok(b"A")),
            (b"a ", Ok(b"a")),
            (
                b"\"hello\"",
                Err(ScanError::Custom("a domain label was quoted")),
            ),
        ];

        let alloc = bumpalo::Bump::new();
        let mut buffer = std::vec::Vec::new();
        for (input, expected) in cases {
            let mut scanner = Scanner::new(input, None);
            let mut label_buf = None;
            let actual = LabelBuf::scan(&mut scanner, &alloc, &mut buffer)
                .map(|label| &label_buf.insert(label).as_bytes()[1..]);
            assert_eq!(actual, expected, "input {:?}", input);
        }
    }
}
