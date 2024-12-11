//! Reversed DNS names.

use core::{
    borrow::Borrow,
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    ops::{Deref, Range},
};

use zerocopy::IntoBytes;
use zerocopy_derive::*;

use crate::new_base::{
    parse::{
        ParseError, ParseFrom, ParseFromMessage, SplitFrom, SplitFromMessage,
    },
    Message,
};

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

//--- Formatting

impl fmt::Debug for RevName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct RevLabels<'a>(&'a RevName);

        impl fmt::Debug for RevLabels<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut first = true;
                self.0.labels().try_for_each(|label| {
                    if !first {
                        f.write_str(".")?;
                    } else {
                        first = false;
                    }

                    label.fmt(f)
                })
            }
        }

        f.debug_tuple("RevName").field(&RevLabels(self)).finish()
    }
}

//----------- RevNameBuf -----------------------------------------------------

/// A 256-byte buffer containing a [`RevName`].
#[derive(Clone, Immutable, Unaligned)]
#[repr(C)] // make layout compatible with '[u8; 256]'
pub struct RevNameBuf {
    /// The position of the root label in the buffer.
    offset: u8,

    /// The buffer containing the [`RevName`].
    buffer: [u8; 255],
}

//--- Construction

impl RevNameBuf {
    /// Construct an empty, invalid buffer.
    fn empty() -> Self {
        Self {
            offset: 0,
            buffer: [0; 255],
        }
    }

    /// Copy a [`RevName`] into a buffer.
    pub fn copy_from(name: &RevName) -> Self {
        let offset = 255 - name.len() as u8;
        let mut buffer = [0u8; 255];
        buffer[offset as usize..].copy_from_slice(name.as_bytes());
        Self { offset, buffer }
    }
}

//--- Parsing from DNS messages

impl<'a> SplitFromMessage<'a> for RevNameBuf {
    fn split_from_message(
        message: &'a Message,
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        // NOTE: The input may be controlled by an attacker.  Compression
        // pointers can be arranged to cause loops or to access every byte in
        // the message in random order.  Instead of performing complex loop
        // detection, which would probably perform allocations, we simply
        // disallow a name to point to data _after_ it.  Standard name
        // compressors will never generate such pointers.

        let message = message.as_bytes();
        let mut buffer = Self::empty();

        // Perform the first iteration early, to catch the end of the name.
        let bytes = message.get(start..).ok_or(ParseError)?;
        let (mut pointer, rest) = parse_segment(bytes, &mut buffer)?;
        let orig_end = message.len() - rest.len();

        // Traverse compression pointers.
        while let Some(start) = pointer.map(usize::from) {
            // Ensure the referenced position comes earlier.
            if start >= start {
                return Err(ParseError);
            }

            // Keep going, from the referenced position.
            let bytes = message.get(start..).ok_or(ParseError)?;
            (pointer, _) = parse_segment(bytes, &mut buffer)?;
            continue;
        }

        // Stop and return the original end.
        // NOTE: 'buffer' is now well-formed because we only stop when we
        // reach a root label (which has been prepended into it).
        Ok((buffer, orig_end))
    }
}

impl<'a> ParseFromMessage<'a> for RevNameBuf {
    fn parse_from_message(
        message: &'a Message,
        range: Range<usize>,
    ) -> Result<Self, ParseError> {
        // See 'split_from_message()' for details.  The only differences are
        // in the range of the first iteration, and the check that the first
        // iteration exactly covers the input range.

        let message = message.as_bytes();
        let mut buffer = Self::empty();

        // Perform the first iteration early, to catch the end of the name.
        let bytes = message.get(range.clone()).ok_or(ParseError)?;
        let (mut pointer, rest) = parse_segment(bytes, &mut buffer)?;

        if !rest.is_empty() {
            // The name didn't reach the end of the input range, fail.
            return Err(ParseError);
        }

        // Traverse compression pointers.
        while let Some(start) = pointer.map(usize::from) {
            // Ensure the referenced position comes earlier.
            if start >= start {
                return Err(ParseError);
            }

            // Keep going, from the referenced position.
            let bytes = message.get(start..).ok_or(ParseError)?;
            (pointer, _) = parse_segment(bytes, &mut buffer)?;
            continue;
        }

        // NOTE: 'buffer' is now well-formed because we only stop when we
        // reach a root label (which has been prepended into it).
        Ok(buffer)
    }
}

/// Parse an encoded and potentially-compressed domain name, without
/// following any compression pointer.
fn parse_segment<'a>(
    mut bytes: &'a [u8],
    buffer: &mut RevNameBuf,
) -> Result<(Option<u16>, &'a [u8]), ParseError> {
    loop {
        let (&length, rest) = bytes.split_first().ok_or(ParseError)?;
        if length == 0 {
            // Found the root, stop.
            buffer.prepend(&[0u8]);
            return Ok((None, rest));
        } else if length < 64 {
            // This looks like a regular label.

            if rest.len() < length as usize {
                // The input doesn't contain the whole label.
                return Err(ParseError);
            } else if buffer.offset < 2 + length {
                // The output name would exceed 254 bytes (this isn't
                // the root label, so it can't fill the 255th byte).
                return Err(ParseError);
            }

            let (label, rest) = bytes.split_at(1 + length as usize);
            buffer.prepend(label);
            bytes = rest;
        } else if length >= 0xC0 {
            // This looks like a compression pointer.

            let (&extra, rest) = rest.split_first().ok_or(ParseError)?;
            let pointer = u16::from_be_bytes([length, extra]);

            // NOTE: We don't verify the pointer here, that's left to
            // the caller (since they have to actually use it).
            return Ok((Some(pointer & 0x3FFF), rest));
        } else {
            // This is an invalid or deprecated label type.
            return Err(ParseError);
        }
    }
}

//--- Parsing from bytes

impl<'a> SplitFrom<'a> for RevNameBuf {
    fn split_from(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let mut buffer = Self::empty();

        let (pointer, rest) = parse_segment(bytes, &mut buffer)?;
        if pointer.is_some() {
            // We can't follow compression pointers, so fail.
            return Err(ParseError);
        }

        // NOTE: 'buffer' is now well-formed because we only stop when we
        // reach a root label (which has been prepended into it).
        Ok((buffer, rest))
    }
}

impl<'a> ParseFrom<'a> for RevNameBuf {
    fn parse_from(bytes: &'a [u8]) -> Result<Self, ParseError> {
        let mut buffer = Self::empty();

        let (pointer, rest) = parse_segment(bytes, &mut buffer)?;
        if pointer.is_some() {
            // We can't follow compression pointers, so fail.
            return Err(ParseError);
        } else if !rest.is_empty() {
            // The name didn't reach the end of the input range, fail.
            return Err(ParseError);
        }

        // NOTE: 'buffer' is now well-formed because we only stop when we
        // reach a root label (which has been prepended into it).
        Ok(buffer)
    }
}

//--- Interaction

impl RevNameBuf {
    /// Prepend bytes to this buffer.
    ///
    /// This is an internal convenience function used while building buffers.
    fn prepend(&mut self, label: &[u8]) {
        self.offset -= label.len() as u8;
        self.buffer[self.offset as usize..][..label.len()]
            .copy_from_slice(label);
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
