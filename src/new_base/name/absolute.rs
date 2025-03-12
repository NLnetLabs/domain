//! Absolute domain names.

use core::{
    borrow::{Borrow, BorrowMut},
    fmt,
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
};

use domain_macros::*;

use crate::new_base::{
    parse::{ParseMessageBytes, SplitMessageBytes},
    wire::{BuildBytes, ParseBytes, ParseError, SplitBytes, TruncationError},
};

use super::LabelIter;

//----------- Name -----------------------------------------------------------

/// An absolute domain name.
#[derive(AsBytes, BuildBytes)]
#[repr(transparent)]
pub struct Name([u8]);

//--- Constants

impl Name {
    /// The maximum size of a domain name.
    pub const MAX_SIZE: usize = 255;

    /// The root name.
    pub const ROOT: &'static Self = {
        // SAFETY: A root label is the shortest valid name.
        unsafe { Self::from_bytes_unchecked(&[0u8]) }
    };
}

//--- Construction

impl Name {
    /// Assume a byte string is a valid [`Name`].
    ///
    /// # Safety
    ///
    /// The byte string must represent a valid uncompressed domain name in the
    /// conventional wire format (a sequence of labels terminating with a root
    /// label, totalling 255 bytes or less).
    pub const unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Self {
        // SAFETY: 'Name' is 'repr(transparent)' to '[u8]', so casting a
        // '[u8]' into a 'Name' is sound.
        core::mem::transmute(bytes)
    }

    /// Assume a mutable byte string is a valid [`Name`].
    ///
    /// # Safety
    ///
    /// The byte string must represent a valid uncompressed domain name in the
    /// conventional wire format (a sequence of labels terminating with a root
    /// label, totalling 255 bytes or less).
    pub unsafe fn from_bytes_unchecked_mut(bytes: &mut [u8]) -> &mut Self {
        // SAFETY: 'Name' is 'repr(transparent)' to '[u8]', so casting a
        // '[u8]' into a 'Name' is sound.
        core::mem::transmute(bytes)
    }
}

//--- Inspection

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

    /// A byte representation of the [`Name`].
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The labels in the [`Name`].
    ///
    /// Note that labels appear in reverse order to the _conventional_ format
    /// (it thus starts with the root label).
    pub const fn labels(&self) -> LabelIter<'_> {
        // SAFETY: A 'Name' always contains valid encoded labels.
        unsafe { LabelIter::new_unchecked(self.as_bytes()) }
    }
}

//--- Interaction

impl Name {
    /// Copy this into the given [`Bump`] allocator.
    #[cfg(feature = "bumpalo")]
    #[allow(clippy::mut_from_ref)] // using a memory allocator
    pub fn clone_to_bump<'r>(&self, bump: &'r bumpalo::Bump) -> &'r mut Self {
        let bytes = bump.alloc_slice_copy(self.as_bytes());
        // SAFETY: 'AsBytes' is a transmute, so we can transmute back.
        unsafe { core::mem::transmute::<&mut [u8], &mut Self>(bytes) }
    }
}

//--- Parsing from bytes

impl<'a> ParseBytes<'a> for &'a Name {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        match Self::split_bytes(bytes) {
            Ok((this, &[])) => Ok(this),
            _ => Err(ParseError),
        }
    }
}

impl<'a> SplitBytes<'a> for &'a Name {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        let mut offset = 0usize;
        while offset < 255 {
            match *bytes.get(offset..).ok_or(ParseError)? {
                [0, ..] => {
                    // Found the root, stop.
                    let (name, rest) = bytes.split_at(offset + 1);

                    // SAFETY: 'name' follows the wire format and is 255 bytes
                    // or shorter.
                    let name = unsafe { Name::from_bytes_unchecked(name) };
                    return Ok((name, rest));
                }

                [l, ..] if l < 64 => {
                    // This looks like a regular label.

                    if bytes.len() < offset + 1 + l as usize {
                        // The input doesn't contain the whole label.
                        return Err(ParseError);
                    }

                    offset += 1 + l as usize;
                }

                _ => return Err(ParseError),
            }
        }

        Err(ParseError)
    }
}

//--- Equality

impl PartialEq for Name {
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

impl Eq for Name {}

//--- Hashing

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for byte in self.as_bytes() {
            // NOTE: Label lengths (which are less than 64) aren't affected by
            // 'to_ascii_lowercase', so this method can be applied uniformly.
            state.write_u8(byte.to_ascii_lowercase())
        }
    }
}

//--- Formatting

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        self.labels().try_for_each(|label| {
            if !first {
                f.write_str(".")?;
            } else {
                first = false;
            }

            label.fmt(f)
        })
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({})", self)
    }
}

//----------- NameBuf --------------------------------------------------------

/// A 256-byte buffer containing a [`Name`].
#[derive(Clone)]
#[repr(C)] // make layout compatible with '[u8; 256]'
pub struct NameBuf {
    /// The size of the encoded name.
    size: u8,

    /// The buffer containing the [`Name`].
    buffer: [u8; 255],
}

//--- Construction

impl NameBuf {
    /// Construct an empty, invalid buffer.
    const fn empty() -> Self {
        Self {
            size: 0,
            buffer: [0; 255],
        }
    }

    /// Copy a [`Name`] into a buffer.
    pub fn copy_from(name: &Name) -> Self {
        let mut buffer = [0u8; 255];
        buffer[..name.len()].copy_from_slice(name.as_bytes());
        Self {
            size: name.len() as u8,
            buffer,
        }
    }
}

//--- Parsing from DNS messages

impl<'a> SplitMessageBytes<'a> for NameBuf {
    fn split_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<(Self, usize), ParseError> {
        // NOTE: The input may be controlled by an attacker.  Compression
        // pointers can be arranged to cause loops or to access every byte in
        // the message in random order.  Instead of performing complex loop
        // detection, which would probably perform allocations, we simply
        // disallow a name to point to data _after_ it.  Standard name
        // compressors will never generate such pointers.

        let mut buffer = Self::empty();

        // Perform the first iteration early, to catch the end of the name.
        let bytes = contents.get(start..).ok_or(ParseError)?;
        let (mut pointer, rest) = parse_segment(bytes, &mut buffer)?;
        let orig_end = contents.len() - rest.len();

        // Traverse compression pointers.
        let mut old_start = start;
        while let Some(start) = pointer.map(usize::from) {
            // Ensure the referenced position comes earlier.
            if start >= old_start {
                return Err(ParseError);
            }

            // Keep going, from the referenced position.
            let start = start.checked_sub(12).ok_or(ParseError)?;
            let bytes = contents.get(start..).ok_or(ParseError)?;
            (pointer, _) = parse_segment(bytes, &mut buffer)?;
            old_start = start;
            continue;
        }

        // Stop and return the original end.
        // NOTE: 'buffer' is now well-formed because we only stop when we
        // reach a root label (which has been appended into it).
        Ok((buffer, orig_end))
    }
}

impl<'a> ParseMessageBytes<'a> for NameBuf {
    fn parse_message_bytes(
        contents: &'a [u8],
        start: usize,
    ) -> Result<Self, ParseError> {
        // See 'split_from_message()' for details.  The only differences are
        // in the range of the first iteration, and the check that the first
        // iteration exactly covers the input range.

        let mut buffer = Self::empty();

        // Perform the first iteration early, to catch the end of the name.
        let bytes = contents.get(start..).ok_or(ParseError)?;
        let (mut pointer, rest) = parse_segment(bytes, &mut buffer)?;

        if !rest.is_empty() {
            // The name didn't reach the end of the input range, fail.
            return Err(ParseError);
        }

        // Traverse compression pointers.
        let mut old_start = start;
        while let Some(start) = pointer.map(usize::from) {
            // Ensure the referenced position comes earlier.
            if start >= old_start {
                return Err(ParseError);
            }

            // Keep going, from the referenced position.
            let start = start.checked_sub(12).ok_or(ParseError)?;
            let bytes = contents.get(start..).ok_or(ParseError)?;
            (pointer, _) = parse_segment(bytes, &mut buffer)?;
            old_start = start;
            continue;
        }

        // NOTE: 'buffer' is now well-formed because we only stop when we
        // reach a root label (which has been appended into it).
        Ok(buffer)
    }
}

/// Parse an encoded and potentially-compressed domain name, without
/// following any compression pointer.
fn parse_segment<'a>(
    mut bytes: &'a [u8],
    buffer: &mut NameBuf,
) -> Result<(Option<u16>, &'a [u8]), ParseError> {
    loop {
        match *bytes {
            [0, ref rest @ ..] => {
                // Found the root, stop.
                buffer.append_bytes(&[0u8]);
                return Ok((None, rest));
            }

            [l, ..] if l < 64 => {
                // This looks like a regular label.

                if bytes.len() < 1 + l as usize {
                    // The input doesn't contain the whole label.
                    return Err(ParseError);
                } else if 255 - buffer.size < 2 + l {
                    // The output name would exceed 254 bytes (this isn't
                    // the root label, so it can't fill the 255th byte).
                    return Err(ParseError);
                }

                let (label, rest) = bytes.split_at(1 + l as usize);
                buffer.append_bytes(label);
                bytes = rest;
            }

            [hi, lo, ref rest @ ..] if hi >= 0xC0 => {
                let pointer = u16::from_be_bytes([hi, lo]);

                // NOTE: We don't verify the pointer here, that's left to
                // the caller (since they have to actually use it).
                return Ok((Some(pointer & 0x3FFF), rest));
            }

            _ => return Err(ParseError),
        }
    }
}

//--- Parsing from bytes

impl<'a> SplitBytes<'a> for NameBuf {
    fn split_bytes(bytes: &'a [u8]) -> Result<(Self, &'a [u8]), ParseError> {
        <&Name>::split_bytes(bytes)
            .map(|(name, rest)| (NameBuf::copy_from(name), rest))
    }
}

impl<'a> ParseBytes<'a> for NameBuf {
    fn parse_bytes(bytes: &'a [u8]) -> Result<Self, ParseError> {
        <&Name>::parse_bytes(bytes).map(NameBuf::copy_from)
    }
}

//--- Building into byte strings

impl BuildBytes for NameBuf {
    fn build_bytes<'b>(
        &self,
        bytes: &'b mut [u8],
    ) -> Result<&'b mut [u8], TruncationError> {
        (**self).build_bytes(bytes)
    }
}

//--- Interaction

impl NameBuf {
    /// Append bytes to this buffer.
    ///
    /// This is an internal convenience function used while building buffers.
    fn append_bytes(&mut self, bytes: &[u8]) {
        self.buffer[self.size as usize..][..bytes.len()]
            .copy_from_slice(bytes);
        self.size += bytes.len() as u8;
    }
}

//--- Access to the underlying 'Name'

impl Deref for NameBuf {
    type Target = Name;

    fn deref(&self) -> &Self::Target {
        let name = &self.buffer[..self.size as usize];
        // SAFETY: A 'NameBuf' always contains a valid 'Name'.
        unsafe { Name::from_bytes_unchecked(name) }
    }
}

impl DerefMut for NameBuf {
    fn deref_mut(&mut self) -> &mut Self::Target {
        let name = &mut self.buffer[..self.size as usize];
        // SAFETY: A 'NameBuf' always contains a valid 'Name'.
        unsafe { Name::from_bytes_unchecked_mut(name) }
    }
}

impl Borrow<Name> for NameBuf {
    fn borrow(&self) -> &Name {
        self
    }
}

impl BorrowMut<Name> for NameBuf {
    fn borrow_mut(&mut self) -> &mut Name {
        self
    }
}

impl AsRef<Name> for NameBuf {
    fn as_ref(&self) -> &Name {
        self
    }
}

impl AsMut<Name> for NameBuf {
    fn as_mut(&mut self) -> &mut Name {
        self
    }
}

//--- Forwarding equality, hashing, and formatting

impl PartialEq for NameBuf {
    fn eq(&self, that: &Self) -> bool {
        **self == **that
    }
}

impl Eq for NameBuf {}

impl Hash for NameBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (**self).hash(state)
    }
}

impl fmt::Display for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}

impl fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        (**self).fmt(f)
    }
}
