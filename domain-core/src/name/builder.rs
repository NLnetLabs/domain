//! Building a domain name.
//!
//! This is a private module for tidiness. `DnameBuilder` and `PushError`
//! are re-exported by the parent module.

use std::{error, ops};
use bytes::BytesMut;
use derive_more::Display;
use crate::octets::OctetsBuilder;
use super::dname::Dname;
use super::relative::{RelativeDname, RelativeDnameError};
use super::traits::{ToDname, ToRelativeDname};


//------------ DnameBuilder --------------------------------------------------

/// Builds a domain name step by step by appending data.
/// 
/// The domain name builder is the most fundamental way to construct a new
/// domain name. It wraps an octet sequence and allows adding single octets,
/// octet slices, or entire labels.
#[derive(Clone)]
pub struct DnameBuilder<Builder> {
    /// The buffer to build the name in.
    builder: Builder,

    /// The position in `octets` where the current label started.
    ///
    /// If this is `None` we currently do not have a label.
    head: Option<usize>,
}

impl<Builder: OctetsBuilder> DnameBuilder<Builder> {
    /// Creates a new domain name builder from an existing bytes buffer.
    ///
    /// Whatever is in the buffer already is considered to be a relative
    /// domain name. Since that may not be the case, this function is
    /// unsafe.
    pub(super) unsafe fn from_builder_unchecked(builder: Builder) -> Self {
        DnameBuilder { builder, head: None }
    }

    /// Creates a new, empty name builder.
    pub fn new() -> Self {
        unsafe { DnameBuilder::from_builder_unchecked(Builder::empty()) }
    }

    /// Creates a new, empty builder with a given capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        unsafe {
            DnameBuilder::from_builder_unchecked(
                Builder::with_capacity(capacity)
            )
        }
    }

    /// Creates a new domain name builder atop an existing octets builder.
    pub fn from_builder(builder: Builder) -> Result<Self, RelativeDnameError> {
        RelativeDname::check_slice(builder.as_ref())?;
        Ok(unsafe { DnameBuilder::from_builder_unchecked(builder) })
    }
}

impl DnameBuilder<Vec<u8>> {
    pub fn new_vec() -> Self {
        Self::new()
    }

    pub fn vec_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

impl DnameBuilder<BytesMut> {
    pub fn new_bytes() -> Self {
        Self::new()
    }

    pub fn bytes_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

impl<Builder: OctetsBuilder> DnameBuilder<Builder> {

    // This should be a `const fn` once that becomes allowed.
    fn max_capacity() -> usize {
        std::cmp::min(Builder::MAX_CAPACITY - 1, 254)
    }

    // This should be a `const fn` once that becomes allowed.
    fn max_absolute_capacity() -> usize {
        std::cmp::min(Builder::MAX_CAPACITY - 1, 254)
    }

    /// Returns whether there currently is a label under construction.
    ///
    /// This returns `false` if the name is still empty or if the last thing
    /// that happend was a call to [`end_label`].
    ///
    /// [`end_label`]: #method.end_label
    pub fn in_label(&self) -> bool {
        self.head.is_some()
    }

    /// Pushes an octet to the end of the domain name.
    ///
    /// Starts a new label if necessary. Returns an error if pushing the byte
    /// would exceed the size limits for labels or domain names.
    pub fn push(&mut self, ch: u8) -> Result<(), PushError> {
        let len = self.len();
        if len >= Self::max_capacity() {
            return Err(PushError::LongName);
        }
        if let Some(head) = self.head {
            if len - head > 63 {
                return Err(PushError::LongLabel)
            }
            self.builder.append_slice(&[ch]);
        }
        else {
            self.head = Some(len);
            self.builder.append_slice(&[0, ch]);
        }
        Ok(())
    }

    /// Appends a byte slice to the end of the domain name.
    ///
    /// Starts a new label if necessary. Returns an error if pushing
    /// would exceed the size limits for labels or domain names.
    ///
    /// If bytes is empty, does absolutely nothing.
    pub fn append_slice(&mut self, slice: &[u8]) -> Result<(), PushError> {
        if slice.is_empty() {
            return Ok(())
        }
        if let Some(head) = self.head {
            if slice.len() > 63 - (self.len() - head) {
                return Err(PushError::LongLabel)
            }
        }
        else {
            if slice.len() > 63 {
                return Err(PushError::LongLabel)
            }
            if self.len() + slice.len() > Self::max_capacity() {
                return Err(PushError::LongName)
            }
            self.head = Some(self.len());
            self.builder.append_slice(&[0]);
        }
        self.builder.append_slice(slice);
        Ok(())
    }

    /// Ends the current label.
    ///
    /// If there isn’t a current label, does nothing.
    pub fn end_label(&mut self) {
        if let Some(head) = self.head {
            let len = self.len() - head - 1;
            self.builder.as_mut()[head] = len as u8;
            self.head = None;
        }
    }

    /// Appends a byte slice as a complete label.
    ///
    /// If there currently is a label under construction, it will be ended
    /// before appending `label`.
    ///
    /// Returns an error if `label` exceeds the label size limit of 63 bytes
    /// or appending the label would exceed the domain name size limit of
    /// 255 bytes.
    pub fn append_label(&mut self, label: &[u8]) -> Result<(), PushError> {
        let head = self.head;
        self.end_label();
        if let Err(err) = self.append_slice(label) {
            self.head = head;
            return Err(err)
        }
        self.end_label();
        Ok(())
    }

    /// Appends a relative domain name.
    ///
    /// If there currently is a label under construction, it will be ended
    /// before appending `name`.
    ///
    /// Returns an error if appending would result in a name longer than 254
    /// bytes.
    //
    //  XXX NEEDS TESTS
    pub fn append_name<N: ToRelativeDname>(
        &mut self, name: &N
    ) -> Result<(), PushNameError> {
        let head = self.head.take();
        self.end_label();
        if self.len() + name.len() > Self::max_capacity() {
            self.head = head;
            return Err(PushNameError)
        }
        for label in name.iter_labels() {
            label.build(&mut self.builder)
        }
        Ok(())
    }

    /// Appends a name from a sequence of characters.
    ///
    /// If there currently is a label under construction, it will be ended
    /// before appending `chars`.
    ///
    /// The character sequence must result in a domain name in master format
    /// representation. That is, its labels should be separated by dots,
    /// actual dots, white space and backslashes should be escaped by a
    /// preceeding backslash, and any byte value that is not a printable
    /// ASCII character should be encoded by a backslash followed by its
    /// three digit decimal value.
    ///
    /// The last label will only be ended if the last character was a dot.
    /// Thus, you can determine if that was the case via `in_label`.
    pub fn append_chars<C: IntoIterator<Item = char>>(
        &mut self,
        chars: C
    ) -> Result<(), FromStrError> {
        let mut chars = chars.into_iter();
        while let Some(ch) = chars.next() {
            match ch {
                '.' => {
                    if !self.in_label() {
                        return Err(FromStrError::EmptyLabel)
                    }
                    self.end_label();
                }
                '\\' => {
                    let in_label = self.in_label();
                    self.push(parse_escape(&mut chars, in_label)?)?;
                }
                ' ' ..= '-' | '/' ..= '[' | ']' ..= '~' => {
                    self.push(ch as u8)?
                }
                _ => return Err(FromStrError::IllegalCharacter(ch))
            }
        }
        Ok(())
    }

    /// Finishes building the name and returns the resulting domain name.
    /// 
    /// If there currently is a label being built, ends the label first
    /// before returning the name. I.e., you don’t have to call [`end_label`]
    /// explicitely.
    ///
    /// [`end_label`]: #method.end_label
    pub fn finish(
        mut self
    ) -> RelativeDname<Builder::Octets> {
        self.end_label();
        unsafe {
            RelativeDname::from_octets_unchecked(self.builder.finish())
        }
    }

    /// Appends the root label to the name and returns it as a `Dname`.
    ///
    /// If there currently is a label under construction, ends the label.
    /// Then adds the empty root label and transforms the name into a
    /// `Dname`.
    pub fn into_dname(
        mut self
    ) -> Dname<Builder::Octets> {
        self.end_label();
        self.builder.append_slice(&[0]);
        unsafe {
            Dname::from_octets_unchecked(self.builder.finish())
        }
    }

    /// Appends an origin and returns the resulting `Dname`.
    /// If there currently is a label under construction, ends the label.
    /// Then adds the `origin` and transforms the name into a
    /// `Dname`. 
    //
    //  XXX NEEDS TESTS
    pub fn append_origin<N: ToDname>(
        mut self, origin: &N
    ) -> Result<Dname<Builder::Octets>, PushNameError> {
        self.end_label();
        if self.len() + origin.len() > Self::max_absolute_capacity() {
            return Err(PushNameError)
        }
        for label in origin.iter_labels() {
            label.build(&mut self.builder)
        }
        Ok(unsafe {
            Dname::from_octets_unchecked(self.builder.finish())
        })
    }
}


//--- Default

impl<Builder: OctetsBuilder> Default for DnameBuilder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}


//--- Deref and AsRef

impl<Builder: OctetsBuilder> ops::Deref for DnameBuilder<Builder> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.builder.as_ref()
    }
}

impl<Builder: OctetsBuilder> AsRef<[u8]> for DnameBuilder<Builder> {
    fn as_ref(&self) -> &[u8] {
        self.builder.as_ref()
    }
}


//------------ PushError -----------------------------------------------------

/// An error happened while trying to push data to a domain name builder.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum PushError {
    /// The current label would exceed the limit of 63 bytes.
    #[display(fmt="long label")]
    LongLabel,

    /// The name would exceed the limit of 255 bytes.
    #[display(fmt="long domain name")]
    LongName,
}

impl error::Error for PushError { }


//------------ PushNameError -------------------------------------------------

/// An error happened while trying to push a name to a domain name builder.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="long domain name")]
pub struct PushNameError;

impl error::Error for PushNameError { }


//------------ FromStrError --------------------------------------------------

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    #[display(fmt="unexpected end of input")]
    UnexpectedEnd,

    /// An empty label was encountered.
    #[display(fmt="an empty label was encountered")]
    EmptyLabel,

    /// A binary label was encountered.
    #[display(fmt="a binary label was encountered")]
    BinaryLabel,

    /// A domain name label has more than 63 octets.
    #[display(fmt="label length limit exceeded")]
    LongLabel,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    #[display(fmt="illegal escape sequence")]
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    #[display(fmt="illegal character '{}'", _0)]
    IllegalCharacter(char),

    /// The name has more than 255 characters.
    #[display(fmt="long domain name")]
    LongName,
}

impl error::Error for FromStrError { }

impl From<PushError> for FromStrError {
    fn from(err: PushError) -> FromStrError {
        match err {
            PushError::LongLabel => FromStrError::LongLabel,
            PushError::LongName => FromStrError::LongName,
        }
    }
}

impl From<PushNameError> for FromStrError {
    fn from(_: PushNameError) -> FromStrError {
        FromStrError::LongName
    }
}


//------------ Santa’s Little Helpers ----------------------------------------

/// Parses the contents of an escape sequence from `chars`.
///
/// The backslash should already have been taken out of `chars`.
fn parse_escape<C>(chars: &mut C, in_label: bool) -> Result<u8, FromStrError>
                where C: Iterator<Item=char> {
    let ch = chars.next().ok_or(FromStrError::UnexpectedEnd)?;
    if ch >= '0' &&  ch <= '9' {
        let v = ch.to_digit(10).unwrap() * 100
              + chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape))?
                     * 10
              + chars.next().ok_or(FromStrError::UnexpectedEnd)
                     .and_then(|c| c.to_digit(10)
                                    .ok_or(FromStrError::IllegalEscape))?;
        if v > 255 {
            return Err(FromStrError::IllegalEscape)
        }
        Ok(v as u8)
    }
    else if ch == '[' {
        // `\[` at the start of a label marks a binary label which we don’t
        // support. Within a label, the sequence is fine.
        if in_label {
            Ok(b'[')
        }
        else {
            Err(FromStrError::BinaryLabel)
        }
    }
    else { Ok(ch as u8) }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn build() {
        let mut builder = DnameBuilder::new_vec();
        builder.push(b'w').unwrap();
        builder.append_slice(b"ww").unwrap();
        builder.end_label();
        builder.append_slice(b"exa").unwrap();
        builder.push(b'm').unwrap();
        builder.push(b'p').unwrap();
        builder.append_slice(b"le").unwrap();
        builder.end_label();
        builder.append_slice(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(),
                   b"\x03www\x07example\x03com");
    }

    #[test]
    fn build_by_label() {
        let mut builder = DnameBuilder::new_vec();
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_label(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(),
                   b"\x03www\x07example\x03com");
    }

    #[test]
    fn build_mixed() {
        let mut builder = DnameBuilder::new_vec();
        builder.push(b'w').unwrap();
        builder.append_slice(b"ww").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(),
                   b"\x03www\x07example\x03com");
    }

    #[test]
    fn name_limit() {
        let mut builder = DnameBuilder::new_vec();
        for _ in 0..25 {
            // 9 bytes label is 10 bytes in total 
            builder.append_label(b"123456789").unwrap();
        }

        assert_eq!(builder.append_label(b"12345"), Err(PushError::LongName));
        assert_eq!(builder.clone().append_label(b"1234"), Ok(()));

        assert_eq!(builder.append_slice(b"12345"), Err(PushError::LongName));
        assert_eq!(builder.clone().append_slice(b"1234"), Ok(()));

        assert_eq!(builder.append_slice(b"12"), Ok(()));
        assert_eq!(builder.push(b'3'), Ok(()));
        assert_eq!(builder.push(b'4'), Err(PushError::LongName))
    }

    #[test]
    fn label_limit() {
        let mut builder = DnameBuilder::new_vec();
        builder.append_label(&[0u8; 63][..]).unwrap();
        assert_eq!(builder.append_label(&[0u8; 64][..]),
                   Err(PushError::LongLabel));
        assert_eq!(builder.append_label(&[0u8; 164][..]),
                   Err(PushError::LongLabel));

        builder.append_slice(&[0u8; 60][..]).unwrap();
        let _ = builder.clone().append_label(b"123").unwrap();
        assert_eq!(builder.append_slice(b"1234"), Err(PushError::LongLabel));
        builder.append_slice(b"12").unwrap();
        builder.push(b'3').unwrap();
        assert_eq!(builder.push(b'4'), Err(PushError::LongLabel));
    }

    #[test]
    fn finish() {
        let mut builder = DnameBuilder::new_vec();
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(),
                   b"\x03www\x07example\x03com");
    }

    #[test]
    fn into_dname() {
        let mut builder = DnameBuilder::new_vec();
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        assert_eq!(builder.into_dname().as_slice(),
                   b"\x03www\x07example\x03com\x00");
    }
}
