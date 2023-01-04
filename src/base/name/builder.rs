//! Building a domain name.
//!
//! This is a private module for tidiness. `DnameBuilder` and `PushError`
//! are re-exported by the parent module.

use super::super::scan::Symbol;
use super::dname::Dname;
use super::relative::{RelativeDname, RelativeDnameError};
use super::traits::{ToDname, ToRelativeDname};
#[cfg(feature = "bytes")]
use bytes::BytesMut;
use octseq::builder::{EmptyBuilder, FreezeBuilder, OctetsBuilder, ShortBuf};
use core::{fmt, ops};
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ DnameBuilder --------------------------------------------------

/// Builds a domain name step by step by appending data.
///
/// The domain name builder is the most fundamental way to construct a new
/// domain name. It wraps an octets builder and allows adding single octets,
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

impl<Builder> DnameBuilder<Builder> {
    /// Creates a new domain name builder from an octets builder.
    ///
    /// Whatever is in the buffer already is considered to be a relative
    /// domain name. Since that may not be the case, this function is
    /// unsafe.
    pub(super) unsafe fn from_builder_unchecked(builder: Builder) -> Self {
        DnameBuilder {
            builder,
            head: None,
        }
    }

    /// Creates a new, empty name builder.
    pub fn new() -> Self
    where
        Builder: EmptyBuilder,
    {
        unsafe { DnameBuilder::from_builder_unchecked(Builder::empty()) }
    }

    /// Creates a new, empty builder with a given capacity.
    pub fn with_capacity(capacity: usize) -> Self
    where
        Builder: EmptyBuilder,
    {
        unsafe {
            DnameBuilder::from_builder_unchecked(Builder::with_capacity(
                capacity,
            ))
        }
    }

    /// Creates a new domain name builder atop an existing octets builder.
    ///
    /// The function checks that whatever is in the builder already
    /// consititutes a correctly encoded relative domain name.
    pub fn from_builder(builder: Builder) -> Result<Self, RelativeDnameError>
    where
        Builder: OctetsBuilder + AsRef<[u8]>,
    {
        RelativeDname::check_slice(builder.as_ref())?;
        Ok(unsafe { DnameBuilder::from_builder_unchecked(builder) })
    }
}

#[cfg(feature = "std")]
impl DnameBuilder<Vec<u8>> {
    /// Creates an empty domain name builder atop a `Vec<u8>`.
    pub fn new_vec() -> Self {
        Self::new()
    }

    /// Creates an empty builder atop a `Vec<u8>` with given capacity.
    ///
    /// Names are limited to a length of 255 octets, but you can provide any
    /// capacity you like here.
    pub fn vec_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

#[cfg(feature = "bytes")]
impl DnameBuilder<BytesMut> {
    /// Creates an empty domain name bulider atop a bytes value.
    pub fn new_bytes() -> Self {
        Self::new()
    }

    /// Creates an empty bulider atop a bytes value with given capacity.
    ///
    /// Names are limited to a length of 255 octets, but you can provide any
    /// capacity you like here.
    pub fn bytes_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

impl<Builder: AsRef<[u8]>> DnameBuilder<Builder> {
    /// Returns the length of the already assembled domain name.
    pub fn len(&self) -> usize {
        self.builder.as_ref().len()
    }

    /// Returns whether the name is still empty.
    pub fn is_empty(&self) -> bool {
        self.builder.as_ref().is_empty()
    }
}

impl<Builder> DnameBuilder<Builder>
where Builder: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]> {
    /// Returns whether there currently is a label under construction.
    ///
    /// This returns `false` if the name is still empty or if the last thing
    /// that happend was a call to [`end_label`].
    ///
    /// [`end_label`]: #method.end_label
    pub fn in_label(&self) -> bool {
        self.head.is_some()
    }

    /// Attempts to append a slice to the underlying builder.
    ///
    /// This method doesn’t perform any checks but only does the necessary
    /// error conversion.
    fn _append_slice(&mut self, slice: &[u8]) -> Result<(), PushError> {
        self.builder.append_slice(slice).map_err(|_| PushError::ShortBuf)
    }

    /// Pushes an octet to the end of the domain name.
    ///
    /// Starts a new label if necessary. Returns an error if pushing the
    /// octet would exceed the size limits for labels or domain names.
    pub fn push(&mut self, ch: u8) -> Result<(), PushError> {
        let len = self.len();
        if len >= 254 {
            return Err(PushError::LongName);
        }
        if let Some(head) = self.head {
            if len - head > 63 {
                return Err(PushError::LongLabel);
            }
            self._append_slice(&[ch])?;
        } else {
            self.head = Some(len);
            self._append_slice(&[0, ch])?;
        }
        Ok(())
    }

    /// Appends the content of an octets slice to the end of the domain name.
    ///
    /// Starts a new label if necessary. Returns an error if pushing
    /// would exceed the size limits for labels or domain names.
    ///
    /// If `slice` is empty, does absolutely nothing.
    pub fn append_slice(&mut self, slice: &[u8]) -> Result<(), PushError> {
        if slice.is_empty() {
            return Ok(());
        }
        if let Some(head) = self.head {
            if slice.len() > 63 - (self.len() - head) {
                return Err(PushError::LongLabel);
            }
        } else {
            if slice.len() > 63 {
                return Err(PushError::LongLabel);
            }
            if self.len() + slice.len() > 254 {
                return Err(PushError::LongName);
            }
            self.head = Some(self.len());
            self._append_slice(&[0])?;
        }
        self._append_slice(slice)?;
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

    /// Appends an octets slice as a complete label.
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
            return Err(err);
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
        &mut self,
        name: &N,
    ) -> Result<(), PushNameError> {
        let head = self.head.take();
        self.end_label();
        if self.len() + usize::from(name.compose_len()) > 254 {
            self.head = head;
            return Err(PushNameError::LongName);
        }
        for label in name.iter_labels() {
            label.compose(
                &mut self.builder
            ).map_err(|_| PushNameError::ShortBuf)?;
        }
        Ok(())
    }

    pub fn append_symbols<Sym: IntoIterator<Item = Symbol>>(
        &mut self,
        symbols: Sym,
    ) -> Result<(), FromStrError> {
        for sym in symbols {
            if matches!(sym, Symbol::Char('.')) {
                if !self.in_label() {
                    return Err(FromStrError::EmptyLabel);
                }
                self.end_label();
            } else if matches!(sym, Symbol::SimpleEscape(b'['))
                && !self.in_label()
            {
                return Err(LabelFromStrError::BinaryLabel.into());
            } else if let Ok(ch) = sym.into_octet() {
                self.push(ch)?;
            } else {
                return Err(match sym {
                    Symbol::Char(ch) => FromStrError::IllegalCharacter(ch),
                    _ => FromStrError::IllegalEscape,
                });
            }
        }
        Ok(())
    }

    /// Appends a name from a sequence of characters.
    ///
    /// If there currently is a label under construction, it will be ended
    /// before appending `chars`.
    ///
    /// The character sequence must result in a domain name in representation
    /// format. That is, its labels should be separated by dots,
    /// actual dots, white space and backslashes should be escaped by a
    /// preceeding backslash, and any byte value that is not a printable
    /// ASCII character should be encoded by a backslash followed by its
    /// three digit decimal value.
    ///
    /// The last label will only be ended if the last character was a dot.
    /// Thus, you can determine if that was the case via
    /// [`in_label`][Self::in_label].
    pub fn append_chars<C: IntoIterator<Item = char>>(
        &mut self,
        chars: C,
    ) -> Result<(), FromStrError> {
        // XXX Convert to use append_symbols.

        let mut chars = chars.into_iter();
        while let Some(ch) = chars.next() {
            match ch {
                '.' => {
                    if !self.in_label() {
                        return Err(FromStrError::EmptyLabel);
                    }
                    self.end_label();
                }
                '\\' => {
                    let in_label = self.in_label();
                    self.push(parse_escape(&mut chars, in_label)?)?;
                }
                ' '..='-' | '/'..='[' | ']'..='~' => self.push(ch as u8)?,
                _ => return Err(FromStrError::IllegalCharacter(ch)),
            }
        }
        Ok(())
    }

    /// Finishes building the name and returns the resulting relative name.
    ///
    /// If there currently is a label being built, ends the label first
    /// before returning the name. I.e., you don’t have to call [`end_label`]
    /// explicitely.
    ///
    /// This method converts the builder into a relative name. If you would
    /// like to turn it into an absolute name, use [`into_dname`] which
    /// appends the root label before finishing.
    ///
    /// [`end_label`]: #method.end_label
    /// [`into_dname`]: #method.into_dname
    pub fn finish(mut self) -> RelativeDname<Builder::Octets>
    where Builder: FreezeBuilder {
        self.end_label();
        unsafe { RelativeDname::from_octets_unchecked(self.builder.freeze()) }
    }

    /// Appends the root label to the name and returns it as a `Dname`.
    ///
    /// If there currently is a label under construction, ends the label.
    /// Then adds the empty root label and transforms the name into a
    /// `Dname`.
    pub fn into_dname(mut self) -> Result<Dname<Builder::Octets>, PushError>
    where Builder: FreezeBuilder {
        self.end_label();
        self.append_slice(&[0])?;
        Ok(unsafe { Dname::from_octets_unchecked(self.builder.freeze()) })
    }

    /// Appends an origin and returns the resulting `Dname`.
    /// If there currently is a label under construction, ends the label.
    /// Then adds the `origin` and transforms the name into a
    /// `Dname`.
    //
    //  XXX NEEDS TESTS
    pub fn append_origin<N: ToDname>(
        mut self,
        origin: &N,
    ) -> Result<Dname<Builder::Octets>, PushNameError>
    where Builder: FreezeBuilder {
        self.end_label();
        if self.len() + usize::from(origin.compose_len()) > 255 {
            return Err(PushNameError::LongName);
        }
        for label in origin.iter_labels() {
            label.compose(
                &mut self.builder
            ).map_err(|_| PushNameError::ShortBuf)?;
        }
        Ok(unsafe { Dname::from_octets_unchecked(self.builder.freeze()) })
    }
}

//--- Default

impl<Builder: EmptyBuilder> Default for DnameBuilder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}

//--- Deref and AsRef

impl<Builder: AsRef<[u8]>> ops::Deref for DnameBuilder<Builder> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.builder.as_ref()
    }
}

impl<Builder: AsRef<[u8]>> AsRef<[u8]> for DnameBuilder<Builder> {
    fn as_ref(&self) -> &[u8] {
        self.builder.as_ref()
    }
}

//------------ Santa’s Little Helpers ----------------------------------------

/// Parses the contents of an escape sequence from `chars`.
///
/// The backslash should already have been taken out of `chars`.
pub(super) fn parse_escape<C>(
    chars: &mut C,
    in_label: bool,
) -> Result<u8, LabelFromStrError>
where
    C: Iterator<Item = char>,
{
    let ch = chars.next().ok_or(LabelFromStrError::UnexpectedEnd)?;
    if ('0'..='9').contains(&ch) {
        let v = ch.to_digit(10).unwrap() * 100
            + chars
                .next()
                .ok_or(LabelFromStrError::UnexpectedEnd)
                .and_then(|c| {
                    c.to_digit(10).ok_or(LabelFromStrError::IllegalEscape)
                })?
                * 10
            + chars
                .next()
                .ok_or(LabelFromStrError::UnexpectedEnd)
                .and_then(|c| {
                    c.to_digit(10).ok_or(LabelFromStrError::IllegalEscape)
                })?;
        if v > 255 {
            return Err(LabelFromStrError::IllegalEscape);
        }
        Ok(v as u8)
    } else if ch == '[' {
        // `\[` at the start of a label marks a binary label which we don’t
        // support. Within a label, the sequence is fine.
        if in_label {
            Ok(b'[')
        } else {
            Err(LabelFromStrError::BinaryLabel)
        }
    } else {
        Ok(ch as u8)
    }
}

//============ Error Types ===================================================

//------------ PushError -----------------------------------------------------

/// An error happened while trying to push data to a domain name builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushError {
    /// The current label would exceed the limit of 63 bytes.
    LongLabel,

    /// The name would exceed the limit of 255 bytes.
    LongName,

    /// The buffer is too short to contain the name.
    ShortBuf,
}

//--- From

impl From<ShortBuf> for PushError {
    fn from(_: ShortBuf) -> PushError {
        PushError::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PushError::LongLabel => f.write_str("long label"),
            PushError::LongName => f.write_str("long domain name"),
            PushError::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PushError {}

//------------ PushNameError -------------------------------------------------

/// An error happened while trying to push a name to a domain name builder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PushNameError {
    /// The name would exceed the limit of 255 bytes.
    LongName,

    /// The buffer is too short to contain the name.
    ShortBuf,
}

//--- From

impl From<ShortBuf> for PushNameError {
    fn from(_: ShortBuf) -> Self {
        PushNameError::ShortBuf
    }
}

//--- Display and Error

impl fmt::Display for PushNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            PushNameError::LongName => f.write_str("long domain name"),
            PushNameError::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PushNameError {}

//------------ LabelFromStrError ---------------------------------------------

/// An error occured while reading a label from a string.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LabelFromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    UnexpectedEnd,

    /// A binary label was encountered.
    BinaryLabel,

    /// The label would exceed the limit of 63 bytes.
    LongLabel,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    IllegalCharacter(char),
}

//--- Display and Error

impl fmt::Display for LabelFromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LabelFromStrError::UnexpectedEnd => {
                f.write_str("unexpected end of input")
            }
            LabelFromStrError::BinaryLabel => {
                f.write_str("a binary label was encountered")
            }
            LabelFromStrError::LongLabel => {
                f.write_str("label length limit exceeded")
            }
            LabelFromStrError::IllegalEscape => {
                f.write_str("illegal escape sequence")
            }
            LabelFromStrError::IllegalCharacter(char) => {
                write!(f, "illegal character '{}'", char)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LabelFromStrError {}

//------------ FromStrError --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum FromStrError {
    /// The string ended when there should have been more characters.
    ///
    /// This most likely happens inside escape sequences and quoting.
    UnexpectedEnd,

    /// An empty label was encountered.
    EmptyLabel,

    /// A binary label was encountered.
    BinaryLabel,

    /// A domain name label has more than 63 octets.
    LongLabel,

    /// An illegal escape sequence was encountered.
    ///
    /// Escape sequences are a backslash character followed by either a
    /// three decimal digit sequence encoding a byte value or a single
    /// other printable ASCII character.
    IllegalEscape,

    /// An illegal character was encountered.
    ///
    /// Only printable ASCII characters are allowed.
    IllegalCharacter(char),

    /// The name has more than 255 characters.
    LongName,

    /// The buffer is too short to contain the name.
    ShortBuf,
}

//--- From

impl From<PushError> for FromStrError {
    fn from(err: PushError) -> FromStrError {
        match err {
            PushError::LongLabel => FromStrError::LongLabel,
            PushError::LongName => FromStrError::LongName,
            PushError::ShortBuf => FromStrError::ShortBuf,
        }
    }
}

impl From<PushNameError> for FromStrError {
    fn from(err: PushNameError) -> FromStrError {
        match err {
            PushNameError::LongName => FromStrError::LongName,
            PushNameError::ShortBuf => FromStrError::ShortBuf,
        }
    }
}

impl From<LabelFromStrError> for FromStrError {
    fn from(err: LabelFromStrError) -> FromStrError {
        match err {
            LabelFromStrError::UnexpectedEnd => FromStrError::UnexpectedEnd,
            LabelFromStrError::BinaryLabel => FromStrError::BinaryLabel,
            LabelFromStrError::LongLabel => FromStrError::LongLabel,
            LabelFromStrError::IllegalEscape => FromStrError::IllegalEscape,
            LabelFromStrError::IllegalCharacter(ch) => {
                FromStrError::IllegalCharacter(ch)
            }
        }
    }
}

//--- Display and Error

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FromStrError::UnexpectedEnd => {
                f.write_str("unexpected end of input")
            }
            FromStrError::EmptyLabel => {
                f.write_str("an empty label was encountered")
            }
            FromStrError::BinaryLabel => {
                f.write_str("a binary label was encountered")
            }
            FromStrError::LongLabel => {
                f.write_str("label length limit exceeded")
            }
            FromStrError::IllegalEscape => {
                f.write_str("illegal escape sequence")
            }
            FromStrError::IllegalCharacter(char) => {
                write!(f, "illegal character '{}'", char)
            }
            FromStrError::LongName => f.write_str("long domain name"),
            FromStrError::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromStrError {}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;

    #[test]
    fn compose() {
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
        assert_eq!(builder.finish().as_slice(), b"\x03www\x07example\x03com");
    }

    #[test]
    fn build_by_label() {
        let mut builder = DnameBuilder::new_vec();
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_label(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(), b"\x03www\x07example\x03com");
    }

    #[test]
    fn build_mixed() {
        let mut builder = DnameBuilder::new_vec();
        builder.push(b'w').unwrap();
        builder.append_slice(b"ww").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(), b"\x03www\x07example\x03com");
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
        assert_eq!(
            builder.append_label(&[0u8; 64][..]),
            Err(PushError::LongLabel)
        );
        assert_eq!(
            builder.append_label(&[0u8; 164][..]),
            Err(PushError::LongLabel)
        );

        builder.append_slice(&[0u8; 60][..]).unwrap();
        builder.clone().append_label(b"123").unwrap();
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
        assert_eq!(builder.finish().as_slice(), b"\x03www\x07example\x03com");
    }

    #[test]
    fn into_dname() {
        let mut builder = DnameBuilder::new_vec();
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        assert_eq!(
            builder.into_dname().unwrap().as_slice(),
            b"\x03www\x07example\x03com\x00"
        );
    }
}
