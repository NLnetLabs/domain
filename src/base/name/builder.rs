//! Building a domain name.
//!
//! This is a private module for tidiness. `NameBuilder` and `PushError`
//! are re-exported by the parent module.

use super::super::scan::{BadSymbol, Symbol, SymbolCharsError, Symbols};
use super::absolute::Name;
use super::relative::{RelativeName, RelativeNameError};
use super::traits::{ToName, ToRelativeName};
use super::Label;
#[cfg(feature = "bytes")]
use bytes::BytesMut;
use core::fmt;
use octseq::builder::{EmptyBuilder, FreezeBuilder, OctetsBuilder, ShortBuf};
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ NameBuilder --------------------------------------------------

/// Builds a domain name step by step by appending data.
///
/// The domain name builder is the most fundamental way to construct a new
/// domain name. It wraps an octets builder that assembles the name step by
/// step.
///
/// The methods [`push`][Self::push] and [`append_slice`][Self::append_slice]
/// to add the octets of a label to end of the builder. Once a label is
/// complete, [`end_label`][Self::end_label] finishes the current label and
/// starts a new one.
///
/// The method [`append_label`][Self::append_label] combines this process
/// and appends the given octets as a label.
///
/// The name builder currently is not aware of internationalized domain
/// names. The octets passed to it are used as is and are not converted.
#[derive(Clone)]
pub struct NameBuilder<Builder> {
    /// The buffer to build the name in.
    builder: Builder,

    /// The position in `octets` where the current label started.
    ///
    /// If this is `None` we currently do not have a label.
    head: Option<usize>,
}

impl<Builder> NameBuilder<Builder> {
    /// Creates a new domain name builder from an octets builder.
    ///
    /// Whatever is in the buffer already is considered to be a relative
    /// domain name. Since that may not be the case, this function is
    /// unsafe.
    pub(super) unsafe fn from_builder_unchecked(builder: Builder) -> Self {
        NameBuilder {
            builder,
            head: None,
        }
    }

    /// Creates a new, empty name builder.
    #[must_use]
    pub fn new() -> Self
    where
        Builder: EmptyBuilder,
    {
        unsafe { NameBuilder::from_builder_unchecked(Builder::empty()) }
    }

    /// Creates a new, empty builder with a given capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self
    where
        Builder: EmptyBuilder,
    {
        unsafe {
            NameBuilder::from_builder_unchecked(Builder::with_capacity(
                capacity,
            ))
        }
    }

    /// Creates a new domain name builder atop an existing octets builder.
    ///
    /// The function checks that whatever is in the builder already
    /// consititutes a correctly encoded relative domain name.
    pub fn from_builder(builder: Builder) -> Result<Self, RelativeNameError>
    where
        Builder: OctetsBuilder + AsRef<[u8]>,
    {
        RelativeName::check_slice(builder.as_ref())?;
        Ok(unsafe { NameBuilder::from_builder_unchecked(builder) })
    }
}

#[cfg(feature = "std")]
impl NameBuilder<Vec<u8>> {
    /// Creates an empty domain name builder atop a `Vec<u8>`.
    #[must_use]
    pub fn new_vec() -> Self {
        Self::new()
    }

    /// Creates an empty builder atop a `Vec<u8>` with given capacity.
    ///
    /// Names are limited to a length of 255 octets, but you can provide any
    /// capacity you like here.
    #[must_use]
    pub fn vec_with_capacity(capacity: usize) -> Self {
        Self::with_capacity(capacity)
    }
}

#[cfg(feature = "bytes")]
impl NameBuilder<BytesMut> {
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

impl<Builder: AsRef<[u8]>> NameBuilder<Builder> {
    /// Returns the already assembled domain name as an octets slice.
    pub fn as_slice(&self) -> &[u8] {
        self.builder.as_ref()
    }

    /// Returns the length of the already assembled domain name.
    pub fn len(&self) -> usize {
        self.builder.as_ref().len()
    }

    /// Returns whether the name is still empty.
    pub fn is_empty(&self) -> bool {
        self.builder.as_ref().is_empty()
    }
}

impl<Builder> NameBuilder<Builder>
where
    Builder: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>,
{
    /// Returns whether there currently is a label under construction.
    ///
    /// This returns `false` if the name is still empty or if the last thing
    /// that happend was a call to [`end_label`].
    ///
    /// [`end_label`]: NameBuilder::end_label
    pub fn in_label(&self) -> bool {
        self.head.is_some()
    }

    /// Attempts to append a slice to the underlying builder.
    ///
    /// This method doesn’t perform any checks but only does the necessary
    /// error conversion.
    fn _append_slice(&mut self, slice: &[u8]) -> Result<(), PushError> {
        self.builder
            .append_slice(slice)
            .map_err(|_| PushError::ShortBuf)
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
            if len - head > Label::MAX_LEN {
                return Err(PushError::LongLabel);
            }
            self._append_slice(&[ch])?;
        } else {
            self.head = Some(len);
            self._append_slice(&[0, ch])?;
        }
        Ok(())
    }

    /// Pushes a symbol to the end of the domain name.
    ///
    /// The symbol is iterpreted as part of the presentation format of a
    /// domain name, i.e., an unescaped dot is considered a label separator.
    pub fn push_symbol(&mut self, sym: Symbol) -> Result<(), FromStrError> {
        if matches!(sym, Symbol::Char('.')) {
            if !self.in_label() {
                return Err(PresentationErrorEnum::EmptyLabel.into());
            }
            self.end_label();
            Ok(())
        } else if matches!(sym, Symbol::SimpleEscape(b'['))
            && !self.in_label()
        {
            Err(LabelFromStrErrorEnum::BinaryLabel.into())
        } else {
            self.push(sym.into_octet()?).map_err(Into::into)
        }
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
            if slice.len() > Label::MAX_LEN - (self.len() - head) {
                return Err(PushError::LongLabel);
            }
        } else {
            if slice.len() > Label::MAX_LEN {
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

    /// Appends a label with the decimal representation of `u8`.
    ///
    /// If there currently is a label under construction, it will be ended
    /// before appending `label`.
    ///
    /// Returns an error if appending would result in a name longer than 254
    /// bytes.
    pub fn append_dec_u8_label(
        &mut self,
        value: u8,
    ) -> Result<(), PushError> {
        self.end_label();
        let hecto = value / 100;
        if hecto > 0 {
            self.push(hecto + b'0')?;
        }
        let deka = (value / 10) % 10;
        if hecto > 0 || deka > 0 {
            self.push(deka + b'0')?;
        }
        self.push(value % 10 + b'0')?;
        self.end_label();
        Ok(())
    }

    /// Appends a label with the hex digit.
    ///
    /// If there currently is a label under construction, it will be ended
    /// before appending `label`.
    ///
    /// Returns an error if appending would result in a name longer than 254
    /// bytes.
    pub fn append_hex_digit_label(
        &mut self,
        nibble: u8,
    ) -> Result<(), PushError> {
        fn hex_digit(nibble: u8) -> u8 {
            match nibble & 0x0F {
                0 => b'0',
                1 => b'1',
                2 => b'2',
                3 => b'3',
                4 => b'4',
                5 => b'5',
                6 => b'6',
                7 => b'7',
                8 => b'8',
                9 => b'9',
                10 => b'A',
                11 => b'B',
                12 => b'C',
                13 => b'D',
                14 => b'E',
                15 => b'F',
                _ => unreachable!(),
            }
        }

        self.end_label();
        self.push(hex_digit(nibble))?;
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
    pub fn append_name<N: ToRelativeName>(
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
            label
                .compose(&mut self.builder)
                .map_err(|_| PushNameError::ShortBuf)?;
        }
        Ok(())
    }

    /// Appends a name from a sequence of symbols.
    ///
    /// If there currently is a label under construction, it will be ended
    /// before appending `chars`.
    ///
    /// The character sequence must result in a domain name in representation
    /// format. That is, its labels should be separated by dots,
    /// actual dots, white space, backslashes  and byte values that are not
    /// printable ASCII characters should be escaped.
    ///
    /// The last label will only be ended if the last character was a dot.
    /// Thus, you can determine if that was the case via
    /// [`in_label`][Self::in_label].
    pub fn append_symbols<Sym: IntoIterator<Item = Symbol>>(
        &mut self,
        symbols: Sym,
    ) -> Result<(), FromStrError> {
        symbols
            .into_iter()
            .try_for_each(|symbol| self.push_symbol(symbol))
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
        Symbols::with(chars.into_iter(), |symbols| {
            self.append_symbols(symbols)
        })
    }

    /// Finishes building the name and returns the resulting relative name.
    ///
    /// If there currently is a label being built, ends the label first
    /// before returning the name. I.e., you don’t have to call [`end_label`]
    /// explicitely.
    ///
    /// This method converts the builder into a relative name. If you would
    /// like to turn it into an absolute name, use [`into_name`] which
    /// appends the root label before finishing.
    ///
    /// [`end_label`]: NameBuilder::end_label
    /// [`into_name`]: NameBuilder::into_name
    pub fn finish(mut self) -> RelativeName<Builder::Octets>
    where
        Builder: FreezeBuilder,
    {
        self.end_label();
        unsafe { RelativeName::from_octets_unchecked(self.builder.freeze()) }
    }

    /// Appends the root label to the name and returns it as a [`Name`].
    ///
    /// If there currently is a label under construction, ends the label.
    /// Then adds the empty root label and transforms the name into a
    /// [`Name`].
    pub fn into_name(mut self) -> Result<Name<Builder::Octets>, PushError>
    where
        Builder: FreezeBuilder,
    {
        self.end_label();
        self._append_slice(&[0])?;
        Ok(unsafe { Name::from_octets_unchecked(self.builder.freeze()) })
    }

    /// Appends an origin and returns the resulting [`Name`].
    ///
    /// If there currently is a label under construction, ends the label.
    /// Then adds the `origin` and transforms the name into a
    /// [`Name`].
    //
    //  XXX NEEDS TESTS
    pub fn append_origin<N: ToName>(
        mut self,
        origin: &N,
    ) -> Result<Name<Builder::Octets>, PushNameError>
    where
        Builder: FreezeBuilder,
    {
        self.end_label();
        if self.len() + usize::from(origin.compose_len()) > Name::MAX_LEN {
            return Err(PushNameError::LongName);
        }
        for label in origin.iter_labels() {
            label
                .compose(&mut self.builder)
                .map_err(|_| PushNameError::ShortBuf)?;
        }
        Ok(unsafe { Name::from_octets_unchecked(self.builder.freeze()) })
    }
}

//--- Default

impl<Builder: EmptyBuilder> Default for NameBuilder<Builder> {
    fn default() -> Self {
        Self::new()
    }
}

//--- AsRef

impl<Builder: AsRef<[u8]>> AsRef<[u8]> for NameBuilder<Builder> {
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
    let ch = chars.next().ok_or(SymbolCharsError::short_input())?;
    if ch.is_ascii_digit() {
        let v = ch.to_digit(10).unwrap() * 100
            + chars
                .next()
                .ok_or(SymbolCharsError::short_input())
                .and_then(|c| {
                    c.to_digit(10).ok_or(SymbolCharsError::bad_escape())
                })?
                * 10
            + chars
                .next()
                .ok_or(SymbolCharsError::short_input())
                .and_then(|c| {
                    c.to_digit(10).ok_or(SymbolCharsError::bad_escape())
                })?;
        if v > 255 {
            return Err(SymbolCharsError::bad_escape().into());
        }
        Ok(v as u8)
    } else if ch == '[' {
        // `\[` at the start of a label marks a binary label which we don’t
        // support. Within a label, the sequence is fine.
        if in_label {
            Ok(b'[')
        } else {
            Err(LabelFromStrErrorEnum::BinaryLabel.into())
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
pub struct LabelFromStrError(LabelFromStrErrorEnum);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LabelFromStrErrorEnum {
    SymbolChars(SymbolCharsError),

    BadSymbol(BadSymbol),

    /// A binary label was encountered.
    BinaryLabel,

    /// The label would exceed the limit of 63 bytes.
    LongLabel,
}

//--- From

impl From<LabelFromStrErrorEnum> for LabelFromStrError {
    fn from(inner: LabelFromStrErrorEnum) -> Self {
        Self(inner)
    }
}

impl From<SymbolCharsError> for LabelFromStrError {
    fn from(err: SymbolCharsError) -> Self {
        Self(LabelFromStrErrorEnum::SymbolChars(err))
    }
}

impl From<BadSymbol> for LabelFromStrError {
    fn from(err: BadSymbol) -> Self {
        Self(LabelFromStrErrorEnum::BadSymbol(err))
    }
}

//--- Display and Error

impl fmt::Display for LabelFromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            LabelFromStrErrorEnum::SymbolChars(err) => err.fmt(f),
            LabelFromStrErrorEnum::BadSymbol(err) => err.fmt(f),
            LabelFromStrErrorEnum::BinaryLabel => {
                f.write_str("a binary label was encountered")
            }
            LabelFromStrErrorEnum::LongLabel => {
                f.write_str("label length limit exceeded")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LabelFromStrError {}

//------------ FromStrError --------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FromStrError {
    /// The string content was wrongly formatted.
    Presentation(PresentationError),

    /// The buffer is too short to contain the name.
    ShortBuf,
}

impl FromStrError {
    pub(super) fn empty_label() -> Self {
        Self::Presentation(PresentationErrorEnum::EmptyLabel.into())
    }
}

//--- From

impl From<PushError> for FromStrError {
    fn from(err: PushError) -> FromStrError {
        match err {
            PushError::LongLabel => LabelFromStrErrorEnum::LongLabel.into(),
            PushError::LongName => PresentationErrorEnum::LongName.into(),
            PushError::ShortBuf => FromStrError::ShortBuf,
        }
    }
}

impl From<PushNameError> for FromStrError {
    fn from(err: PushNameError) -> FromStrError {
        match err {
            PushNameError::LongName => PresentationErrorEnum::LongName.into(),
            PushNameError::ShortBuf => FromStrError::ShortBuf,
        }
    }
}

impl<T: Into<PresentationError>> From<T> for FromStrError {
    fn from(err: T) -> Self {
        Self::Presentation(err.into())
    }
}

//--- Display and Error

impl fmt::Display for FromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            FromStrError::Presentation(err) => err.fmt(f),
            FromStrError::ShortBuf => ShortBuf.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromStrError {}

//------------ PresentationError ---------------------------------------------

/// An illegal presentation format was encountered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PresentationError(PresentationErrorEnum);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PresentationErrorEnum {
    BadLabel(LabelFromStrError),

    /// An empty label was encountered.
    EmptyLabel,

    /// The name has more than 255 characters.
    LongName,
}

//--- From

impl From<PresentationErrorEnum> for PresentationError {
    fn from(err: PresentationErrorEnum) -> Self {
        Self(err)
    }
}

impl<T: Into<LabelFromStrError>> From<T> for PresentationError {
    fn from(err: T) -> Self {
        Self(PresentationErrorEnum::BadLabel(err.into()))
    }
}

//--- Display and Error

impl fmt::Display for PresentationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            PresentationErrorEnum::BadLabel(ref err) => err.fmt(f),
            PresentationErrorEnum::EmptyLabel => f.write_str("empty label"),
            PresentationErrorEnum::LongName => {
                f.write_str("long domain name")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PresentationError {}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;

    #[test]
    fn compose() {
        let mut builder = NameBuilder::new_vec();
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
        let mut builder = NameBuilder::new_vec();
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_label(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(), b"\x03www\x07example\x03com");
    }

    #[test]
    fn build_mixed() {
        let mut builder = NameBuilder::new_vec();
        builder.push(b'w').unwrap();
        builder.append_slice(b"ww").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(), b"\x03www\x07example\x03com");
    }

    #[test]
    fn name_limit() {
        let mut builder = NameBuilder::new_vec();
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
        let mut builder = NameBuilder::new_vec();
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
        let mut builder = NameBuilder::new_vec();
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        assert_eq!(builder.finish().as_slice(), b"\x03www\x07example\x03com");
    }

    #[test]
    fn into_name() {
        let mut builder = NameBuilder::new_vec();
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        assert_eq!(
            builder.into_name().unwrap().as_slice(),
            b"\x03www\x07example\x03com\x00"
        );
    }
}
