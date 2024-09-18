//! Building a domain name.
//!
//! This is a private module for tidiness. `NameBuilder` and `BuildError`
//! are re-exported by the parent module.

use core::borrow::{Borrow, BorrowMut};
use core::fmt;

use super::absolute::Name;
use super::label::Label;
use super::relative::RelativeName;
use super::uncertain::UncertainName;
use crate::base::scan::{self, Symbol, Symbols};

//------------ NameBuilder --------------------------------------------------

/// An incremental builder for domain names.
///
/// A [`NameBuilder`] manages a buffer and provides high-level operations to
/// incrementally construct a domain name in that buffer.  The domain name can
/// be built out of individual bytes and/or whole labels.  Once building is
/// complete, an absolute or relative domain name can be extracted.
///
/// This type does not support internationalized domain names directly.  Such
/// domain names must be punycoded before being passed in.
///
/// # Usage
///
/// To construct the builder, call [`new()`] (providing a pre-constructed
/// buffer) or [`default()`] (automatically constructing a buffer).
///
/// [`new()`]: Self::new()
/// [`default()`]: Self::default()
///
/// If the domain name being constructed is already available as a sequence of
/// labels (where each label is a slice of bytes), call [`append_label()`]
/// repeatedly.  If a label is available as a sequence of byte slices, it can be
/// incrementally constructed with [`append_slice()`], terminating with
/// [`end_label()`].
///
/// [`append_label()`]: Self::append_label()
/// [`append_slice()`]: Self::append_slice()
/// [`end_label()`]: Self::end_label()
///
/// Special care must be taken with absolute domain names, which contain a root
/// label (which is of zero length).  The root label must attached with a call
/// to [`append()`], without calling [`end_label()`] after it.
///
/// Once the entire domain name has been constructed, it can be extracted out of
/// the builder.  Depending on the type of domain name required, call
/// [`as_absolute()`], [`as_relative()`], or [`as_uncertain()`].  These are also
/// available as [`From`] implementations.
///
/// [`as_absolute()`]: Self::as_absolute()
/// [`as_relative()`]: Self::as_relative()
/// [`as_uncertain()`]: Self::as_uncertain()
#[derive(Clone)]
pub struct NameBuilder<Buffer: ?Sized> {
    /// The offset to write the next byte to.
    write_offset: u8,

    /// The offset of the length octet of the current label.
    ///
    /// Invariants:
    ///
    /// - `label_offset <= write_offset`
    ///   - if `label_offset < write_offset`:
    ///     - a label is currently being built.
    ///     - `buffer[label_offset] == 0`.
    label_offset: u8,

    /// The buffer to build the name in.
    ///
    /// Invariants:
    ///
    /// - `buffer[.. write_offset]` is initialized.
    buffer: Buffer,
}

/// # Preparing
impl<Buffer> NameBuilder<Buffer> {
    /// Construct a new [`NameBuilder`] using the given buffer.
    ///
    /// Any existing contents in the buffer will be ignored and overwritten.
    #[must_use]
    pub const fn new(buffer: Buffer) -> Self {
        Self {
            write_offset: 0,
            label_offset: 0,
            buffer,
        }
    }
}

impl<Buffer: ?Sized> NameBuilder<Buffer> {
    /// The total size of the built domain name, in bytes.
    pub fn len(&self) -> usize {
        self.write_offset as usize
    }

    /// Whether the builder is empty.
    pub fn is_empty(&self) -> bool {
        self.write_offset == 0
    }
}

/// # Building
impl<Buffer: ?Sized> NameBuilder<Buffer>
where
    Buffer: Borrow<[u8; 256]> + BorrowMut<[u8; 256]>,
{
    /// Append a whole label as a slice of bytes.
    ///
    /// The label is added to the end of the domain name.
    ///
    /// # Errors
    ///
    /// Returns an error if the label is too big, or if appending it to the
    /// domain name would make the domain name too big.
    ///
    /// # Panics
    ///
    /// Panics if a label was already being built.
    pub fn append_label(&mut self, label: &[u8]) -> Result<(), BuildError> {
        assert!(
            self.cur_label().is_none(),
            "cannot append a whole label to a partially-built one"
        );

        // Ensure the new label will fit.
        self.can_fit_label(label.len())?;

        let buffer = self.buffer.borrow_mut();
        buffer[self.write_offset as usize] = label.len() as u8;
        buffer[self.write_offset as usize + 1..][..label.len()]
            .copy_from_slice(label);
        self.write_offset += (1 + label.len()) as u8;
        self.label_offset = self.write_offset;

        Ok(())
    }

    /// Append a slice of bytes to the current label.
    ///
    /// If no label exists, a new label will be created.
    ///
    /// # Errors
    ///
    /// Returns an error if the label being built is too big, or if appending it
    /// to the current domain name would make the domain name too big.
    pub fn append_slice(&mut self, data: &[u8]) -> Result<(), BuildError> {
        // Ensure the label being built will fit.
        self.can_fit_label(
            data.len() + self.cur_label().map_or(0, |l| l.len()),
        )?;

        let buffer = self.buffer.borrow_mut();
        if self.label_offset == self.write_offset {
            // Start a new label.
            buffer[self.write_offset as usize] = 0;
            self.write_offset += 1;
        }

        // Append the new data.
        buffer[self.write_offset as usize..][..data.len()]
            .copy_from_slice(data);
        self.write_offset += data.len() as u8;

        Ok(())
    }

    /// End the current label, if any.
    ///
    /// # Panics
    ///
    /// Panics if this is a root label (i.e. has zero length).
    pub fn end_label(&mut self) {
        if self.label_offset < self.write_offset {
            let len = self.write_offset - self.label_offset - 1;
            assert!(len > 0, "cannot end a root label");
            self.buffer.borrow_mut()[self.label_offset as usize] = len;
        }
    }

    /// Append a relative name to the current label.
    ///
    /// # Errors
    ///
    /// Returns an error if the domain name would become too big.
    ///
    /// # Panics
    ///
    /// Panics if a label was already being built.
    pub fn append_relative_name<Octs>(
        &mut self,
        name: RelativeName<Octs>,
    ) -> Result<(), BuildError>
    where
        Octs: AsRef<[u8]>,
    {
        assert!(
            self.cur_label().is_none(),
            "cannot append a name to a partially-built label"
        );

        if self.write_offset as usize + name.len() > Name::MAX_LEN {
            return Err(BuildError::LongName);
        }

        let buffer = self.buffer.borrow_mut();
        buffer[self.write_offset as usize..][..name.len()]
            .copy_from_slice(name.as_ref());
        self.write_offset += name.len() as u8;
        self.label_offset += name.len() as u8;
        Ok(())
    }

    /// Check that a label can be appended to this builder.
    ///
    /// This ignores any partially-built label already in the builder; its size
    /// should be included in the provided `label_size` parameter.
    const fn can_fit_label(
        &self,
        label_size: usize,
    ) -> Result<(), BuildError> {
        if label_size > Label::MAX_LEN {
            Err(BuildError::LongLabel)
        } else if self.label_offset as usize + 1 + label_size > Name::MAX_LEN
        {
            Err(BuildError::LongName)
        } else {
            Ok(())
        }
    }
}

/// # Scanning
///
/// The presentation format for domain names is somewhat underspecified.  For
/// the purposes of this implementation, it is defined thusly:
///
/// A domain name in the presentation format is a sequence of ASCII characters.
/// It is divided into a sequence of period-separated labels (possibly with one
/// terminating period representing the root label).  Labels can contain almost
/// any printable ASCII character, except `"[].` (unless they are escaped).
///
/// Backslashes represent escape sequences.  A backslash followed by three ASCII
/// digits is interpreted as an octal-encoded byte value (with digits ordered
/// from most to least significant).  If it is followed by a printable ASCII
/// character that is not a decimal digit, it is interpreted as that character
/// verbatim, even if that character is otherwise not allowed in a label.
///
/// A binary label is one that begins and ends with escaped square brackets.  It
/// is defined by a now-obsolete RFC and we choose not to support it.  However,
/// as end-users may still write binary labels, we will detect them and provide
/// an appropriate error message instead of silently doing the wrong thing.
impl<Buffer: ?Sized> NameBuilder<Buffer>
where
    Buffer: Borrow<[u8; 256]> + BorrowMut<[u8; 256]>,
{
    /// Scan and a label from the presentation format and append it.
    ///
    /// Given a label encoded in the presentation format, this function will
    /// parse it, decode escape sequences within it, and append it to the name.
    ///
    /// # Errors
    ///
    /// Returns an error if the label is misformatted or too big, or if
    /// appending it to the domain name would make the domain name too big.
    ///
    /// # Panics
    ///
    /// Panics if a label was already being built.
    pub fn scan_label(&mut self, label: &str) -> Result<(), ScanError> {
        assert!(
            self.cur_label().is_none(),
            "cannot append a whole label to a partially-built one"
        );

        // TODO: Rewrite to process the entire label in one go.
        Symbols::with(label.chars(), |symbols| {
            for symbol in symbols {
                // Ensure it is not one of the disallowed characters.
                if matches!(
                    symbol,
                    Symbol::Char(
                        '"' | '[' | ']' | '.' | ' ' | '\t' | '\r' | '\n'
                    ) | Symbol::SimpleEscape(b' ' | b'\t' | b'\r' | b'\n')
                ) {
                    return Err(ScanError::DisallowedChar);
                } else if self.cur_label().is_none()
                    && matches!(symbol, Symbol::SimpleEscape(b'['))
                {
                    return Err(ScanError::BinaryLabel);
                }

                self.append_slice(&[symbol.into_octet()?])?;
            }

            if !label.is_empty() {
                self.end_label();
            }

            Ok(())
        })
    }

    /// Scan a whole domain name from the presentation format and append it.
    ///
    /// Given a domain name encoded in the presentation format, this function
    /// will parse it, decode escape sequences within it, and append it.
    ///
    /// # Errors
    ///
    /// Returns an error if the label is misformatted or too big, or if
    /// appending it to the domain name would make the domain name too big.
    ///
    /// # Panics
    ///
    /// Panics if a label was already being built.
    pub fn scan_name(&mut self, name: &str) -> Result<(), ScanError> {
        assert!(
            self.cur_label().is_none(),
            "cannot append a whole name to a partially-built label"
        );

        // TODO: Rewrite to process the entire name in one go.
        Symbols::with(name.chars(), |symbols| {
            for symbol in symbols {
                // Ensure it is not one of the disallowed characters.
                if matches!(
                    symbol,
                    Symbol::Char(
                        '"' | '[' | ']' | '.' | ' ' | '\t' | '\r' | '\n'
                    ) | Symbol::SimpleEscape(b' ' | b'\t' | b'\r' | b'\n')
                ) {
                    return Err(ScanError::DisallowedChar);
                } else if matches!(symbol, Symbol::Char('.')) {
                    if self.cur_label().is_none() {
                        return Err(ScanError::EmptyLabel);
                    }
                    self.end_label();
                } else {
                    self.append_slice(&[symbol.into_octet()?])?;
                }
            }

            // End the last label, or create the root label.
            if self.cur_label().is_some() {
                self.end_label();
            } else {
                self.append_slice(&[])?;
            }

            Ok(())
        })
    }
}

/// # Inspecting
impl<Buffer: ?Sized> NameBuilder<Buffer>
where
    Buffer: Borrow<[u8; 256]>,
{
    /// The domain name built thus far.
    ///
    /// This does not include any partially-built label.
    pub fn cur_slice(&self) -> &[u8] {
        &self.buffer.borrow()[..self.label_offset as usize]
    }

    /// The current label being built, if any.
    ///
    /// This does not include the length octet for the label.
    pub fn cur_label(&self) -> Option<&[u8]> {
        if self.label_offset < self.write_offset {
            let label = self.label_offset as usize;
            let write = self.write_offset as usize;
            Some(&self.buffer.borrow()[label + 1..write])
        } else {
            None
        }
    }
}

/// # Extracting
impl<Buffer: ?Sized> NameBuilder<Buffer>
where
    Buffer: Borrow<[u8; 256]>,
{
    /// Extract an absolute domain name from the builder.
    ///
    /// If the name does not end with the root label (which has length zero),
    /// [`None`] is returned.
    ///
    /// # Errors
    ///
    /// Fails if the octet sequence type underlying the [`Name`] cannot
    /// allocate enough space to store the domain name.
    ///
    /// # Panics
    ///
    /// Panics if a non-empty label was in the process of being built.
    pub fn as_absolute<'a, Octs>(
        &'a self,
    ) -> Result<Option<Name<Octs>>, Octs::Error>
    where
        Octs: TryFrom<&'a [u8]>,
    {
        assert!(
            !self.cur_label().is_some_and(|l| !l.is_empty()),
            "cannot extract a domain name while a label is being built"
        );

        if self.cur_label().is_some() {
            let buffer = &self.buffer.borrow()[..self.write_offset as usize];
            let octseq = Octs::try_from(buffer)?;
            Ok(Some(unsafe {
                // SAFETY: `buffer` contains a valid name that was built through
                // `NameBuilder`.  A single root label is present, at the end.
                Name::from_octets_unchecked(octseq)
            }))
        } else {
            Ok(None)
        }
    }

    /// Extract a relative domain name from the builder.
    ///
    /// If the name ends with the root label (which has length zero), [`None`]
    /// is returned.
    ///
    /// # Errors
    ///
    /// Fails if the octet sequence type underlying the [`RelativeName`] cannot
    /// allocate enough space to store the domain name.
    ///
    /// # Panics
    ///
    /// Panics if a label was in the process of being built.
    pub fn as_relative<'a, Octs>(
        &'a self,
    ) -> Result<Option<RelativeName<Octs>>, Octs::Error>
    where
        Octs: TryFrom<&'a [u8]>,
    {
        assert!(
            !self.cur_label().is_some_and(|l| !l.is_empty()),
            "cannot extract a domain name while a label is being built"
        );

        if self.cur_label().is_none() {
            let buffer = &self.buffer.borrow()[..self.write_offset as usize];
            let octseq = Octs::try_from(buffer)?;
            Ok(Some(unsafe {
                // SAFETY: `buffer` contains a valid name that was built through
                // `NameBuilder`.  No root labels are present.
                // TODO: Worry about a 255-byte relative name?
                RelativeName::from_octets_unchecked(octseq)
            }))
        } else {
            Ok(None)
        }
    }

    /// Extract an absolute or relative domain name from the builder.
    ///
    /// # Errors
    ///
    /// Fails if the octet sequence type underlying the [`UncertainName`] cannot
    /// allocate enough space to store the domain name.
    ///
    /// # Panics
    ///
    /// Panics if a non-empty label was in the process of being built.
    pub fn as_uncertain<'a, Octs>(
        &'a self,
    ) -> Result<UncertainName<Octs>, Octs::Error>
    where
        Octs: TryFrom<&'a [u8]>,
    {
        assert!(
            self.write_offset <= self.label_offset + 1,
            "cannot extract a domain name while a label is being built"
        );

        let buffer = &self.buffer.borrow()[..self.write_offset as usize];
        let octseq = Octs::try_from(buffer)?;
        if self.write_offset == self.label_offset {
            Ok(unsafe {
                // SAFETY: `buffer` contains a valid name that was built through
                // `NameBuilder`.  A single root label is present, at the end.
                Name::from_octets_unchecked(octseq).into()
            })
        } else {
            Ok(unsafe {
                // SAFETY: `buffer` contains a valid name that was built through
                // `NameBuilder`.  No root labels are present.
                // TODO: Worry about a 255-byte relative name?
                RelativeName::from_octets_unchecked(octseq).into()
            })
        }
    }
}

impl<Buffer: Default> Default for NameBuilder<Buffer> {
    fn default() -> Self {
        Self::new(Buffer::default())
    }
}

//------------ BuildError ----------------------------------------------------

/// An error in building a domain name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// The backing buffer is too short to store the data.
    ShortBuf,

    /// The label being built would exceed the 63-byte limit.
    LongLabel,

    /// The name being built would exceed the 255-byte limit.
    LongName,
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Self::ShortBuf => "the backing buffer was too short",
            Self::LongLabel => "domain name label longer than 63 bytes",
            Self::LongName => "domain name longer than 255 bytes",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BuildError {}

//------------ ScanError -----------------------------------------------------

/// An error in scanning a domain name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScanError {
    /// An invalid escape sequence was encountered.
    InvalidEscape,

    /// A disallowed character was encountered.
    DisallowedChar,

    /// A binary label (which is unsupported) was encountered.
    BinaryLabel,

    /// An empty (non-root) label was encountered.
    EmptyLabel,

    /// The backing buffer is too short to store the data.
    ShortBuf,

    /// The label being built would exceed the 63-byte limit.
    LongLabel,

    /// The name being built would exceed the 255-byte limit.
    LongName,
}

impl From<BuildError> for ScanError {
    fn from(value: BuildError) -> Self {
        match value {
            BuildError::ShortBuf => Self::ShortBuf,
            BuildError::LongLabel => Self::LongLabel,
            BuildError::LongName => Self::LongName,
        }
    }
}

impl From<scan::SymbolCharsError> for ScanError {
    fn from(_value: scan::SymbolCharsError) -> Self {
        Self::InvalidEscape
    }
}

impl From<scan::BadSymbol> for ScanError {
    fn from(_value: scan::BadSymbol) -> Self {
        // TODO: If we could inspect BadSymbolEnum, we could be more specific.
        Self::DisallowedChar
    }
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            Self::InvalidEscape => "invalid escape sequence found",
            Self::DisallowedChar => "disallowed character found",
            Self::BinaryLabel => "binary labels are unsupported",
            Self::EmptyLabel => "empty domain name label",
            Self::ShortBuf => "the backing buffer was too short",
            Self::LongLabel => "domain name label longer than 63 bytes",
            Self::LongName => "domain name longer than 255 bytes",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ScanError {}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(feature = "std")]
mod test {
    use super::*;

    #[test]
    fn compose() {
        let mut builder = NameBuilder::new([0u8; 256]);
        builder.append_slice(b"w").unwrap();
        builder.append_slice(b"ww").unwrap();
        builder.end_label();
        builder.append_slice(b"exa").unwrap();
        builder.append_slice(b"m").unwrap();
        builder.append_slice(b"p").unwrap();
        builder.append_slice(b"le").unwrap();
        builder.end_label();
        builder.append_slice(b"com").unwrap();
        builder.end_label();
        assert_eq!(builder.cur_slice(), b"\x03www\x07example\x03com");
    }

    #[test]
    fn build_by_label() {
        let mut builder = NameBuilder::new([0u8; 256]);
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_label(b"com").unwrap();
        assert_eq!(builder.cur_slice(), b"\x03www\x07example\x03com");
    }

    #[test]
    fn build_mixed() {
        let mut builder = NameBuilder::new([0u8; 256]);
        builder.append_slice(b"w").unwrap();
        builder.append_slice(b"ww").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        assert_eq!(builder.cur_slice(), b"\x03www\x07example\x03com");
    }

    #[test]
    fn name_limit() {
        let mut builder = NameBuilder::new([0u8; 256]);
        for _ in 0..25 {
            // 9 bytes label is 10 bytes in total
            builder.append_label(b"123456789").unwrap();
        }

        assert_eq!(builder.append_label(b"12345"), Err(BuildError::LongName));
        assert_eq!(builder.clone().append_label(b"1234"), Ok(()));

        assert_eq!(builder.append_slice(b"12345"), Err(BuildError::LongName));
        assert_eq!(builder.clone().append_slice(b"1234"), Ok(()));

        assert_eq!(builder.append_slice(b"12"), Ok(()));
        assert_eq!(builder.append_slice(b"3"), Ok(()));
        assert_eq!(builder.append_slice(b"4"), Err(BuildError::LongName));
    }

    #[test]
    fn label_limit() {
        let mut builder = NameBuilder::new([0u8; 256]);
        builder.append_label(&[0u8; 63][..]).unwrap();
        assert_eq!(
            builder.append_label(&[0u8; 64][..]),
            Err(BuildError::LongLabel)
        );
        assert_eq!(
            builder.append_label(&[0u8; 164][..]),
            Err(BuildError::LongLabel)
        );

        builder.append_slice(&[0u8; 60][..]).unwrap();
        builder.clone().append_label(b"123").unwrap();
        assert_eq!(builder.append_slice(b"1234"), Err(BuildError::LongLabel));
        builder.append_slice(b"12").unwrap();
        builder.append_slice(b"3").unwrap();
        assert_eq!(builder.append_slice(b"4"), Err(BuildError::LongLabel));
    }

    #[test]
    fn finish() {
        let mut builder = NameBuilder::new([0u8; 256]);
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        assert_eq!(builder.cur_slice(), b"\x03www\x07example\x03com");
    }

    #[test]
    fn as_absolute() {
        let mut builder = NameBuilder::new([0u8; 256]);
        builder.append_label(b"www").unwrap();
        builder.append_label(b"example").unwrap();
        builder.append_slice(b"com").unwrap();
        let name: Option<Name<&[u8]>> = builder.as_absolute().unwrap();
        assert_eq!(
            name.as_ref().map(Name::as_slice),
            Some(&b"\x03www\x07example\x03com\x00"[..])
        );
    }
}
