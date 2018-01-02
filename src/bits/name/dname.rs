/// Uncompressed, absolute domain names.
///
/// This is a private module. Its public types are re-exported by the parent.

use std::{cmp, fmt, hash, ops, str};
use std::ascii::AsciiExt;
use bytes::{BufMut, Bytes};
use ::bits::compose::{Compose, Compress, Compressor};
use ::bits::parse::{Parse, ParseAll, Parser, ShortBuf};
use ::master::scan::{CharSource, Scan, Scanner, ScanError, SyntaxError};
use super::error::{FromStrError, LabelTypeError, SplitLabelError};
use super::label::Label;
use super::relative::{RelativeDname, DnameIter};
use super::traits::{ToLabelIter, ToDname, ToRelativeDname};
use super::uncertain::UncertainDname;


//------------ Dname ---------------------------------------------------------

/// An uncompressed, absolute domain name.
///
/// The type wraps a [`Bytes`] value and guarantees that it always contains
/// a correctly encoded, absolute domain name. It derefs to [`Bytes`] and
/// therefore to `[u8]` allowing you direct access to the underlying byte
/// slice. It does overide all applicable methods providing access to parts
/// of the byte slice, though, returning either `Dname` or [`RelativeDname`]s
/// instead.
///
/// You can construct a domain name from a string via the `FromStr` trait or
/// manually via a [`DnameBuilder`]. In addition, you can also parse it from
/// a message. This will, however, require the name to be uncompressed.
///
/// [`Bytes`]: ../../../bytes/struct.Bytes.html
/// [`DnameBuilder`]: struct.DnameBuilder.html
#[derive(Clone)]
pub struct Dname {
    bytes: Bytes
}

/// # Creation and Conversion
///
impl Dname {
    /// Creates a domain name from the underlying bytes without any check.
    ///
    /// Since this will allow to actually construct an incorrectly encoded
    /// domain name value, the function is unsafe.
    pub(super) unsafe fn from_bytes_unchecked(bytes: Bytes) -> Self {
        Dname { bytes }
    }

    /// Creates a domain name representing the root.
    ///
    /// The resulting domain name will consist of the root label only.
    pub fn root() -> Self {
        unsafe { Self::from_bytes_unchecked(Bytes::from_static(b"\0")) }
    }

    /// Creates a domain name from a bytes value.
    ///
    /// This will only succeed if `bytes` contains a properly encoded
    /// absolute domain name. Because the function checks, this will take
    /// a wee bit of time.
    pub fn from_bytes(bytes: Bytes) -> Result<Self, DnameBytesError> {
        if bytes.len() > 255 {
            return Err(DnameError::LongName.into());
        }
        {
            let mut tmp = bytes.as_ref();
            loop {
                let (label, tail) = Label::split_from(tmp)?;
                if label.is_root() {
                    if tail.is_empty() {
                        break;
                    }
                    else {
                        return Err(DnameBytesError::TrailingData)
                    }
                }
                if tail.is_empty() {
                    return Err(DnameBytesError::RelativeName)
                }
                tmp = tail;
            }
        }
        Ok(unsafe { Dname::from_bytes_unchecked(bytes) })
    }

    /// Creates a domain name from a byte slice.
    ///
    /// The function will create a new bytes value from the slice’s content.
    /// If the slice does not contain a correctly encoded, absolute domain
    /// name, the function will fail.
    pub fn from_slice(s: &[u8]) -> Result<Self, DnameBytesError> {
        Self::from_bytes(s.into())
    }

    /// Creates a domain name from a sequence of characters.
    ///
    /// The sequence must result in a domain name in master format
    /// representation. That is, its labels should be separated by dots.
    /// Actual dots, white space and backslashes should be escaped by a
    /// preceeding backslash, and any byte value that is not a printable
    /// ASCII character should be encoded by a backslash followed by its
    /// three digit decimal value.
    ///
    /// The name will always be an absolute name. If the last character in the
    /// sequence is not a dot, the function will quietly add a root label,
    /// anyway. In most cases, this is likely what you want. If it isn’t,
    /// though, use [`UncertainDname`] instead to be able to check.
    ///
    /// [`UncertainDname`]: enum.UncertainDname.html
    pub fn from_chars<C>(chars: C) -> Result<Self, FromStrError>
                      where C: IntoIterator<Item=char> {
        UncertainDname::from_chars(chars).map(|res| res.into_absolute())
    }

    /// Returns a reference to the underlying bytes value.
    pub fn as_bytes(&self) -> &Bytes {
        &self.bytes
    }

    /// Returns a reference to the underlying byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    /// Converts the domain name into its underlying bytes value.
    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }
 
    /// Converts the name into a relative name by dropping the root label.
    pub fn into_relative(mut self) -> RelativeDname {
        let len = self.bytes.len() - 1;
        self.bytes.truncate(len);
        unsafe { RelativeDname::from_bytes_unchecked(self.bytes) }
    }
}

/// # Properties
///
impl Dname {
    /// Returns whether the name is the root label only.
    pub fn is_root(&self) -> bool {
        self.len() == 1
    }
}


/// # Working with Labels
///
impl Dname {
    /// Returns an iterator over the labels of the domain name.
    pub fn iter(&self) -> DnameIter {
        DnameIter::new(self.bytes.as_ref())
    }

    /// Returns an iterator over the suffixes of the name.
    ///
    /// The returned iterator starts with the full name and then for each
    /// additional step returns a name with the left-most label stripped off
    /// until it reaches the root label.
    pub fn iter_suffixes(&self) -> SuffixIter {
        SuffixIter::new(self)
    }

    /// Returns the number of labels in the domain name.
    pub fn label_count(&self) -> usize {
        self.iter().count()
    }

    /// Returns a reference to the first label.
    pub fn first(&self) -> &Label {
        self.iter().next().unwrap()
    }

    /// Returns a reference to the last label.
    pub fn last(&self) -> &Label {
        self.iter().next_back().unwrap()
    }

    /// Determines whether `base` is a prefix of `self`.
    /// 
    /// As this methods accepts only relative domain names, it will only
    /// allow checking for a ‘strict’ prefix.
    pub fn starts_with<N: ToRelativeDname>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<N: ToDname>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::ends_with(self, base)
    }

    /// Returns whether an index points to the first byte of a label.
    pub fn is_label_start(&self, mut index: usize) -> bool {
        let mut tmp = self.as_slice();
        while !tmp.is_empty() {
            let (label, tail) = Label::split_from(tmp).unwrap();
            let len = label.len() + 1;
            if index < len {
                return false
            }
            else if index == len {
                return true
            }
            index -= len;
            tmp = tail;
        }
        false
    }

    /// Like `is_label_start` but panics if it isn’t.
    ///
    fn check_index(&self, index: usize) {
        if !self.is_label_start(index) {
            panic!("index not at start of label");
        }
    }

    /// Returns the part of the name indicated by start and end positions.
    ///
    /// The returned name will start at position `begin` and end right before
    /// position `end`. Both positions must point to the begining of a label.
    ///
    /// # Panics
    ///
    /// The method panics if either position is not the start of a label or
    /// is out of bounds.
    ///
    /// Because the returned domain name is relative, the method will also
    /// panic if the end is equal to the length of the name. If you
    /// want to slice the entire end of the name including the final root
    /// label, you can use [`slice_from()`] instead.
    ///
    /// [`slice_from()`]: #method.slice_from
    pub fn slice(&self, begin: usize, end: usize) -> RelativeDname {
        self.check_index(begin);
        self.check_index(end);
        unsafe {
            RelativeDname::from_bytes_unchecked(self.bytes.slice(begin, end))
        }
    }

    /// Returns the part of the name starting at the given position.
    ///
    /// # Panics
    ///
    /// The method panics if `begin` isn’t the index of the beginning of a
    /// label or is out of bounds.
    pub fn slice_from(&self, begin: usize) -> Self {
        self.check_index(begin);
        unsafe {
            Self::from_bytes_unchecked(self.bytes.slice_from(begin))
        }
    }

    /// Returns the part of the name ending at the given position.
    ///
    /// # Panics
    ///
    /// The method panics if `end` is not the beginning of a label or is out
    /// of bounds. Because the returned domain name is relative, the method
    /// will also panic if the end is equal to the length of the name.
    pub fn slice_to(&self, end: usize) -> RelativeDname {
        self.check_index(end);
        unsafe {
            RelativeDname::from_bytes_unchecked(self.bytes.slice_to(end))
        }
    }

    /// Splits the name into two at the given position.
    ///
    /// Unlike the version on [`Bytes`], the method consumes `self` since the
    /// left side needs to be converted into a [`RelativeDname`].
    /// Consequently, it returns a pair of the left and right parts.
    ///
    /// # Panics
    ///
    /// The method will panic if `mid` is not the index of the beginning of
    /// a label or if it is out of bounds.
    ///
    /// [`Bytes`]: ../../../bytes/struct.Bytes.html#method.split_off
    /// [`RelativeDname`]: struct.RelativeDname.html
    pub fn split_off(mut self, mid: usize) -> (RelativeDname, Dname) {
        let left = self.split_to(mid);
        (left, self)
    }

    /// Splits the name into two at the given position.
    ///
    /// Afterwards, `self` will contain the name starting at the position
    /// while the name ending right before it will be returned.
    ///
    /// # Panics
    ///
    /// The method will panic if `mid` is not the start of a new label or is
    /// out of bounds.
    pub fn split_to(&mut self, mid: usize) -> RelativeDname {
        self.check_index(mid);
        unsafe {
            RelativeDname::from_bytes_unchecked(self.bytes.split_to(mid))
        }
    }

    /// Truncates the name before `len`.
    ///
    /// Because truncating converts the name into a relative name, the method
    /// consumes self.
    ///
    /// # Panics
    ///
    /// The method will panic if `len` is not the index of a new label or if
    /// it is out of bounds.
    pub fn truncate(mut self, len: usize) -> RelativeDname {
        self.check_index(len);
        self.bytes.truncate(len);
        unsafe { RelativeDname::from_bytes_unchecked(self.bytes) }
    }

    /// Splits off the first label.
    ///
    /// If this name is longer than just the root label, returns the first
    /// label as a relative name and removes it from the name itself. If the
    /// name is only the root label, returns `None` and does nothing.
    pub fn split_first(&mut self) -> Option<RelativeDname> {
        if self.len() == 1 {
            return None
        }
        let end = self.iter().next().unwrap().len() + 1;
        Some(unsafe {
            RelativeDname::from_bytes_unchecked(self.bytes.split_to(end))
        })
    }

    /// Reduces the name to the parent of the current name.
    ///
    /// If the name consists of the root label only, returns `false` and does
    /// nothing. Otherwise, drops the first label and returns `true`.
    pub fn parent(&mut self) -> bool {
        self.split_first().is_some()
    }

    /// Strips the suffix `base` from the domain name.
    ///
    /// If `base` is indeed a suffix, returns a relative domain name with the
    /// remainder of the name. Otherwise, returns an error with an unmodified
    /// `self`.
    pub fn strip_suffix<N: ToDname>(self, base: &N)
                                    -> Result<RelativeDname, Dname> {
        if self.ends_with(base) {
            Ok(self.truncate(base.compose_len()))
        }
        else {
            Err(self)
        }
    }
}


//--- Parse, ParseAll, and Compose

impl Parse for Dname {
    type Err = DnameParseError;

    fn parse(parser: &mut Parser) -> Result<Self, Self::Err> {
        let len = {
            let mut tmp = parser.peek_all();
            loop {
                if tmp.is_empty() {
                    return Err(ShortBuf.into())
                }
                let (label, tail) = Label::split_from(tmp)?;
                tmp = tail;
                if label.is_root() {
                    break;
                }
            }
            parser.remaining() - tmp.len()
        };
        if len > 255 {
            return Err(DnameError::LongName.into());
        }
        Ok(unsafe {
            Self::from_bytes_unchecked(parser.parse_bytes(len).unwrap())
        })
    }
}

impl ParseAll for Dname {
    type Err = DnameBytesError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        let mut tmp = parser.clone();
        let end = tmp.pos() + len;
        let res = Self::parse(&mut tmp)?;
        if tmp.pos() < end {
            return Err(DnameBytesError::TrailingData)
        }
        else if tmp.pos() > end {
            return Err(ShortBuf.into())
        }
        parser.advance(len)?;
        Ok(res)
    }
}


impl Compose for Dname {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.as_ref())
    }
}

impl Compress for Dname {
    fn compress(&self, compressor: &mut Compressor) -> Result<(), ShortBuf> {
        compressor.compress_name(self)
    }
}


//--- FromStr

impl str::FromStr for Dname {
    type Err = FromStrError;

    /// Parses a string into an absolute domain name.
    ///
    /// The implementation assumes that the string refers to an absolute name
    /// whether it ends in a dot or not. If you need to be able to distinguish
    /// between those two cases, you can use [`UncertainDname`] instead.
    ///
    /// [`UncertainDname`]: struct.UncertainDname.html
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        UncertainDname::from_str(s).map(|res| res.into_absolute())
    }
}


//--- ToLabelIter and ToDname

impl<'a> ToLabelIter<'a> for Dname {
    type LabelIter = DnameIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        self.iter()
    }
}

impl ToDname for Dname {
    fn to_name(&self) -> Dname {
        self.clone()
    }

    fn as_flat_slice(&self) -> Option<&[u8]> {
        Some(self.as_slice())
    }
}


//--- Deref and AsRef

impl ops::Deref for Dname {
    type Target = Bytes;

    fn deref(&self) -> &Bytes {
        self.as_ref()
    }
}

impl AsRef<Bytes> for Dname {
    fn as_ref(&self) -> &Bytes {
        &self.bytes
    }
}

impl AsRef<[u8]> for Dname {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}


//--- IntoIterator

impl<'a> IntoIterator for &'a Dname {
    type Item = &'a Label;
    type IntoIter = DnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//--- PartialEq and Eq

impl<N: ToDname> PartialEq<N> for Dname {
    fn eq(&self, other: &N) -> bool {
        if let Some(slice) = other.as_flat_slice() {
            self.as_slice().eq_ignore_ascii_case(slice)
        }
        else {
            self.iter().eq(other.iter_labels())
        }
    }
}

impl Eq for Dname { }


//--- PartialOrd and Ord

impl<N: ToDname> PartialOrd<N> for Dname {
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        self.iter().partial_cmp(other.iter_labels())
    }
}

impl Ord for Dname {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.iter().cmp(other.iter())
    }
}


//--- Hash

impl hash::Hash for Dname {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}


//--- Scan and Display

impl Scan for Dname {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.try_scan(UncertainDname::scan, |res| {
            res.try_into_absolute().map_err(|_| SyntaxError::RelativeName)
        })
    }
}

impl fmt::Display for Dname {
    /// Formats the domain name.
    ///
    /// This will produce the domain name in ‘common display format’ without
    /// the trailing dot.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.iter();
        write!(f, "{}", iter.next().unwrap())?;
        for label in iter {
            if !label.is_root() {
                write!(f, ".{}", label)?
            }
        }
        Ok(())
    }
}


//--- Debug

impl fmt::Debug for Dname {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Dname({}.)", self)
    }
}


//------------ SuffixIter ----------------------------------------------------

/// An iterator over ever shorter suffixes of a domain name.
#[derive(Clone, Debug)]
pub struct SuffixIter {
    name: Option<Dname>,
}

impl SuffixIter {
    /// Creates a new iterator cloning `name`.
    fn new(name: &Dname) -> Self {
        SuffixIter {
            name: Some(name.clone())
        }
    }
}

impl Iterator for SuffixIter {
    type Item = Dname;

    fn next(&mut self) -> Option<Self::Item> {
        let (res, ok) = match self.name {
            Some(ref mut name) => (name.clone(), name.parent()),
            None => return None
        };
        if !ok {
            self.name = None
        }
        Some(res)
    }
}


//------------ DnameError ----------------------------------------------------

/// A domain name wasn’t encoded correctly.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum DnameError {
    #[fail(display="{}", _0)]
    BadLabel(LabelTypeError),

    #[fail(display="compressed domain name")]
    CompressedName,

    #[fail(display="long domain name")]
    LongName,
}

impl From<LabelTypeError> for DnameError {
    fn from(err: LabelTypeError) -> DnameError {
        DnameError::BadLabel(err)
    }
}


//------------ DnameParseError -----------------------------------------------

/// An error happened while parsing a domain name.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum DnameParseError {
    #[fail(display="{}", _0)]
    BadName(DnameError),

    #[fail(display="unexpected end of buffer")]
    ShortBuf,
}

impl<T: Into<DnameError>> From<T> for DnameParseError {
    fn from(err: T) -> DnameParseError {
        DnameParseError::BadName(err.into())
    }
}

impl From<SplitLabelError> for DnameParseError {
    fn from(err: SplitLabelError) -> DnameParseError {
        match err {
            SplitLabelError::Pointer(_)
                => DnameParseError::BadName(DnameError::CompressedName),
            SplitLabelError::BadType(t)
                => DnameParseError::BadName(DnameError::BadLabel(t)),
            SplitLabelError::ShortSlice => DnameParseError::ShortBuf,
        }
    }
}

impl From<ShortBuf> for DnameParseError {
    fn from(_: ShortBuf) -> DnameParseError {
        DnameParseError::ShortBuf
    }
}


//------------ DnameBytesError -----------------------------------------------

/// An error happened while converting a bytes value into a domain name.
#[derive(Clone, Copy, Debug, Eq, Fail, PartialEq)]
pub enum DnameBytesError {
    #[fail(display="{}", _0)]
    ParseError(DnameParseError),

    #[fail(display="relative name")]
    RelativeName,

    #[fail(display="trailing data")]
    TrailingData,
}

impl<T: Into<DnameParseError>> From<T> for DnameBytesError {
    fn from(err: T) -> DnameBytesError {
        DnameBytesError::ParseError(err.into())
    }
}


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn root() {
        assert_eq!(Dname::root().as_slice(), b"\0");
    }

    #[test]
    fn from_slice() {
        // a simple good name
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0")
                         .unwrap().as_slice(),
                   b"\x03www\x07example\x03com\0");
        
        // relative name
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com"),
                   Err(DnameBytesError::RelativeName));

        // bytes shorter than what label length says.
        assert_eq!(Dname::from_slice(b"\x03www\x07exa"),
                   Err(ShortBuf.into()));

        // label 63 long ok, 64 bad.
        let mut slice = [0u8; 65];
        slice[0] = 63;
        assert!(Dname::from_slice(&slice[..]).is_ok());
        let mut slice = [0u8; 66];
        slice[0] = 64;
        assert!(Dname::from_slice(&slice[..]).is_err());

        // name 255 long ok, 256 bad.
        let mut buf = Vec::new();
        for _ in 0..25 {
            buf.extend_from_slice(b"\x09123456789");
        }
        assert_eq!(buf.len(), 250);
        let mut tmp = buf.clone();
        tmp.extend_from_slice(b"\x03123\0");
        assert_eq!(Dname::from_slice(&tmp).map(|_| ()), Ok(()));
        buf.extend_from_slice(b"\x041234\0");
        assert!(Dname::from_slice(&buf).is_err());

        // trailing data
        assert!(Dname::from_slice(b"\x03com\0\x03www\0").is_err());

        // bad label heads: compressed, other types.
        assert_eq!(Dname::from_slice(b"\xa2asdasds"),
                   Err(LabelTypeError::Undefined.into()));
        assert_eq!(Dname::from_slice(b"\x62asdasds"),
                   Err(LabelTypeError::Extended(0x62).into()));
        assert_eq!(Dname::from_slice(b"\xccasdasds"),
                   Err(DnameError::CompressedName.into()));
    }

    // No test for `Dname::from_chars` necessary since it only defers to
    // `UncertainDname`.
    //
    // No tests for the simple conversion methods because, well, simple.

    #[test]
    fn into_relative() {
        assert_eq!(Dname::from_slice(b"\x03www\0").unwrap()
                         .into_relative().as_slice(),
                   b"\x03www");
    }

    #[test]
    fn is_root() {
        assert_eq!(Dname::from_slice(b"\0").unwrap().is_root(), true);
        assert_eq!(Dname::from_slice(b"\x03www\0").unwrap().is_root(), false);
        assert_eq!(Dname::root().is_root(), true);
    }

    #[test]
    fn iter() {
    }
}
