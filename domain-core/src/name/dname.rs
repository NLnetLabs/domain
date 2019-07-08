/// Uncompressed, absolute domain names.
///
/// This is a private module. Its public types are re-exported by the parent.

use std::{cmp, error, fmt, hash, ops, str};
use bytes::{BufMut, Bytes};
use derive_more::Display;
use crate::cmp::CanonicalOrd;
use crate::compose::{Compose, Compress, Compressor};
use crate::master::scan::{CharSource, Scan, Scanner, ScanError, SyntaxError};
use crate::parse::{Parse, ParseAll, ParseAllError, Parser, ShortBuf};
use super::label::{Label, LabelTypeError, SplitLabelError};
use super::relative::{RelativeDname, DnameIter};
use super::traits::{ToLabelIter, ToDname};
use super::uncertain::{UncertainDname, FromStrError};


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
/// [`RelativeDname`]: struct.RelativeDname.html
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
    pub unsafe fn from_bytes_unchecked(bytes: Bytes) -> Self {
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
/// More of the usual methods on byte sequences, such as
/// [`len`](#method.len), are available via
/// [deref to `Bytes`](#deref-methods).
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
    ///
    /// Because the last label in an absolute name is always the root label,
    /// this method can return a static reference. It is also a wee bit silly,
    /// but here for completeness.
    pub fn last(&self) -> &'static Label {
        Label::root()
    }

    /// Determines whether `base` is a prefix of `self`.
    pub fn starts_with<'a, N: ToLabelIter<'a>>(&'a self, base: &'a N) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<'a, N: ToLabelIter<'a>>(&'a self, base: &'a N) -> bool {
        <Self as ToLabelIter>::ends_with(self, base)
    }

    /// Returns whether an index points to the first byte of a non-root label.
    pub fn is_label_start(&self, mut index: usize) -> bool {
        if index == 0 {
            return true
        }
        let mut tmp = self.as_slice();
        while !tmp.is_empty() {
            let (label, tail) = Label::split_from(tmp).unwrap();
            let len = label.len() + 1;
            if index < len || len == 1 { // length 1: root label.
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
    fn check_index(&self, index: usize) {
        if !self.is_label_start(index) {
            panic!("index not at start of a label");
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
            let len = self.compose_len() - base.compose_len();
            Ok(self.truncate(len))
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
        let len = name_len(parser)?;
        Ok(unsafe {
            Self::from_bytes_unchecked(parser.parse_bytes(len).unwrap())
        })
    }

    fn skip(parser: &mut Parser) -> Result<(), Self::Err> {
        let len = name_len(parser)?;
        parser.advance(len)?;
        Ok(())
    }
}

fn name_len(parser: &mut Parser) -> Result<usize, DnameParseError> {
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
        Err(DnameError::LongName.into())
    }
    else {
        Ok(len)
    }
}

impl ParseAll for Dname {
    type Err = DnameParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        Ok(Self::from_bytes(parser.parse_bytes(len)?)?)
    }
}


impl Compose for Dname {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.as_ref())
    }
    
    fn compose_canonical<B: BufMut>(&self, buf: &mut B) {
        for label in self.iter_labels() {
            label.compose_canonical(buf)
        }
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


//--- PartialEq, and Eq

impl<N: ToDname> PartialEq<N> for Dname {
    fn eq(&self, other: &N) -> bool {
        self.name_eq(other)
    }
}

impl Eq for Dname { }


//--- PartialOrd, Ord, and CanonicalOrd

impl<N: ToDname> PartialOrd<N> for Dname {
    /// Returns the ordering between `self` and `other`.
    ///
    /// Domain name order is determined according to the ‘canonical DNS
    /// name order’ as defined in [section 6.1 of RFC 4034][RFC4034-6.1].
    ///
    /// [RFC4034-6.1]: https://tools.ietf.org/html/rfc4034#section-6.1
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        Some(self.name_cmp(other))
    }
}

impl Ord for Dname {
    /// Returns the ordering between `self` and `other`.
    ///
    /// Domain name order is determined according to the ‘canonical DNS
    /// name order’ as defined in [section 6.1 of RFC 4034][RFC4034-6.1].
    ///
    /// [RFC4034-6.1]: https://tools.ietf.org/html/rfc4034#section-6.1
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.name_cmp(other)
    }
}

impl<N: ToDname> CanonicalOrd<N> for Dname {
    fn canonical_cmp(&self, other: &N) -> cmp::Ordering {
        self.name_cmp(other)
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
        let pos = scanner.pos();
        let name = match UncertainDname::scan(scanner)? {
            UncertainDname::Relative(name) => name,
            UncertainDname::Absolute(name) => return Ok(name)
        };
        let origin = match *scanner.origin() {
            Some(ref origin) => origin,
            None => return Err((SyntaxError::NoOrigin, pos).into())
        };
        name.into_builder().append_origin(origin)
                           .map_err(|err| (SyntaxError::from(err), pos).into())
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
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum DnameError {
    #[display(fmt="{}", _0)]
    BadLabel(LabelTypeError),

    #[display(fmt="compressed domain name")]
    CompressedName,

    #[display(fmt="long domain name")]
    LongName,
}

impl error::Error for DnameError { }

impl From<LabelTypeError> for DnameError {
    fn from(err: LabelTypeError) -> DnameError {
        DnameError::BadLabel(err)
    }
}


//------------ DnameParseError -----------------------------------------------

/// An error happened while parsing a domain name.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum DnameParseError {
    #[display(fmt="{}", _0)]
    BadName(DnameError),

    #[display(fmt="unexpected end of buffer")]
    ShortBuf,
}

impl error::Error for DnameParseError { }

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
            SplitLabelError::ShortBuf => DnameParseError::ShortBuf,
        }
    }
}

impl From<ShortBuf> for DnameParseError {
    fn from(_: ShortBuf) -> DnameParseError {
        DnameParseError::ShortBuf
    }
}


//------------ DnameParseAllError --------------------------------------------

/// An error happened while parsing a domain name.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum DnameParseAllError {
    #[display(fmt="{}", _0)]
    BadName(DnameError),

    #[display(fmt="{}", _0)]
    ParseError(ParseAllError)
}

impl error::Error for DnameParseAllError { }

impl<T: Into<DnameError>> From<T> for DnameParseAllError {
    fn from(err: T) -> Self {
        DnameParseAllError::BadName(err.into())
    }
}

impl From<ShortBuf> for DnameParseAllError {
    fn from(err: ShortBuf) -> Self {
        DnameParseAllError::ParseError(err.into())
    }
}

impl From<ParseAllError> for DnameParseAllError {
    fn from(err: ParseAllError) -> Self {
        DnameParseAllError::ParseError(err)
    }
}

impl From<DnameParseError> for DnameParseAllError {
    fn from(err: DnameParseError) -> Self {
        match err {
            DnameParseError::BadName(err) => DnameParseAllError::BadName(err),
            DnameParseError::ShortBuf
                => DnameParseAllError::ParseError(ParseAllError::ShortBuf),
        }
    }
}

impl From<DnameBytesError> for DnameParseAllError {
    fn from(err: DnameBytesError) -> Self {
        match err {
            DnameBytesError::ParseError(DnameParseError::BadName(err))
                => DnameParseAllError::BadName(err),
            DnameBytesError::ParseError(DnameParseError::ShortBuf)
                => DnameParseAllError::ParseError(ParseAllError::ShortBuf),
            DnameBytesError::RelativeName
                => DnameParseAllError::ParseError(ParseAllError::ShortField),
            DnameBytesError::TrailingData
                => DnameParseAllError::ParseError(ParseAllError::TrailingData),
        }
    }
}


//------------ DnameBytesError -----------------------------------------------

/// An error happened while converting a bytes value into a domain name.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum DnameBytesError {
    #[display(fmt="{}", _0)]
    ParseError(DnameParseError),

    #[display(fmt="relative name")]
    RelativeName,

    #[display(fmt="trailing data")]
    TrailingData,
}

impl error::Error for DnameBytesError { }

impl<T: Into<DnameParseError>> From<T> for DnameBytesError {
    fn from(err: T) -> DnameBytesError {
        DnameBytesError::ParseError(err.into())
    }
}


//============ Testing =======================================================
//
// Some of the helper functions herein are resused by the tests of other
// sub-modules of ::bits::name. Hence the `pub(crate)` designation.

#[cfg(test)]
pub(crate) mod test {
    use std::cmp::Ordering;
    use unwrap::unwrap;
    use super::*;

    macro_rules! assert_panic {
        ( $cond:expr ) => {
            {
                let result = ::std::panic::catch_unwind(|| $cond);
                assert!(result.is_err());
            }
        }
    }

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

        // empty input
        assert_eq!(Dname::from_slice(b""), Err(ShortBuf.into()));
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

    pub fn cmp_iter<I>(mut iter: I, labels: &[&[u8]])
    where
        I: Iterator,
        I::Item: AsRef<[u8]>
    {
        let mut labels = labels.iter();
        loop {
            match (iter.next(), labels.next()) {
                (Some(left), Some(right)) => assert_eq!(left.as_ref(), *right),
                (None, None) => break,
                (_, None) => panic!("extra items in iterator"),
                (None, _) => panic!("missing items in iterator"),
            }
        }
    }

    #[test]
    fn iter() {
        cmp_iter(Dname::root().iter(), &[b""]);
        cmp_iter(Dname::from_slice(b"\x03www\x07example\x03com\0")
                       .unwrap().iter(),
                 &[b"www", b"example", b"com", b""]);
    }

    pub fn cmp_iter_back<I>(mut iter: I, labels: &[&[u8]])
    where
        I: DoubleEndedIterator,
        I::Item: AsRef<[u8]>
    {
        let mut labels = labels.iter();
        loop {
            match (iter.next_back(), labels.next()) {
                (Some(left), Some(right)) => assert_eq!(left.as_ref(), *right),
                (None, None) => break,
                (_, None) => panic!("extra items in iterator"),
                (None, _) => panic!("missing items in iterator"),
            }
        }
    }

    #[test]
    fn iter_back() {
        cmp_iter_back(Dname::root().iter(), &[b""]);
        cmp_iter_back(Dname::from_slice(b"\x03www\x07example\x03com\0")
                            .unwrap().iter(),
                      &[b"", b"com", b"example", b"www"]);
    }

    #[test]
    fn iter_suffixes() {
        cmp_iter(Dname::root().iter_suffixes(), &[b"\0"]);
        cmp_iter(Dname::from_slice(b"\x03www\x07example\x03com\0")
                       .unwrap().iter_suffixes(),
                 &[b"\x03www\x07example\x03com\0", b"\x07example\x03com\0",
                   b"\x03com\0", b"\0"]);
    }

    #[test]
    fn label_count() {
        assert_eq!(Dname::root().label_count(), 1);
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap()
                         .label_count(),
                   4);
    }

    #[test]
    fn first() {
        assert_eq!(Dname::root().first().as_slice(), b"");
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap()
                         .first().as_slice(),
                   b"www");
    }

    // No test for `last` because it is so trivial.

    #[test]
    fn last() {
        assert_eq!(Dname::root().last().as_slice(), b"");
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap()
                         .last().as_slice(),
                   b"");
    }

    #[test]
    fn starts_with() {
        let root = Dname::root();
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert!(root.starts_with(&root));
        assert!(wecr.starts_with(&wecr));
        
        assert!( root.starts_with(&RelativeDname::empty()));
        assert!( wecr.starts_with(&RelativeDname::empty()));
        
        let test = RelativeDname::from_slice(b"\x03www").unwrap();
        assert!(!root.starts_with(&test));
        assert!( wecr.starts_with(&test));
        
        let test = RelativeDname::from_slice(b"\x03www\x07example").unwrap();
        assert!(!root.starts_with(&test));
        assert!( wecr.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x03www\x07example\x03com")
                                 .unwrap();
        assert!(!root.starts_with(&test));
        assert!( wecr.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x07example\x03com").unwrap();
        assert!(!root.starts_with(&test));
        assert!(!wecr.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x03www").unwrap()
                    .chain(RelativeDname::from_slice(b"\x07example").unwrap())
                    .unwrap();
        assert!(!root.starts_with(&test));
        assert!( wecr.starts_with(&test));

        let test = test.chain(RelativeDname::from_slice(b"\x03com")
                                            .unwrap())
                       .unwrap();
        assert!(!root.starts_with(&test));
        assert!( wecr.starts_with(&test));
    }

    #[test]
    fn ends_with() {
        let root = Dname::root();
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        for name in wecr.iter_suffixes() {
            if name.is_root() {
                assert!(root.ends_with(&name));
            }
            else {
                assert!(!root.ends_with(&name));
            }
            assert!(wecr.ends_with(&name));
        }
    }

    #[test]
    fn is_label_start() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert!( wecr.is_label_start(0)); // \x03
        assert!(!wecr.is_label_start(1)); // w
        assert!(!wecr.is_label_start(2)); // w
        assert!(!wecr.is_label_start(3)); // w
        assert!( wecr.is_label_start(4)); // \x07
        assert!(!wecr.is_label_start(5)); // e
        assert!(!wecr.is_label_start(6)); // x
        assert!(!wecr.is_label_start(7)); // a
        assert!(!wecr.is_label_start(8)); // m
        assert!(!wecr.is_label_start(9)); // p
        assert!(!wecr.is_label_start(10)); // l
        assert!(!wecr.is_label_start(11)); // e
        assert!( wecr.is_label_start(12)); // \x03
        assert!(!wecr.is_label_start(13)); // c
        assert!(!wecr.is_label_start(14)); // o
        assert!(!wecr.is_label_start(15)); // m
        assert!( wecr.is_label_start(16)); // \0
        assert!(!wecr.is_label_start(17)); //
        assert!(!wecr.is_label_start(18)); //
    }

    #[test]
    fn slice() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.slice(0, 4).as_slice(), b"\x03www");
        assert_eq!(wecr.slice(0, 12).as_slice(), b"\x03www\x07example");
        assert_eq!(wecr.slice(4, 12).as_slice(), b"\x07example");
        assert_eq!(wecr.slice(4, 16).as_slice(), b"\x07example\x03com");

        assert_panic!(wecr.slice(0,3));
        assert_panic!(wecr.slice(1,4));
        assert_panic!(wecr.slice(0,11));
        assert_panic!(wecr.slice(1,12));
        assert_panic!(wecr.slice(0,17));
        assert_panic!(wecr.slice(4,17));
        assert_panic!(wecr.slice(0,18));
    }

    #[test]
    fn slice_from() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.slice_from(0).as_slice(),
                   b"\x03www\x07example\x03com\0");
        assert_eq!(wecr.slice_from(4).as_slice(), b"\x07example\x03com\0");
        assert_eq!(wecr.slice_from(12).as_slice(), b"\x03com\0");
        assert_eq!(wecr.slice_from(16).as_slice(), b"\0");

        assert_panic!(wecr.slice_from(17));
        assert_panic!(wecr.slice_from(18));
    }

    #[test]
    fn slice_to() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.slice_to(0).as_slice(), b"");
        assert_eq!(wecr.slice_to(4).as_slice(), b"\x03www");
        assert_eq!(wecr.slice_to(12).as_slice(), b"\x03www\x07example");
        assert_eq!(wecr.slice_to(16).as_slice(), b"\x03www\x07example\x03com");

        assert_panic!(wecr.slice_to(17));
        assert_panic!(wecr.slice_to(18));
    }

    #[test]
    fn split_off() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        let (left, right) = wecr.clone().split_off(0);
        assert_eq!(left.as_slice(), b"");
        assert_eq!(right.as_slice(), b"\x03www\x07example\x03com\0");

        let (left, right) = wecr.clone().split_off(4);
        assert_eq!(left.as_slice(), b"\x03www");
        assert_eq!(right.as_slice(), b"\x07example\x03com\0");

        let (left, right) = wecr.clone().split_off(12);
        assert_eq!(left.as_slice(), b"\x03www\x07example");
        assert_eq!(right.as_slice(), b"\x03com\0");

        let (left, right) = wecr.clone().split_off(16);
        assert_eq!(left.as_slice(), b"\x03www\x07example\x03com");
        assert_eq!(right.as_slice(), b"\0");

        assert_panic!(wecr.clone().split_off(1));
        assert_panic!(wecr.clone().split_off(14));
        assert_panic!(wecr.clone().split_off(17));
        assert_panic!(wecr.clone().split_off(18));
    }

    #[test]
    fn split_to() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        let mut tmp = wecr.clone();
        assert_eq!(tmp.split_to(0).as_slice(), b"");
        assert_eq!(tmp.as_slice(), b"\x03www\x07example\x03com\0");

        let mut tmp = wecr.clone();
        assert_eq!(tmp.split_to(4).as_slice(), b"\x03www");
        assert_eq!(tmp.as_slice(), b"\x07example\x03com\0");

        let mut tmp = wecr.clone();
        assert_eq!(tmp.split_to(12).as_slice(), b"\x03www\x07example");
        assert_eq!(tmp.as_slice(), b"\x03com\0");

        let mut tmp = wecr.clone();
        assert_eq!(tmp.split_to(16).as_slice(), b"\x03www\x07example\x03com");
        assert_eq!(tmp.as_slice(), b"\0");

        assert_panic!(wecr.clone().split_to(1));
        assert_panic!(wecr.clone().split_to(14));
        assert_panic!(wecr.clone().split_to(17));
        assert_panic!(wecr.clone().split_to(18));
    }

    #[test]
    fn truncate() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.clone().truncate(0).as_slice(),
                   b"");
        assert_eq!(wecr.clone().truncate(4).as_slice(),
                   b"\x03www");
        assert_eq!(wecr.clone().truncate(12).as_slice(),
                   b"\x03www\x07example");
        assert_eq!(wecr.clone().truncate(16).as_slice(),
                   b"\x03www\x07example\x03com");
        
        assert_panic!(wecr.clone().truncate(1));
        assert_panic!(wecr.clone().truncate(14));
        assert_panic!(wecr.clone().truncate(17));
        assert_panic!(wecr.clone().truncate(18));
    }

    #[test]
    fn split_first() {
        let mut wecr = Dname::from_slice(b"\x03www\x07example\x03com\0")
                             .unwrap();

        assert_eq!(wecr.split_first().unwrap().as_slice(), b"\x03www");
        assert_eq!(wecr.as_slice(), b"\x07example\x03com\0");
        assert_eq!(wecr.split_first().unwrap().as_slice(), b"\x07example");
        assert_eq!(wecr.as_slice(), b"\x03com\0");
        assert_eq!(wecr.split_first().unwrap().as_slice(), b"\x03com");
        assert_eq!(wecr.as_slice(), b"\0");
        assert!(wecr.split_first().is_none());
        assert_eq!(wecr.as_slice(), b"\0");
        assert!(wecr.split_first().is_none());
        assert_eq!(wecr.as_slice(), b"\0");
    }

    #[test]
    fn parent() {
        let mut wecr = Dname::from_slice(b"\x03www\x07example\x03com\0")
                             .unwrap();

        assert!(wecr.parent());
        assert_eq!(wecr.as_slice(), b"\x07example\x03com\0");
        assert!(wecr.parent());
        assert_eq!(wecr.as_slice(), b"\x03com\0");
        assert!(wecr.parent());
        assert_eq!(wecr.as_slice(), b"\0");
        assert!(!wecr.parent());
        assert_eq!(wecr.as_slice(), b"\0");
        assert!(!wecr.parent());
        assert_eq!(wecr.as_slice(), b"\0");
    }

    #[test]
    fn strip_suffix() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();
        let ecr = Dname::from_slice(b"\x07example\x03com\0").unwrap();
        let cr = Dname::from_slice(b"\x03com\0").unwrap();
        let wenr = Dname::from_slice(b"\x03www\x07example\x03net\0").unwrap();
        let enr = Dname::from_slice(b"\x07example\x03net\0").unwrap();
        let nr = Dname::from_slice(b"\x03net\0").unwrap();

        assert_eq!(wecr.clone().strip_suffix(&wecr).unwrap().as_slice(),
                   b"");
        assert_eq!(wecr.clone().strip_suffix(&ecr).unwrap().as_slice(),
                   b"\x03www");
        assert_eq!(wecr.clone().strip_suffix(&cr).unwrap().as_slice(),
                   b"\x03www\x07example");
        assert_eq!(wecr.clone().strip_suffix(&Dname::root())
                               .unwrap().as_slice(),
                   b"\x03www\x07example\x03com");

        assert_eq!(wecr.clone().strip_suffix(&wenr).unwrap_err().as_slice(),
                   b"\x03www\x07example\x03com\0");
        assert_eq!(wecr.clone().strip_suffix(&enr).unwrap_err().as_slice(),
                   b"\x03www\x07example\x03com\0");
        assert_eq!(wecr.clone().strip_suffix(&nr).unwrap_err().as_slice(),
                   b"\x03www\x07example\x03com\0");
    }

    #[test]
    fn parse() {
        // Parse a correctly formatted name.
        let mut p = Parser::from_static(b"\x03www\x07example\x03com\0af");
        assert_eq!(Dname::parse(&mut p).unwrap().as_slice(),
                  b"\x03www\x07example\x03com\0");
        assert_eq!(p.peek_all(), b"af");

        // Short buffer in middle of label.
        let mut p = Parser::from_static(b"\x03www\x07exam");
        assert_eq!(Dname::parse(&mut p), Err(ShortBuf.into()));

        // Short buffer at end of label.
        let mut p = Parser::from_static(b"\x03www\x07example");
        assert_eq!(Dname::parse(&mut p), Err(ShortBuf.into()));

        // Compressed name.
        let mut p = Parser::from_static(b"\x03com\x03www\x07example\xc0\0");
        p.advance(4).unwrap();
        assert_eq!(Dname::parse(&mut p),
                   Err(DnameError::CompressedName.into()));

        // Bad label header.
        let mut p = Parser::from_static(b"\x03www\x07example\xbffoo");
        assert_eq!(Dname::parse(&mut p),
                   Err(LabelTypeError::Undefined.into()));

        // Long name: 255 bytes is fine.
        let mut buf = Vec::new();
        for _ in 0..50 {
            buf.extend_from_slice(b"\x041234");
        }
        buf.extend_from_slice(b"\x03123\0");
        assert_eq!(buf.len(), 255);
        let mut p = Parser::from_bytes(buf.into());
        assert!(Dname::parse(&mut p).is_ok());
        assert_eq!(p.peek_all(), b"");

        // Long name: 256 bytes are bad.
        let mut buf = Vec::new();
        for _ in 0..51 {
            buf.extend_from_slice(b"\x041234");
        }
        buf.extend_from_slice(b"\0");
        assert_eq!(buf.len(), 256);
        let mut p = Parser::from_bytes(buf.into());
        assert_eq!(Dname::parse(&mut p),
                   Err(DnameError::LongName.into()));
    }

    #[test]
    fn parse_all() {
        // The current implementation defers to `Dname::from_bytes`. As there
        // are test cases for the error cases with that function, all we need
        // to do is make sure it defers correctly.

        let mut p = Parser::from_static(b"\x03www\x07example\x03com\0af");
        assert_eq!(Dname::parse_all(&mut p, 17).unwrap().as_slice(),
                  b"\x03www\x07example\x03com\0");
        assert_eq!(p.peek_all(), b"af");
        
        let mut p = Parser::from_static(b"\0af");
        assert_eq!(Dname::parse_all(&mut p, 1).unwrap().as_slice(), b"\0");
        assert_eq!(p.peek_all(), b"af");
    }

    // I don’t think we need tests for `Compose::compose` and `Compress`. The
    // former only copies the underlying bytes, the latter simply
    // defers to `Compressor::compress_name` which is tested separately.

    #[test]
    fn compose_canonical() {
        let mut buf = Vec::new();
        unwrap!(
            Dname::from_slice(b"\x03wWw\x07exaMPle\x03com\0")
        ).compose_canonical(&mut buf);
        assert_eq!(buf.as_slice(), b"\x03www\x07example\x03com\0");
    }

    #[test]
    fn from_str() {
        // Another simple test. `UncertainDname` does all the heavy lifting,
        // so we don’t need to test all the escape sequence shenanigans here.
        // Just check that we’ll always get a name, final dot or not, unless
        // the string is empty.
        use std::str::FromStr;

        assert_eq!(Dname::from_str("www.example.com").unwrap().as_slice(),
                   b"\x03www\x07example\x03com\0");
        assert_eq!(Dname::from_str("www.example.com.").unwrap().as_slice(),
                   b"\x03www\x07example\x03com\0");
    }

    #[test]
    fn eq() {
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
                   Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap());
        assert_eq!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
                   Dname::from_slice(b"\x03wWw\x07eXAMple\x03Com\0").unwrap());
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            RelativeDname::from_slice(b"\x03www").unwrap()
                .chain(RelativeDname::from_slice(b"\x07example\x03com")
                                     .unwrap())
                    .unwrap()
                .chain(Dname::root()).unwrap()
        );
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            RelativeDname::from_slice(b"\x03wWw").unwrap()
                .chain(RelativeDname::from_slice(b"\x07eXAMple\x03coM")
                                     .unwrap())
                    .unwrap()
                .chain(Dname::root()).unwrap()
        );

        assert_ne!(Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
                   Dname::from_slice(b"\x03ww4\x07example\x03com\0").unwrap());
        assert_ne!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            RelativeDname::from_slice(b"\x03www").unwrap()
                .chain(RelativeDname::from_slice(b"\x073xample\x03com")
                                     .unwrap())
                    .unwrap()
                .chain(Dname::root()).unwrap()
        );
    }

    #[test]
    fn cmp() {
        // The following is taken from section 6.1 of RFC 4034.
        let names = [
            Dname::from_slice(b"\x07example\0").unwrap(),
            Dname::from_slice(b"\x01a\x07example\0").unwrap(),
            Dname::from_slice(b"\x08yljkjljk\x01a\x07example\0").unwrap(),
            Dname::from_slice(b"\x01Z\x01a\x07example\0").unwrap(),
            Dname::from_slice(b"\x04zABC\x01a\x07example\0").unwrap(),
            Dname::from_slice(b"\x01z\x07example\0").unwrap(),
            Dname::from_slice(b"\x01\x01\x01z\x07example\0").unwrap(),
            Dname::from_slice(b"\x01*\x01z\x07example\0").unwrap(),
            Dname::from_slice(b"\x01\xc8\x01z\x07example\0").unwrap(),
        ];
        for i in 0..names.len() {
            for j in 0..names.len() {
                let ord = if i < j { Ordering::Less }
                          else if i == j { Ordering::Equal }
                          else { Ordering::Greater };
                assert_eq!(names[i].partial_cmp(&names[j]), Some(ord));
                assert_eq!(names[i].cmp(&names[j]), ord);
            }
        }

        let n1 = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();
        let n2 = Dname::from_slice(b"\x03wWw\x07eXAMple\x03Com\0").unwrap();
        assert_eq!(n1.partial_cmp(&n2), Some(Ordering::Equal));
        assert_eq!(n1.cmp(&n2), Ordering::Equal);
    }

    #[test]
    fn hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut s1 = DefaultHasher::new();
        let mut s2 = DefaultHasher::new();
        Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap()
              .hash(&mut s1);
        Dname::from_slice(b"\x03wWw\x07eXAMple\x03Com\0").unwrap()
              .hash(&mut s2);
        assert_eq!(s1.finish(), s2.finish());
    }

    // Scan and Display skipped for now.
}

