use super::super::cmp::CanonicalOrd;
use super::super::octets::{
    Compose, EmptyBuilder, FormError, FromBuilder, OctetsBuilder, OctetsExt,
    OctetsFrom, OctetsRef, Parse, ParseError, Parser, ShortBuf,
};
use super::builder::{DnameBuilder, FromStrError};
use super::label::{Label, LabelTypeError, SplitLabelError};
use super::relative::{DnameIter, RelativeDname};
use super::traits::{ToDname, ToLabelIter};
#[cfg(feature = "master")]
use super::uncertain::UncertainDname;
#[cfg(feature = "scan")]
use crate::scan::{Scan, ScanError, Scanner, SyntaxError};
#[cfg(feature = "bytes")]
use bytes::Bytes;
use core::str::FromStr;
/// Uncompressed, absolute domain names.
///
/// This is a private module. Its public types are re-exported by the parent.
use core::{cmp, fmt, hash, ops, str};
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ Dname ---------------------------------------------------------

/// An uncompressed, absolute domain name.
///
/// The type wraps an octets sequence and guarantees that it always contains
/// a correctly encoded, absolute domain name. It provides an interface
/// similar to a slice of the labels of the name, i.e., you can iterate over
/// the labels, split them off, etc.
///
/// You can construct a domain name from a string via the `FromStr` trait or
/// manually via a [`DnameBuilder`]. In addition, you can also parse it from
/// a message. This will, however, require the name to be uncompressed.
/// Otherwise, you would receive a [`ParsedDname`] which can be converted into
/// `Dname` via [`ToDname::to_dname`].
///
/// [`DnameBuilder`]: struct.DnameBuilder.html
/// [`ParsedDname`]: struct.ParsedDname.html
/// [`RelativeDname`]: struct.RelativeDname.html
/// [`ToDname::to_dname`]: trait.ToDname.html#method.to_dname
#[derive(Clone)]
pub struct Dname<Octets: ?Sized>(Octets);

/// # Creating Values
///
impl<Octets> Dname<Octets> {
    /// Creates a domain name from the underlying octets without any check.
    ///
    /// Since this will allow to actually construct an incorrectly encoded
    /// domain name value, the function is unsafe.
    ///
    /// # Safety
    ///
    /// The octets sequence passed in `octets` must contain a correctly
    /// encoded absolute domain name. It must be at most 255 octets long.
    /// It must contain the root label exactly once as its last label.
    pub const unsafe fn from_octets_unchecked(octets: Octets) -> Self {
        Dname(octets)
    }

    /// Creates a domain name from an octet sequence.
    ///
    /// This will only succeed if `octets` contains a properly encoded
    /// absolute domain name. Because the function checks, this will take
    /// a wee bit of time.
    pub fn from_octets(octets: Octets) -> Result<Self, DnameError>
    where
        Octets: AsRef<[u8]>,
    {
        Dname::check_slice(octets.as_ref())?;
        Ok(unsafe { Dname::from_octets_unchecked(octets) })
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
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
        C: IntoIterator<Item = char>,
    {
        let mut builder = DnameBuilder::<Octets::Builder>::new();
        builder.append_chars(chars)?;
        builder.into_dname().map_err(Into::into)
    }

    /// Returns a domain name consisting of the root label only.
    ///
    /// This function will work for any kind octets sequence that can be
    /// created from an octets slice. Since this will require providing the
    /// type parameter in some cases, there are shortcuts methods for specific
    /// octets types: [`root_ref`], [`root_vec`], and [`root_bytes`].
    ///
    /// [`root_ref`]: #method.root_ref
    /// [`root_vec`]: #method.root_vec
    /// [`root_bytes`]: #method.root_bytes
    pub fn root() -> Self
    where
        Octets: From<&'static [u8]>,
    {
        unsafe { Self::from_octets_unchecked(b"\0".as_ref().into()) }
    }
}

impl Dname<[u8]> {
    /// Creates a domain name from an octet slice without checking,
    unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        &*(slice as *const [u8] as *const Dname<[u8]>)
    }

    /// Creates a domain name from an octets slice.
    ///
    /// This will only succeed if `slice` contains a properly encoded
    /// absolute domain name.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, DnameError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Creates a domain name for the root label only atop an octets slice.
    pub fn root_slice() -> &'static Self {
        unsafe { Self::from_slice_unchecked("\0".as_ref()) }
    }

    /// Checks whether an octet slice contains a correctly encoded name.
    fn check_slice(mut slice: &[u8]) -> Result<(), DnameError> {
        if slice.len() > 255 {
            return Err(DnameError::LongName);
        }
        loop {
            let (label, tail) = Label::split_from(slice)?;
            if label.is_root() {
                if tail.is_empty() {
                    break;
                } else {
                    return Err(DnameError::TrailingData);
                }
            }
            if tail.is_empty() {
                return Err(DnameError::RelativeName);
            }
            slice = tail;
        }
        Ok(())
    }
}

impl Dname<&'static [u8]> {
    /// Creates a domain name for the root label only atop a slice reference.
    pub fn root_ref() -> Self {
        Self::root()
    }
}

#[cfg(feature = "std")]
impl Dname<Vec<u8>> {
    /// Creates a domain name for the root label only atop a `Vec<u8>`.
    pub fn root_vec() -> Self {
        Self::root()
    }

    /// Creates a domain name atop a `Vec<u8>` from its string representation.
    pub fn vec_from_str(s: &str) -> Result<Self, FromStrError> {
        FromStr::from_str(s)
    }
}

#[cfg(feature = "bytes")]
impl Dname<Bytes> {
    /// Creates a domain name for the root label only atop a bytes values.
    pub fn root_bytes() -> Self {
        Self::root()
    }

    /// Creates a domain name atop a Bytes from its string representation.
    pub fn bytes_from_str(s: &str) -> Result<Self, FromStrError> {
        FromStr::from_str(s)
    }
}

/// # Conversions
///
impl<Octets: ?Sized> Dname<Octets> {
    /// Returns a reference to the underlying octets sequence.
    pub fn as_octets(&self) -> &Octets {
        &self.0
    }

    /// Converts the domain name into the underlying octets sequence.
    pub fn into_octets(self) -> Octets
    where
        Octets: Sized,
    {
        self.0
    }

    /// Converts the name into a relative name by dropping the root label.
    pub fn into_relative(mut self) -> RelativeDname<Octets>
    where
        Octets: Sized + OctetsExt,
    {
        let len = self.0.as_ref().len() - 1;
        self.0.truncate(len);
        unsafe { RelativeDname::from_octets_unchecked(self.0) }
    }

    /// Returns a domain name using a reference to the octets.
    pub fn for_ref(&self) -> Dname<&Octets> {
        unsafe { Dname::from_octets_unchecked(&self.0) }
    }

    /// Returns a reference to the underlying octets slice.
    pub fn as_slice(&self) -> &[u8]
    where
        Octets: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    /// Returns a domain name for the octets slice of the content.
    pub fn for_slice(&self) -> Dname<&[u8]>
    where
        Octets: AsRef<[u8]>,
    {
        unsafe { Dname::from_octets_unchecked(self.0.as_ref()) }
    }
}

/// # Properties
///
/// More of the usual methods on octets sequences, such as `len`, are
/// available via the implementation of `Deref<Target = Octets>`.
impl<Octets: AsRef<[u8]> + ?Sized> Dname<Octets> {
    /// Returns whether the name is the root label only.
    pub fn is_root(&self) -> bool {
        self.0.as_ref().len() == 1
    }
}

/// # Working with Labels
///
/// All methods that split the name or cut off parts on the left side are
/// only available on octets sequences that are their only range, e.g.,
/// `&[u8]` or `Bytes`, as these are the only types that can be split.
impl<Octets: AsRef<[u8]> + ?Sized> Dname<Octets> {
    /// Returns an iterator over the labels of the domain name.
    pub fn iter(&self) -> DnameIter {
        DnameIter::new(self.0.as_ref())
    }

    /// Returns an iterator over the suffixes of the name.
    ///
    /// The returned iterator starts with the full name and then for each
    /// additional step returns a name with the left-most label stripped off
    /// until it reaches the root label.
    pub fn iter_suffixes(&self) -> SuffixIter<&Octets> {
        SuffixIter::new(self.for_ref())
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
    pub fn starts_with<'a, N: ToLabelIter<'a> + ?Sized>(
        &'a self,
        base: &'a N,
    ) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<'a, N: ToLabelIter<'a> + ?Sized>(
        &'a self,
        base: &'a N,
    ) -> bool {
        <Self as ToLabelIter>::ends_with(self, base)
    }

    /// Returns whether an index points to the first byte of a non-root label.
    pub fn is_label_start(&self, mut index: usize) -> bool {
        if index == 0 {
            return true;
        }
        let mut tmp = self.as_slice();
        while !tmp.is_empty() {
            let (label, tail) = Label::split_from(tmp).unwrap();
            let len = label.len() + 1;
            if index < len || len == 1 {
                // length 1: root label.
                return false;
            } else if index == len {
                return true;
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
    /// position `end`. Both positions are given as indexes into the
    /// underlying octets sequence and must point to the begining of a label.
    ///
    /// The method returns a reference to an unsized relative domain name and
    /// is thus best suited for temporary referencing. If you want to keep the
    /// part of the name around, [`range`] is likely a better choice.
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
    /// [`range`]: #method.range
    /// [`slice_from()`]: #method.slice_from
    pub fn slice(&self, begin: usize, end: usize) -> &RelativeDname<[u8]> {
        self.check_index(begin);
        self.check_index(end);
        unsafe {
            RelativeDname::from_slice_unchecked(&self.0.as_ref()[begin..end])
        }
    }

    /// Returns the part of the name starting at the given position.
    ///
    /// The returned name will start at the given postion and cover the
    /// remainder of the name. The position `begin` is provided as an index
    /// into the underlying octets sequence and must point to the beginning
    /// of a label.
    ///
    /// The method returns a reference to an unsized domain name and
    /// is thus best suited for temporary referencing. If you want to keep the
    /// part of the name around, [`range_from`] is likely a better choice.
    ///
    /// # Panics
    ///
    /// The method panics if `begin` isn’t the index of the beginning of a
    /// label or is out of bounds.
    ///
    /// [`range_from`]: #method.range_from
    pub fn slice_from(&self, begin: usize) -> &Dname<[u8]> {
        self.check_index(begin);
        unsafe { Dname::from_slice_unchecked(&self.0.as_ref()[begin..]) }
    }

    /// Returns the part of the name ending at the given position.
    ///
    /// The returned name will start at beginning of the name and continue
    /// until just before the given postion. The position `end` is considered
    /// as an index into the underlying octets sequence and must point to the
    /// beginning of a label.
    ///
    /// The method returns a reference to an unsized domain name and
    /// is thus best suited for temporary referencing. If you want to keep the
    /// part of the name around, [`range_to`] is likely a better choice.
    ///
    /// # Panics
    ///
    /// The method panics if `end` is not the beginning of a label or is out
    /// of bounds. Because the returned domain name is relative, the method
    /// will also panic if the end is equal to the length of the name.
    ///
    /// [`range_to`]: #method.range_to
    pub fn slice_to(&self, end: usize) -> &RelativeDname<[u8]> {
        self.check_index(end);
        unsafe {
            RelativeDname::from_slice_unchecked(&self.0.as_ref()[..end])
        }
    }

    /// Returns the part of the name indicated by start and end positions.
    ///
    /// The returned name will start at position `begin` and end right before
    /// position `end`. Both positions are given as indexes into the
    /// underlying octets sequence and must point to the begining of a label.
    ///
    /// # Panics
    ///
    /// The method panics if either position is not the start of a label or
    /// is out of bounds.
    ///
    /// Because the returned domain name is relative, the method will also
    /// panic if the end is equal to the length of the name. If you
    /// want to slice the entire end of the name including the final root
    /// label, you can use [`range_from()`] instead.
    ///
    /// [`range_from()`]: #method.range_from
    pub fn range<'a>(
        &'a self,
        begin: usize,
        end: usize,
    ) -> RelativeDname<<&'a Octets as OctetsRef>::Range>
    where
        &'a Octets: OctetsRef,
    {
        self.check_index(begin);
        self.check_index(end);
        unsafe {
            RelativeDname::from_octets_unchecked(self.0.range(begin, end))
        }
    }

    /// Returns the part of the name starting at the given position.
    ///
    /// The returned name will start at the given postion and cover the
    /// remainder of the name. The position `begin` is provided as an index
    /// into the underlying octets sequence and must point to the beginning
    /// of a label.
    ///
    /// # Panics
    ///
    /// The method panics if `begin` isn’t the index of the beginning of a
    /// label or is out of bounds.
    pub fn range_from<'a>(
        &'a self,
        begin: usize,
    ) -> Dname<<&'a Octets as OctetsRef>::Range>
    where
        &'a Octets: OctetsRef,
    {
        self.check_index(begin);
        unsafe { Dname::from_octets_unchecked(self.0.range_from(begin)) }
    }

    /// Returns the part of the name ending at the given position.
    ///
    /// The returned name will start at beginning of the name and continue
    /// until just before the given postion. The position `end` is considered
    /// as an index into the underlying octets sequence and must point to the
    /// beginning of a label.
    ///
    /// # Panics
    ///
    /// The method panics if `end` is not the beginning of a label or is out
    /// of bounds. Because the returned domain name is relative, the method
    /// will also panic if the end is equal to the length of the name.
    pub fn range_to<'a>(
        &'a self,
        end: usize,
    ) -> RelativeDname<<&'a Octets as OctetsRef>::Range>
    where
        &'a Octets: OctetsRef,
    {
        self.check_index(end);
        unsafe { RelativeDname::from_octets_unchecked(self.0.range_to(end)) }
    }
}

impl<Octets: AsRef<[u8]>> Dname<Octets> {
    /// Splits the name into two at the given position.
    ///
    /// Returns a pair of the left and right part of the split name.
    ///
    /// # Panics
    ///
    /// The method will panic if `mid` is not the index of the beginning of
    /// a label or if it is out of bounds.
    pub fn split_at(mut self, mid: usize) -> (RelativeDname<Octets>, Self)
    where
        for<'a> &'a Octets: OctetsRef<Range = Octets>,
    {
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
    pub fn split_to(&mut self, mid: usize) -> RelativeDname<Octets>
    where
        for<'a> &'a Octets: OctetsRef<Range = Octets>,
    {
        self.check_index(mid);
        let res = self.0.range_to(mid);
        self.0 = self.0.range_from(mid);
        unsafe { RelativeDname::from_octets_unchecked(res) }
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
    pub fn truncate(mut self, len: usize) -> RelativeDname<Octets>
    where
        Octets: OctetsExt,
    {
        self.check_index(len);
        self.0.truncate(len);
        unsafe { RelativeDname::from_octets_unchecked(self.0) }
    }

    /// Splits off the first label.
    ///
    /// If this name is longer than just the root label, returns the first
    /// label as a relative name and removes it from the name itself. If the
    /// name is only the root label, returns `None` and does nothing.
    pub fn split_first(&mut self) -> Option<RelativeDname<Octets>>
    where
        for<'a> &'a Octets: OctetsRef<Range = Octets>,
    {
        if self.len() == 1 {
            return None;
        }
        let end = self.iter().next().unwrap().len() + 1;
        Some(self.split_to(end))
    }

    /// Reduces the name to the parent of the current name.
    ///
    /// If the name consists of the root label only, returns `false` and does
    /// nothing. Otherwise, drops the first label and returns `true`.
    pub fn parent(&mut self) -> bool
    where
        for<'a> &'a Octets: OctetsRef<Range = Octets>,
    {
        self.split_first().is_some()
    }

    /// Strips the suffix `base` from the domain name.
    ///
    /// If `base` is indeed a suffix, returns a relative domain name with the
    /// remainder of the name. Otherwise, returns an error with an unmodified
    /// `self`.
    pub fn strip_suffix<N: ToDname + ?Sized>(
        self,
        base: &N,
    ) -> Result<RelativeDname<Octets>, Self>
    where
        Octets: OctetsExt,
    {
        if self.ends_with(base) {
            let len = self.0.as_ref().len() - base.len();
            Ok(self.truncate(len))
        } else {
            Err(self)
        }
    }
}

//--- Deref and AsRef

impl<Octets: ?Sized> ops::Deref for Dname<Octets> {
    type Target = Octets;

    fn deref(&self) -> &Octets {
        &self.0
    }
}

impl<Octets: AsRef<T> + ?Sized, T: ?Sized> AsRef<T> for Dname<Octets> {
    fn as_ref(&self) -> &T {
        self.0.as_ref()
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets> OctetsFrom<Dname<SrcOctets>> for Dname<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: Dname<SrcOctets>) -> Result<Self, ShortBuf> {
        Octets::octets_from(source.0)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

//--- FromStr

impl<Octets> FromStr for Dname<Octets>
where
    Octets: FromBuilder,
    <Octets as FromBuilder>::Builder: EmptyBuilder,
{
    type Err = FromStrError;

    /// Parses a string into an absolute domain name.
    ///
    /// The implementation assumes that the string refers to an absolute name
    /// whether it ends in a dot or not. If you need to be able to distinguish
    /// between those two cases, you can use [`UncertainDname`] instead.
    ///
    /// [`UncertainDname`]: struct.UncertainDname.html
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_chars(s.chars())
    }
}

//--- PartialEq, and Eq

impl<Octets, N> PartialEq<N> for Dname<Octets>
where
    Octets: AsRef<[u8]> + ?Sized,
    N: ToDname + ?Sized,
{
    fn eq(&self, other: &N) -> bool {
        self.name_eq(other)
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> Eq for Dname<Octets> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<Octets, N> PartialOrd<N> for Dname<Octets>
where
    Octets: AsRef<[u8]> + ?Sized,
    N: ToDname + ?Sized,
{
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

impl<Octets: AsRef<[u8]> + ?Sized> Ord for Dname<Octets> {
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

impl<Octets, N> CanonicalOrd<N> for Dname<Octets>
where
    Octets: AsRef<[u8]> + ?Sized,
    N: ToDname + ?Sized,
{
    fn canonical_cmp(&self, other: &N) -> cmp::Ordering {
        self.name_cmp(other)
    }
}

//--- Hash

impl<Octets: AsRef<[u8]> + ?Sized> hash::Hash for Dname<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}

//--- ToLabelIter and ToDname

impl<'a, Octets> ToLabelIter<'a> for Dname<Octets>
where
    Octets: AsRef<[u8]> + ?Sized,
{
    type LabelIter = DnameIter<'a>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        self.iter()
    }

    fn len(&self) -> usize {
        self.0.as_ref().len()
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> ToDname for Dname<Octets> {
    fn as_flat_slice(&self) -> Option<&[u8]> {
        Some(self.0.as_ref())
    }
}

//--- IntoIterator

impl<'a, Octets> IntoIterator for &'a Dname<Octets>
where
    Octets: AsRef<[u8]> + ?Sized,
{
    type Item = &'a Label;
    type IntoIter = DnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Dname<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = name_len(parser)?;
        Ok(unsafe { Self::from_octets_unchecked(parser.parse_octets(len)?) })
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        let len = name_len(parser)?;
        parser.advance(len).map_err(Into::into)
    }
}

fn name_len<Source: AsRef<[u8]>>(
    parser: &mut Parser<Source>,
) -> Result<usize, ParseError> {
    let len = {
        let mut tmp = parser.peek_all();
        loop {
            if tmp.is_empty() {
                return Err(ParseError::ShortInput);
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
    } else {
        Ok(len)
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> Compose for Dname<Octets> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(self.0.as_ref())
    }

    fn compose_canonical<T: OctetsBuilder>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            for label in self.iter_labels() {
                label.compose_canonical(target)?;
            }
            Ok(())
        })
    }
}

//--- Scan and Display

#[cfg(feature = "master")]
impl Scan for Dname<Bytes> {
    fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, ScanError> {
        let pos = scanner.pos();
        let name = match UncertainDname::scan(scanner)? {
            UncertainDname::Relative(name) => name,
            UncertainDname::Absolute(name) => return Ok(name),
        };
        let origin = match *scanner.origin() {
            Some(ref origin) => origin,
            None => return Err((SyntaxError::NoOrigin, pos).into()),
        };
        name.into_builder()
            .append_origin(origin)
            .map_err(|err| (SyntaxError::from(err), pos).into())
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> fmt::Display for Dname<Octets> {
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

impl<Octets: AsRef<[u8]> + ?Sized> fmt::Debug for Dname<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Dname({}.)", self)
    }
}

//------------ SuffixIter ----------------------------------------------------

/// An iterator over ever shorter suffixes of a domain name.
#[derive(Clone)]
pub struct SuffixIter<Ref> {
    name: Dname<Ref>,
    start: Option<usize>,
}

impl<Ref> SuffixIter<Ref> {
    /// Creates a new iterator cloning `name`.
    fn new(name: Dname<Ref>) -> Self {
        SuffixIter {
            name,
            start: Some(0),
        }
    }
}

impl<Ref: OctetsRef> Iterator for SuffixIter<Ref> {
    type Item = Dname<Ref::Range>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = match self.start {
            Some(start) => start,
            None => return None,
        };
        let res = self.name.range_from(start);
        let label = res.first();
        if label.is_root() {
            self.start = None;
        } else {
            self.start = Some(start + label.compose_len())
        }
        Some(res)
    }
}

//============ Error Types ===================================================

//------------ DnameError ----------------------------------------------------

/// A domain name wasn’t encoded correctly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnameError {
    /// The encoding contained an unknown or disallowed label type.
    BadLabel(LabelTypeError),

    /// The encoding contained a compression pointer.
    CompressedName,

    /// The name was longer than 255 octets.
    LongName,

    /// The name did not end with the root label.
    RelativeName,

    /// There was more data after the root label was encountered.
    TrailingData,

    /// The input ended in the middle of a label.
    ShortInput,
}

//--- From

impl From<LabelTypeError> for DnameError {
    fn from(err: LabelTypeError) -> DnameError {
        DnameError::BadLabel(err)
    }
}

impl From<SplitLabelError> for DnameError {
    fn from(err: SplitLabelError) -> DnameError {
        match err {
            SplitLabelError::Pointer(_) => DnameError::CompressedName,
            SplitLabelError::BadType(t) => DnameError::BadLabel(t),
            SplitLabelError::ShortInput => DnameError::ShortInput,
        }
    }
}

impl From<DnameError> for FormError {
    fn from(err: DnameError) -> FormError {
        FormError::new(match err {
            DnameError::BadLabel(_) => "unknown label type",
            DnameError::CompressedName => "compressed domain name",
            DnameError::LongName => "long domain name",
            DnameError::RelativeName => "relative domain name",
            DnameError::TrailingData => "trailing data in buffer",
            DnameError::ShortInput => "unexpected end of buffer",
        })
    }
}

impl From<DnameError> for ParseError {
    fn from(err: DnameError) -> ParseError {
        match err {
            DnameError::ShortInput => ParseError::ShortInput,
            other => ParseError::Form(other.into()),
        }
    }
}

//--- Display and Error

impl fmt::Display for DnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DnameError::BadLabel(ref err) => err.fmt(f),
            DnameError::CompressedName => {
                f.write_str("compressed domain name")
            }
            DnameError::LongName => f.write_str("long domain name"),
            DnameError::RelativeName => f.write_str("relative name"),
            DnameError::TrailingData => f.write_str("trailing data"),
            DnameError::ShortInput => ParseError::ShortInput.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for DnameError {}

//============ Testing =======================================================
//
// Some of the helper functions herein are resused by the tests of other
// sub-modules of ::bits::name. Hence the `pub(crate)` designation.

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    #[cfg(feature = "std")]
    macro_rules! assert_panic {
        ( $cond:expr ) => {{
            let result = std::panic::catch_unwind(|| $cond);
            assert!(result.is_err());
        }};
    }

    #[test]
    fn impls() {
        fn assert_to_dname<T: ToDname + ?Sized>(_: &T) {}

        assert_to_dname(Dname::from_slice(b"\0".as_ref()).unwrap());
        assert_to_dname(&Dname::from_octets(b"\0").unwrap());
        assert_to_dname(&Dname::from_octets(b"\0".as_ref()).unwrap());

        #[cfg(feature = "std")]
        {
            assert_to_dname(
                &Dname::from_octets(Vec::from(b"\0".as_ref())).unwrap(),
            );
        }
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn impls_bytes() {
        fn assert_to_dname<T: ToDname + ?Sized>(_: &T) {}

        assert_to_dname(
            &Dname::from_octets(Bytes::from(b"\0".as_ref())).unwrap(),
        );
    }

    #[test]
    fn root() {
        assert_eq!(Dname::root_ref().as_slice(), b"\0");
        #[cfg(feature = "std")]
        {
            assert_eq!(Dname::root_vec().as_slice(), b"\0");
        }
        assert_eq!(Dname::root_slice().as_slice(), b"\0");
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn root_bytes() {
        assert_eq!(Dname::root_bytes().as_slice(), b"\0");
    }

    #[test]
    #[cfg(feature = "std")]
    fn from_slice() {
        // a simple good name
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .as_slice(),
            b"\x03www\x07example\x03com\0"
        );

        // relative name
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com"),
            Err(DnameError::RelativeName)
        );

        // bytes shorter than what label length says.
        assert_eq!(
            Dname::from_slice(b"\x03www\x07exa"),
            Err(DnameError::ShortInput)
        );

        // label 63 long ok, 64 bad.
        let mut slice = [0u8; 65];
        slice[0] = 63;
        assert!(Dname::from_slice(&slice[..]).is_ok());
        let mut slice = [0u8; 66];
        slice[0] = 64;
        assert!(Dname::from_slice(&slice[..]).is_err());

        // name 255 long ok, 256 bad.
        let mut buf = std::vec::Vec::new();
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
        assert_eq!(
            Dname::from_slice(b"\xa2asdasds"),
            Err(LabelTypeError::Undefined.into())
        );
        assert_eq!(
            Dname::from_slice(b"\x62asdasds"),
            Err(LabelTypeError::Extended(0x62).into())
        );
        assert_eq!(
            Dname::from_slice(b"\xccasdasds"),
            Err(DnameError::CompressedName.into())
        );

        // empty input
        assert_eq!(Dname::from_slice(b""), Err(DnameError::ShortInput));
    }

    // `Dname::from_chars` is covered in the `FromStr` test.
    //
    // No tests for the simple conversion methods because, well, simple.

    #[test]
    fn into_relative() {
        assert_eq!(
            Dname::from_octets(b"\x03www\0".as_ref())
                .unwrap()
                .into_relative()
                .as_slice(),
            b"\x03www"
        );
    }

    #[test]
    fn is_root() {
        assert_eq!(Dname::from_slice(b"\0").unwrap().is_root(), true);
        assert_eq!(Dname::from_slice(b"\x03www\0").unwrap().is_root(), false);
        assert_eq!(Dname::root_ref().is_root(), true);
    }

    pub fn cmp_iter<I>(mut iter: I, labels: &[&[u8]])
    where
        I: Iterator,
        I::Item: AsRef<[u8]>,
    {
        let mut labels = labels.iter();
        loop {
            match (iter.next(), labels.next()) {
                (Some(left), Some(right)) => {
                    assert_eq!(left.as_ref(), *right)
                }
                (None, None) => break,
                (_, None) => panic!("extra items in iterator"),
                (None, _) => panic!("missing items in iterator"),
            }
        }
    }

    #[test]
    fn iter() {
        cmp_iter(Dname::root_ref().iter(), &[b""]);
        cmp_iter(
            Dname::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .iter(),
            &[b"www", b"example", b"com", b""],
        );
    }

    pub fn cmp_iter_back<I>(mut iter: I, labels: &[&[u8]])
    where
        I: DoubleEndedIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut labels = labels.iter();
        loop {
            match (iter.next_back(), labels.next()) {
                (Some(left), Some(right)) => {
                    assert_eq!(left.as_ref(), *right)
                }
                (None, None) => break,
                (_, None) => panic!("extra items in iterator"),
                (None, _) => panic!("missing items in iterator"),
            }
        }
    }

    #[test]
    fn iter_back() {
        cmp_iter_back(Dname::root_ref().iter(), &[b""]);
        cmp_iter_back(
            Dname::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .iter(),
            &[b"", b"com", b"example", b"www"],
        );
    }

    #[test]
    fn iter_suffixes() {
        cmp_iter(Dname::root_ref().iter_suffixes(), &[b"\0"]);
        cmp_iter(
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap()
                .iter_suffixes(),
            &[
                b"\x03www\x07example\x03com\0",
                b"\x07example\x03com\0",
                b"\x03com\0",
                b"\0",
            ],
        );
    }

    #[test]
    fn label_count() {
        assert_eq!(Dname::root_ref().label_count(), 1);
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .label_count(),
            4
        );
    }

    #[test]
    fn first() {
        assert_eq!(Dname::root_ref().first().as_slice(), b"");
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .first()
                .as_slice(),
            b"www"
        );
    }

    #[test]
    fn last() {
        assert_eq!(Dname::root_ref().last().as_slice(), b"");
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .last()
                .as_slice(),
            b""
        );
    }

    #[test]
    fn starts_with() {
        let root = Dname::root_ref();
        let wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap();

        assert!(root.starts_with(&root));
        assert!(wecr.starts_with(&wecr));

        assert!(root.starts_with(&RelativeDname::empty_ref()));
        assert!(wecr.starts_with(&RelativeDname::empty_ref()));

        let test = RelativeDname::from_slice(b"\x03www").unwrap();
        assert!(!root.starts_with(&test));
        assert!(wecr.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x03www\x07example").unwrap();
        assert!(!root.starts_with(&test));
        assert!(wecr.starts_with(&test));

        let test =
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap();
        assert!(!root.starts_with(&test));
        assert!(wecr.starts_with(&test));

        let test = RelativeDname::from_slice(b"\x07example\x03com").unwrap();
        assert!(!root.starts_with(&test));
        assert!(!wecr.starts_with(&test));

        let test = RelativeDname::from_octets(b"\x03www".as_ref())
            .unwrap()
            .chain(
                RelativeDname::from_octets(b"\x07example".as_ref()).unwrap(),
            )
            .unwrap();
        assert!(!root.starts_with(&test));
        assert!(wecr.starts_with(&test));

        let test = test
            .chain(RelativeDname::from_octets(b"\x03com".as_ref()).unwrap())
            .unwrap();
        assert!(!root.starts_with(&test));
        assert!(wecr.starts_with(&test));
    }

    #[test]
    fn ends_with() {
        let root = Dname::root_ref();
        let wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap();

        for name in wecr.iter_suffixes() {
            if name.is_root() {
                assert!(root.ends_with(&name));
            } else {
                assert!(!root.ends_with(&name));
            }
            assert!(wecr.ends_with(&name));
        }
    }

    #[test]
    fn is_label_start() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert!(wecr.is_label_start(0)); // \x03
        assert!(!wecr.is_label_start(1)); // w
        assert!(!wecr.is_label_start(2)); // w
        assert!(!wecr.is_label_start(3)); // w
        assert!(wecr.is_label_start(4)); // \x07
        assert!(!wecr.is_label_start(5)); // e
        assert!(!wecr.is_label_start(6)); // x
        assert!(!wecr.is_label_start(7)); // a
        assert!(!wecr.is_label_start(8)); // m
        assert!(!wecr.is_label_start(9)); // p
        assert!(!wecr.is_label_start(10)); // l
        assert!(!wecr.is_label_start(11)); // e
        assert!(wecr.is_label_start(12)); // \x03
        assert!(!wecr.is_label_start(13)); // c
        assert!(!wecr.is_label_start(14)); // o
        assert!(!wecr.is_label_start(15)); // m
        assert!(wecr.is_label_start(16)); // \0
        assert!(!wecr.is_label_start(17)); //
        assert!(!wecr.is_label_start(18)); //
    }

    #[test]
    #[cfg(feature = "std")]
    fn slice() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.slice(0, 4).as_slice(), b"\x03www");
        assert_eq!(wecr.slice(0, 12).as_slice(), b"\x03www\x07example");
        assert_eq!(wecr.slice(4, 12).as_slice(), b"\x07example");
        assert_eq!(wecr.slice(4, 16).as_slice(), b"\x07example\x03com");

        assert_panic!(wecr.slice(0, 3));
        assert_panic!(wecr.slice(1, 4));
        assert_panic!(wecr.slice(0, 11));
        assert_panic!(wecr.slice(1, 12));
        assert_panic!(wecr.slice(0, 17));
        assert_panic!(wecr.slice(4, 17));
        assert_panic!(wecr.slice(0, 18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn slice_from() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(
            wecr.slice_from(0).as_slice(),
            b"\x03www\x07example\x03com\0"
        );
        assert_eq!(wecr.slice_from(4).as_slice(), b"\x07example\x03com\0");
        assert_eq!(wecr.slice_from(12).as_slice(), b"\x03com\0");
        assert_eq!(wecr.slice_from(16).as_slice(), b"\0");

        assert_panic!(wecr.slice_from(17));
        assert_panic!(wecr.slice_from(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn slice_to() {
        let wecr = Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.slice_to(0).as_slice(), b"");
        assert_eq!(wecr.slice_to(4).as_slice(), b"\x03www");
        assert_eq!(wecr.slice_to(12).as_slice(), b"\x03www\x07example");
        assert_eq!(
            wecr.slice_to(16).as_slice(),
            b"\x03www\x07example\x03com"
        );

        assert_panic!(wecr.slice_to(17));
        assert_panic!(wecr.slice_to(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn range() {
        let wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap();

        assert_eq!(wecr.range(0, 4).as_slice(), b"\x03www");
        assert_eq!(wecr.range(0, 12).as_slice(), b"\x03www\x07example");
        assert_eq!(wecr.range(4, 12).as_slice(), b"\x07example");
        assert_eq!(wecr.range(4, 16).as_slice(), b"\x07example\x03com");

        assert_panic!(wecr.range(0, 3));
        assert_panic!(wecr.range(1, 4));
        assert_panic!(wecr.range(0, 11));
        assert_panic!(wecr.range(1, 12));
        assert_panic!(wecr.range(0, 17));
        assert_panic!(wecr.range(4, 17));
        assert_panic!(wecr.range(0, 18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn range_from() {
        let wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap();

        assert_eq!(
            wecr.range_from(0).as_slice(),
            b"\x03www\x07example\x03com\0"
        );
        assert_eq!(wecr.range_from(4).as_slice(), b"\x07example\x03com\0");
        assert_eq!(wecr.range_from(12).as_slice(), b"\x03com\0");
        assert_eq!(wecr.range_from(16).as_slice(), b"\0");

        assert_panic!(wecr.range_from(17));
        assert_panic!(wecr.range_from(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn range_to() {
        let wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap();

        assert_eq!(wecr.range_to(0).as_slice(), b"");
        assert_eq!(wecr.range_to(4).as_slice(), b"\x03www");
        assert_eq!(wecr.range_to(12).as_slice(), b"\x03www\x07example");
        assert_eq!(
            wecr.range_to(16).as_slice(),
            b"\x03www\x07example\x03com"
        );

        assert_panic!(wecr.range_to(17));
        assert_panic!(wecr.range_to(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn split_at() {
        let wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap();

        let (left, right) = wecr.clone().split_at(0);
        assert_eq!(left.as_slice(), b"");
        assert_eq!(right.as_slice(), b"\x03www\x07example\x03com\0");

        let (left, right) = wecr.clone().split_at(4);
        assert_eq!(left.as_slice(), b"\x03www");
        assert_eq!(right.as_slice(), b"\x07example\x03com\0");

        let (left, right) = wecr.clone().split_at(12);
        assert_eq!(left.as_slice(), b"\x03www\x07example");
        assert_eq!(right.as_slice(), b"\x03com\0");

        let (left, right) = wecr.clone().split_at(16);
        assert_eq!(left.as_slice(), b"\x03www\x07example\x03com");
        assert_eq!(right.as_slice(), b"\0");

        assert_panic!(wecr.clone().split_at(1));
        assert_panic!(wecr.clone().split_at(14));
        assert_panic!(wecr.clone().split_at(17));
        assert_panic!(wecr.clone().split_at(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn split_to() {
        let wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap();

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
    #[cfg(feature = "std")]
    fn truncate() {
        let wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap();

        assert_eq!(wecr.clone().truncate(0).as_slice(), b"");
        assert_eq!(wecr.clone().truncate(4).as_slice(), b"\x03www");
        assert_eq!(
            wecr.clone().truncate(12).as_slice(),
            b"\x03www\x07example"
        );
        assert_eq!(
            wecr.clone().truncate(16).as_slice(),
            b"\x03www\x07example\x03com"
        );

        assert_panic!(wecr.clone().truncate(1));
        assert_panic!(wecr.clone().truncate(14));
        assert_panic!(wecr.clone().truncate(17));
        assert_panic!(wecr.clone().truncate(18));
    }

    #[test]
    fn split_first() {
        let mut wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
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
        let mut wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
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
        let wecr =
            Dname::from_octets(b"\x03www\x07example\x03com\0".as_ref())
                .unwrap();
        let ecr =
            Dname::from_octets(b"\x07example\x03com\0".as_ref()).unwrap();
        let cr = Dname::from_octets(b"\x03com\0".as_ref()).unwrap();
        let wenr =
            Dname::from_octets(b"\x03www\x07example\x03net\0".as_ref())
                .unwrap();
        let enr =
            Dname::from_octets(b"\x07example\x03net\0".as_ref()).unwrap();
        let nr = Dname::from_octets(b"\x03net\0".as_ref()).unwrap();

        assert_eq!(wecr.clone().strip_suffix(&wecr).unwrap().as_slice(), b"");
        assert_eq!(
            wecr.clone().strip_suffix(&ecr).unwrap().as_slice(),
            b"\x03www"
        );
        assert_eq!(
            wecr.clone().strip_suffix(&cr).unwrap().as_slice(),
            b"\x03www\x07example"
        );
        assert_eq!(
            wecr.clone()
                .strip_suffix(&Dname::root_slice())
                .unwrap()
                .as_slice(),
            b"\x03www\x07example\x03com"
        );

        assert_eq!(
            wecr.clone().strip_suffix(&wenr).unwrap_err().as_slice(),
            b"\x03www\x07example\x03com\0"
        );
        assert_eq!(
            wecr.clone().strip_suffix(&enr).unwrap_err().as_slice(),
            b"\x03www\x07example\x03com\0"
        );
        assert_eq!(
            wecr.clone().strip_suffix(&nr).unwrap_err().as_slice(),
            b"\x03www\x07example\x03com\0"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn parse() {
        // Parse a correctly formatted name.
        let mut p = Parser::from_static(b"\x03www\x07example\x03com\0af");
        assert_eq!(
            Dname::parse(&mut p).unwrap().as_slice(),
            b"\x03www\x07example\x03com\0"
        );
        assert_eq!(p.peek_all(), b"af");

        // Short buffer in middle of label.
        let mut p = Parser::from_static(b"\x03www\x07exam");
        assert_eq!(Dname::parse(&mut p), Err(ParseError::ShortInput));

        // Short buffer at end of label.
        let mut p = Parser::from_static(b"\x03www\x07example");
        assert_eq!(Dname::parse(&mut p), Err(ParseError::ShortInput));

        // Compressed name.
        let mut p = Parser::from_static(b"\x03com\x03www\x07example\xc0\0");
        p.advance(4).unwrap();
        assert_eq!(
            Dname::parse(&mut p),
            Err(DnameError::CompressedName.into())
        );

        // Bad label header.
        let mut p = Parser::from_static(b"\x03www\x07example\xbffoo");
        assert!(Dname::parse(&mut p).is_err());

        // Long name: 255 bytes is fine.
        let mut buf = Vec::new();
        for _ in 0..50 {
            buf.extend_from_slice(b"\x041234");
        }
        buf.extend_from_slice(b"\x03123\0");
        assert_eq!(buf.len(), 255);
        let mut p = Parser::from_ref(buf.as_slice());
        assert!(Dname::parse(&mut p).is_ok());
        assert_eq!(p.peek_all(), b"");

        // Long name: 256 bytes are bad.
        let mut buf = Vec::new();
        for _ in 0..51 {
            buf.extend_from_slice(b"\x041234");
        }
        buf.extend_from_slice(b"\0");
        assert_eq!(buf.len(), 256);
        let mut p = Parser::from_ref(buf.as_slice());
        assert_eq!(Dname::parse(&mut p), Err(DnameError::LongName.into()));
    }

    // I don’t think we need tests for `Compose::compose` since it only
    // copies the underlying bytes.

    #[test]
    #[cfg(feature = "std")]
    fn compose_canonical() {
        let mut buf = Vec::new();
        Dname::from_slice(b"\x03wWw\x07exaMPle\x03com\0")
            .unwrap()
            .compose_canonical(&mut buf)
            .unwrap();
        assert_eq!(buf.as_slice(), b"\x03www\x07example\x03com\0");
    }

    #[test]
    #[cfg(feature = "std")]
    fn from_str() {
        // Another simple test. `DnameBuilder` does all the heavy lifting,
        // so we don’t need to test all the escape sequence shenanigans here.
        // Just check that we’ll always get a name, final dot or not, unless
        // the string is empty.
        use core::str::FromStr;
        use std::vec::Vec;

        assert_eq!(
            Dname::<Vec<u8>>::from_str("www.example.com")
                .unwrap()
                .as_slice(),
            b"\x03www\x07example\x03com\0"
        );
        assert_eq!(
            Dname::<Vec<u8>>::from_str("www.example.com.")
                .unwrap()
                .as_slice(),
            b"\x03www\x07example\x03com\0"
        );
    }

    #[test]
    fn eq() {
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap()
        );
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            Dname::from_slice(b"\x03wWw\x07eXAMple\x03Com\0").unwrap()
        );
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            &RelativeDname::from_octets(b"\x03www".as_ref())
                .unwrap()
                .chain(
                    RelativeDname::from_octets(
                        b"\x07example\x03com".as_ref()
                    )
                    .unwrap()
                )
                .unwrap()
                .chain(Dname::root_ref())
                .unwrap()
        );
        assert_eq!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            &RelativeDname::from_octets(b"\x03wWw".as_ref())
                .unwrap()
                .chain(
                    RelativeDname::from_octets(
                        b"\x07eXAMple\x03coM".as_ref()
                    )
                    .unwrap()
                )
                .unwrap()
                .chain(Dname::root_ref())
                .unwrap()
        );
        assert_ne!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            Dname::from_slice(b"\x03ww4\x07example\x03com\0").unwrap()
        );
        assert_ne!(
            Dname::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            &RelativeDname::from_octets(b"\x03www".as_ref())
                .unwrap()
                .chain(
                    RelativeDname::from_octets(
                        b"\x073xample\x03com".as_ref()
                    )
                    .unwrap()
                )
                .unwrap()
                .chain(Dname::root_ref())
                .unwrap()
        );
    }

    #[test]
    fn cmp() {
        use core::cmp::Ordering;

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
                let ord = if i < j {
                    Ordering::Less
                } else if i == j {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                };
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
    #[cfg(feature = "std")]
    fn hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut s1 = DefaultHasher::new();
        let mut s2 = DefaultHasher::new();
        Dname::from_slice(b"\x03www\x07example\x03com\0")
            .unwrap()
            .hash(&mut s1);
        Dname::from_slice(b"\x03wWw\x07eXAMple\x03Com\0")
            .unwrap()
            .hash(&mut s2);
        assert_eq!(s1.finish(), s2.finish());
    }

    // Scan and Display skipped for now.
}
