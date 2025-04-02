//! Uncompressed, absolute domain names.
//!
//! This is a private module. Its public types are re-exported by the parent.

use super::super::cmp::CanonicalOrd;
use super::super::net::IpAddr;
use super::super::scan::{Scanner, Symbol, SymbolCharsError, Symbols};
use super::super::wire::{FormError, ParseError};
use super::builder::{FromStrError, NameBuilder, PushError};
use super::label::{Label, LabelTypeError, SplitLabelError};
use super::relative::{NameIter, RelativeName};
use super::traits::{FlattenInto, ToLabelIter, ToName};
#[cfg(feature = "bytes")]
use bytes::Bytes;
use core::ops::{Bound, RangeBounds};
use core::str::FromStr;
use core::{borrow, cmp, fmt, hash, mem, str};
use octseq::builder::{
    EmptyBuilder, FreezeBuilder, FromBuilder, OctetsBuilder, Truncate,
};
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;
#[cfg(feature = "serde")]
use octseq::serde::{DeserializeOctets, SerializeOctets};
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ Name ----------------------------------------------------------

/// An uncompressed, absolute domain name.
///
/// The type wraps an octets sequence that contains an absolute domain name in
/// wire-format encoding. It provides an interface similar to a slice of the
/// labels of the name, i.e., you can iterate over the labels, split them off,
/// etc.
///
/// You can construct a domain name from a string via the [`FromStr`] trait or
/// manually via a [`NameBuilder`]. In addition, you can also parse it from
/// a message. This will, however, require the name to be uncompressed.
/// Otherwise, you would receive a [`ParsedName`] which can be converted into
/// [`Name`] via [`ToName::to_name`].
///
/// The canonical way to convert a domain name into its presentation format is
/// using [`to_string`] or by using its [`Display`] implementation (which
/// performs no allocations).
///
/// [`FromStr`]: std::str::FromStr
/// [`to_string`]: std::string::ToString::to_string
/// [`ParsedName`]: crate::base::name::ParsedName
/// [`Display`]: std::fmt::Display
#[derive(Clone)]
#[repr(transparent)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Name<Octs: ?Sized>(Octs);

impl Name<()> {
    /// Domain names have a maximum length of 255 octets.
    pub const MAX_LEN: usize = 255;
}

/// # Creating Values
///
impl<Octs> Name<Octs> {
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
    pub const unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        Self(octets)
    }

    /// Creates a domain name from an octet sequence.
    ///
    /// This will only succeed if `octets` contains a properly encoded
    /// absolute domain name in wire format. Because the function checks for
    /// correctness, this will take a wee bit of time.
    pub fn from_octets(octets: Octs) -> Result<Self, NameError>
    where
        Octs: AsRef<[u8]>,
    {
        Name::check_slice(octets.as_ref())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    pub fn from_symbols<Sym>(symbols: Sym) -> Result<Self, FromStrError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
            + FreezeBuilder<Octets = Octs>
            + AsRef<[u8]>
            + AsMut<[u8]>,
        Sym: IntoIterator<Item = Symbol>,
    {
        // NameBuilder can’t deal with a single dot, so we need to special
        // case that.
        let mut symbols = symbols.into_iter();
        let first = match symbols.next() {
            Some(first) => first,
            None => return Err(SymbolCharsError::short_input().into()),
        };
        if first == Symbol::Char('.') {
            if symbols.next().is_some() {
                return Err(FromStrError::empty_label());
            } else {
                // Make a root name.
                let mut builder =
                    <Octs as FromBuilder>::Builder::with_capacity(1);
                builder
                    .append_slice(b"\0")
                    .map_err(|_| FromStrError::ShortBuf)?;
                return Ok(unsafe {
                    Self::from_octets_unchecked(builder.freeze())
                });
            }
        }

        let mut builder = NameBuilder::<Octs::Builder>::new();
        builder.push_symbol(first)?;
        builder.append_symbols(symbols)?;
        builder.into_name().map_err(Into::into)
    }

    /// Creates a domain name from a sequence of characters.
    ///
    /// The sequence must result in a domain name in representation format.
    /// That is, its labels should be separated by dots.
    /// Actual dots, white space and backslashes should be escaped by a
    /// preceeding backslash, and any byte value that is not a printable
    /// ASCII character should be encoded by a backslash followed by its
    /// three digit decimal value.
    ///
    /// If Internationalized Domain Names are to be used, the labels already
    /// need to be in punycode-encoded form.
    ///
    /// The name will always be an absolute name. If the last character in the
    /// sequence is not a dot, the function will quietly add a root label,
    /// anyway. In most cases, this is likely what you want. If it isn’t,
    /// though, use [`UncertainName`] instead to be able to check.
    ///
    /// [`UncertainName`]: crate::base::name::UncertainName
    pub fn from_chars<C>(chars: C) -> Result<Self, FromStrError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
            + FreezeBuilder<Octets = Octs>
            + AsRef<[u8]>
            + AsMut<[u8]>,
        C: IntoIterator<Item = char>,
    {
        Symbols::with(chars.into_iter(), |symbols| {
            Self::from_symbols(symbols)
        })
    }

    /// Reads a name in presentation format from the beginning of a scanner.
    pub fn scan<S: Scanner<Name = Self>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        scanner.scan_name()
    }

    /// Returns a domain name consisting of the root label only.
    ///
    /// This function will work for any kind octets sequence that can be
    /// created from an octets slice. Since this will require providing the
    /// type parameter in some cases, there are shortcuts methods for specific
    /// octets types: [`root_ref`], [`root_vec`], and [`root_bytes`].
    ///
    /// [`root_ref`]: Name::root_ref
    /// [`root_vec`]: Name::root_vec
    /// [`root_bytes`]: Name::root_bytes
    #[must_use]
    pub fn root() -> Self
    where
        Octs: From<&'static [u8]>,
    {
        unsafe { Self::from_octets_unchecked(b"\0".as_ref().into()) }
    }

    /// Creates a domain name for reverse IP address lookup.
    ///
    /// The returned name will use the standard suffixes of `in-addr.arpa.`
    /// for IPv4 addresses and `ip6.arpa.` for IPv6.
    pub fn reverse_from_addr(addr: IpAddr) -> Result<Self, PushError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
            + FreezeBuilder<Octets = Octs>
            + AsRef<[u8]>
            + AsMut<[u8]>,
    {
        let mut builder =
            NameBuilder::<<Octs as FromBuilder>::Builder>::new();
        match addr {
            IpAddr::V4(addr) => {
                let [a, b, c, d] = addr.octets();
                builder.append_dec_u8_label(d)?;
                builder.append_dec_u8_label(c)?;
                builder.append_dec_u8_label(b)?;
                builder.append_dec_u8_label(a)?;
                builder.append_label(b"in-addr")?;
                builder.append_label(b"arpa")?;
            }
            IpAddr::V6(addr) => {
                for &item in addr.octets().iter().rev() {
                    builder.append_hex_digit_label(item)?;
                    builder.append_hex_digit_label(item >> 4)?;
                }
                builder.append_label(b"ip6")?;
                builder.append_label(b"arpa")?;
            }
        }
        builder.into_name()
    }
}

impl Name<[u8]> {
    /// Creates a domain name from an octet slice without checking,
    unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        // SAFETY: Name has repr(transparent)
        mem::transmute(slice)
    }

    /// Creates a domain name from an octets slice.
    ///
    /// Note that the input must be in wire format, as shown below.
    ///
    /// # Examples
    ///
    /// ```
    /// use domain::base::name::Name;
    /// Name::from_slice(b"\x07example\x03com\x00");
    /// ```
    ///
    /// # Errors
    ///
    /// This will only succeed if `slice` contains a properly encoded
    /// absolute domain name.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, NameError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Creates a domain name for the root label only atop an octets slice.
    #[must_use]
    pub fn root_slice() -> &'static Self {
        unsafe { Self::from_slice_unchecked("\0".as_ref()) }
    }

    /// Checks whether an octet slice contains a correctly encoded name.
    fn check_slice(mut slice: &[u8]) -> Result<(), NameError> {
        if slice.len() > Name::MAX_LEN {
            return Err(NameError(DnameErrorEnum::LongName));
        }
        loop {
            let (label, tail) = Label::split_from(slice)?;
            if label.is_root() {
                if tail.is_empty() {
                    break;
                } else {
                    return Err(NameError(DnameErrorEnum::TrailingData));
                }
            }
            if tail.is_empty() {
                return Err(NameError(DnameErrorEnum::RelativeName));
            }
            slice = tail;
        }
        Ok(())
    }
}

impl Name<&'static [u8]> {
    /// Creates a domain name for the root label only atop a slice reference.
    #[must_use]
    pub fn root_ref() -> Self {
        Self::root()
    }
}

#[cfg(feature = "std")]
impl Name<Vec<u8>> {
    /// Creates a domain name for the root label only atop a `Vec<u8>`.
    #[must_use]
    pub fn root_vec() -> Self {
        Self::root()
    }

    /// Creates a domain name atop a `Vec<u8>` from its string representation.
    pub fn vec_from_str(s: &str) -> Result<Self, FromStrError> {
        FromStr::from_str(s)
    }
}

#[cfg(feature = "bytes")]
impl Name<Bytes> {
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
impl<Octs: ?Sized> Name<Octs> {
    /// Returns a reference to the underlying octets sequence.
    ///
    /// These octets contain the domain name in wire format.
    pub fn as_octets(&self) -> &Octs {
        &self.0
    }

    /// Converts the domain name into the underlying octets sequence.
    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.0
    }

    /// Converts the name into a relative name by dropping the root label.
    pub fn into_relative(mut self) -> RelativeName<Octs>
    where
        Octs: Sized + AsRef<[u8]> + Truncate,
    {
        let len = self.0.as_ref().len() - 1;
        self.0.truncate(len);
        unsafe { RelativeName::from_octets_unchecked(self.0) }
    }

    /// Returns a domain name using a reference to the octets.
    pub fn for_ref(&self) -> Name<&Octs> {
        unsafe { Name::from_octets_unchecked(&self.0) }
    }

    /// Returns a reference to the underlying octets slice.
    ///
    /// The slice will contain the domain name in wire format.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    /// Returns a domain name for the octets slice of the content.
    pub fn for_slice(&self) -> &Name<[u8]>
    where
        Octs: AsRef<[u8]>,
    {
        unsafe { Name::from_slice_unchecked(self.0.as_ref()) }
    }

    /// Converts the domain name into its canonical form.
    ///
    /// This will convert all octets that are upper case ASCII characters
    /// into their lower case equivalent.
    pub fn make_canonical(&mut self)
    where
        Octs: AsMut<[u8]>,
    {
        Label::make_slice_canonical(self.0.as_mut());
    }
}

/// # Properties
///
impl<Octs: AsRef<[u8]> + ?Sized> Name<Octs> {
    /// Returns whether the name is the root label only.
    pub fn is_root(&self) -> bool {
        self.0.as_ref().len() == 1
    }

    /// Returns the length of the domain name.
    #[allow(clippy::len_without_is_empty)] // never empty ...
    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    /// Returns an object that displays the name with a final dot.
    ///
    /// The name itself displays without a final dot unless the name is the
    /// root label only. Because this means you can’t just unconditionally
    /// add a dot after the name, this method can be used to display the name
    /// always ending in a single dot.
    pub fn fmt_with_dot(&self) -> impl fmt::Display + '_ {
        ToName::fmt_with_dot(self)
    }
}

/// # Working with Labels
///
impl<Octs: AsRef<[u8]> + ?Sized> Name<Octs> {
    /// Returns an iterator over the labels of the domain name.
    pub fn iter(&self) -> NameIter {
        NameIter::new(self.0.as_ref())
    }

    /// Returns an iterator over the suffixes of the name.
    ///
    /// The returned iterator starts with the full name and then for each
    /// additional step returns a name with the left-most label stripped off
    /// until it reaches the root label.
    pub fn iter_suffixes(&self) -> SuffixIter<'_, Octs> {
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
    pub fn starts_with<'a, N: ToLabelIter + ?Sized>(
        &'a self,
        base: &'a N,
    ) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<'a, N: ToLabelIter + ?Sized>(
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

    /// Checks that a range starts and ends at label bounds.
    fn check_bounds(&self, bounds: &impl RangeBounds<usize>) {
        match bounds.start_bound().cloned() {
            Bound::Included(idx) => self.check_index(idx),
            Bound::Excluded(_) => {
                panic!("excluded lower bounds not supported");
            }
            Bound::Unbounded => {}
        }
        match bounds.end_bound().cloned() {
            Bound::Included(idx) => self
                .check_index(idx.checked_add(1).expect("end bound too big")),
            Bound::Excluded(idx) => self.check_index(idx),
            Bound::Unbounded => {
                panic!("unbounded end bound (results in absolute name)")
            }
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
    /// The method panics if either position is not the start of a label or is
    /// out of bounds.
    ///
    /// Because the returned domain name is relative, the method will also
    /// panic if the end is equal to the length of the name. If you want to
    /// slice the entire end of the name including the final root label, you
    /// can use [`slice_from`] instead.
    ///
    /// [`range`]: Name::range
    /// [`slice_from`]: Name::slice_from
    pub fn slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> &RelativeName<[u8]> {
        self.check_bounds(&range);
        unsafe {
            RelativeName::from_slice_unchecked(self.0.as_ref().range(range))
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
    /// [`range_from`]: Name::range_from
    pub fn slice_from(&self, begin: usize) -> &Name<[u8]> {
        self.check_index(begin);
        unsafe { Name::from_slice_unchecked(&self.0.as_ref()[begin..]) }
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
    /// label, you can use [`range_from`] instead.
    ///
    /// [`range_from`]: Name::range_from
    pub fn range(
        &self,
        range: impl RangeBounds<usize>,
    ) -> RelativeName<<Octs as Octets>::Range<'_>>
    where
        Octs: Octets,
    {
        self.check_bounds(&range);
        unsafe { RelativeName::from_octets_unchecked(self.0.range(range)) }
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
    pub fn range_from(
        &self,
        begin: usize,
    ) -> Name<<Octs as Octets>::Range<'_>>
    where
        Octs: Octets,
    {
        self.check_index(begin);
        unsafe { self.range_from_unchecked(begin) }
    }

    /// Returns the part of the name starting at a position without checking.
    unsafe fn range_from_unchecked(
        &self,
        begin: usize,
    ) -> Name<<Octs as Octets>::Range<'_>>
    where
        Octs: Octets,
    {
        Name::from_octets_unchecked(self.0.range(begin..))
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Name<Octs> {
    /// Splits the name into two at the given position.
    ///
    /// Returns a pair of the left and right part of the split name.
    ///
    /// # Panics
    ///
    /// The method will panic if `mid` is not the index of the beginning of
    /// a label or if it is out of bounds.
    pub fn split(
        &self,
        mid: usize,
    ) -> (RelativeName<Octs::Range<'_>>, Name<Octs::Range<'_>>)
    where
        Octs: Octets,
    {
        self.check_index(mid);
        unsafe {
            (
                RelativeName::from_octets_unchecked(self.0.range(..mid)),
                Name::from_octets_unchecked(self.0.range(mid..)),
            )
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
    pub fn truncate(mut self, len: usize) -> RelativeName<Octs>
    where
        Octs: Truncate + Sized,
    {
        self.check_index(len);
        self.0.truncate(len);
        unsafe { RelativeName::from_octets_unchecked(self.0) }
    }

    /// Splits off the first label.
    ///
    /// If this name is longer than just the root label, returns a pair
    /// of that label and the remaining name. If the name is only the root
    /// label, returns `None`.
    pub fn split_first(&self) -> Option<(&Label, Name<Octs::Range<'_>>)>
    where
        Octs: Octets,
    {
        if self.compose_len() == 1 {
            return None;
        }
        let label = self.iter().next().unwrap();
        Some((label, self.split(label.len() + 1).1))
    }

    /// Returns the parent of the current name.
    ///
    /// If the name consists of the root label only, returns `None`.
    pub fn parent(&self) -> Option<Name<Octs::Range<'_>>>
    where
        Octs: Octets,
    {
        self.split_first().map(|(_, parent)| parent)
    }

    /// Strips the suffix `base` from the domain name.
    ///
    /// If `base` is indeed a suffix, returns a relative domain name with the
    /// remainder of the name. Otherwise, returns an error with an unmodified
    /// `self`.
    pub fn strip_suffix<N: ToName + ?Sized>(
        self,
        base: &N,
    ) -> Result<RelativeName<Octs>, Self>
    where
        Octs: Truncate + Sized,
    {
        if self.ends_with(base) {
            let len = self.0.as_ref().len() - usize::from(base.compose_len());
            Ok(self.truncate(len))
        } else {
            Err(self)
        }
    }
}

impl<Octs> Name<Octs> {
    /// Reads a name in wire format from the beginning of a parser.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let len = Self::parse_name_len(parser)?;
        Ok(unsafe { Self::from_octets_unchecked(parser.parse_octets(len)?) })
    }

    /// Peeks at a parser and returns the length of a name at its beginning.
    fn parse_name_len<Source: AsRef<[u8]> + ?Sized>(
        parser: &Parser<Source>,
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
        if len > Name::MAX_LEN {
            Err(NameError(DnameErrorEnum::LongName).into())
        } else {
            Ok(len)
        }
    }
}

//--- AsRef

impl<Octs> AsRef<Octs> for Name<Octs> {
    fn as_ref(&self) -> &Octs {
        &self.0
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> AsRef<[u8]> for Name<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Name<SrcOcts>> for Name<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Name<SrcOcts>) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.0)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

//--- FromStr

impl<Octs> FromStr for Name<Octs>
where
    Octs: FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder
        + FreezeBuilder<Octets = Octs>
        + AsRef<[u8]>
        + AsMut<[u8]>,
{
    type Err = FromStrError;

    /// Parses a string into an absolute domain name.
    ///
    /// The name needs to be formatted in representation format, i.e., as a
    /// sequence of labels separated by dots. If Internationalized Domain
    /// Name (IDN) labels are to be used, these need to be given in punycode
    /// encoded form.
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

//--- FlattenInto

impl<Octs, Target> FlattenInto<Name<Target>> for Name<Octs>
where
    Target: OctetsFrom<Octs>,
{
    type AppendError = Target::Error;

    fn try_flatten_into(self) -> Result<Name<Target>, Self::AppendError> {
        Target::try_octets_from(self.0)
            .map(|octets| unsafe { Name::from_octets_unchecked(octets) })
    }
}

//--- PartialEq, and Eq

impl<Octs, N> PartialEq<N> for Name<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    N: ToName + ?Sized,
{
    fn eq(&self, other: &N) -> bool {
        self.name_eq(other)
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Eq for Name<Octs> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<Octs, N> PartialOrd<N> for Name<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    N: ToName + ?Sized,
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

impl<Octs: AsRef<[u8]> + ?Sized> Ord for Name<Octs> {
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

impl<Octs, N> CanonicalOrd<N> for Name<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    N: ToName + ?Sized,
{
    fn canonical_cmp(&self, other: &N) -> cmp::Ordering {
        self.name_cmp(other)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]> + ?Sized> hash::Hash for Name<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}

//--- ToLabelIter and ToName

impl<Octs> ToLabelIter for Name<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
{
    type LabelIter<'a>
        = NameIter<'a>
    where
        Octs: 'a;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        self.iter()
    }

    fn compose_len(&self) -> u16 {
        u16::try_from(self.0.as_ref().len()).expect("long domain name")
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> ToName for Name<Octs> {
    fn as_flat_slice(&self) -> Option<&[u8]> {
        Some(self.0.as_ref())
    }
}

//--- IntoIterator

impl<'a, Octs> IntoIterator for &'a Name<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
{
    type Item = &'a Label;
    type IntoIter = NameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- Display

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Display for Name<Octs> {
    /// Formats the domain name.
    ///
    /// This will produce the domain name in ‘common display format’ without
    /// the trailing dot with the exception of a root name which will be just
    /// a dot.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }

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

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Debug for Name<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Name({})", self.fmt_with_dot())
    }
}

//--- AsRef and Borrow

impl<Octs: AsRef<[u8]>> AsRef<Name<[u8]>> for Name<Octs> {
    fn as_ref(&self) -> &Name<[u8]> {
        self.for_slice()
    }
}

/// Borrow a domain name.
///
/// Containers holding an owned `Name<_>` may be queried with name over a
/// slice. This `Borrow<_>` impl supports user code querying containers with
/// compatible-but-different types like the following example:
///
/// ```
/// use std::collections::HashMap;
///
/// use domain::base::Name;
///
/// fn get_description(
///     hash: &HashMap<Name<Vec<u8>>, String>
/// ) -> Option<&str> {
///     let lookup_name: &Name<[u8]> =
///         Name::from_slice(b"\x03www\x07example\x03com\0").unwrap();
///     hash.get(lookup_name).map(|x| x.as_ref())
/// }
/// ```
impl<Octs: AsRef<[u8]>> borrow::Borrow<Name<[u8]>> for Name<Octs> {
    fn borrow(&self) -> &Name<[u8]> {
        self.for_slice()
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<Octs> serde::Serialize for Name<Octs>
where
    Octs: AsRef<[u8]> + SerializeOctets + ?Sized,
{
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer
                .serialize_newtype_struct("Name", &format_args!("{}", self))
        } else {
            serializer.serialize_newtype_struct(
                "Name",
                &self.0.as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octs> serde::Deserialize<'de> for Name<Octs>
where
    Octs: FromBuilder + DeserializeOctets<'de>,
    <Octs as FromBuilder>::Builder: FreezeBuilder<Octets = Octs>
        + EmptyBuilder
        + AsRef<[u8]>
        + AsMut<[u8]>,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octs> serde::de::Visitor<'de> for InnerVisitor<'de, Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder: FreezeBuilder<Octets = Octs>
                + EmptyBuilder
                + AsRef<[u8]>
                + AsMut<[u8]>,
        {
            type Value = Name<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an absolute domain name")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                Name::from_str(v).map_err(E::custom)
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    Name::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    Name::from_octets(octets).map_err(E::custom)
                })
            }
        }

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octs> serde::de::Visitor<'de> for NewtypeVisitor<Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder: EmptyBuilder
                + FreezeBuilder<Octets = Octs>
                + AsRef<[u8]>
                + AsMut<[u8]>,
        {
            type Value = Name<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an absolute domain name")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octs::visitor()))
                } else {
                    Octs::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octs::visitor()),
                    )
                }
            }
        }

        deserializer
            .deserialize_newtype_struct("Name", NewtypeVisitor(PhantomData))
    }
}

//------------ SuffixIter ----------------------------------------------------

/// An iterator over ever shorter suffixes of a domain name.
#[derive(Clone)]
pub struct SuffixIter<'a, Octs: ?Sized> {
    name: &'a Name<Octs>,
    start: Option<usize>,
}

impl<'a, Octs: ?Sized> SuffixIter<'a, Octs> {
    /// Creates a new iterator cloning `name`.
    fn new(name: &'a Name<Octs>) -> Self {
        SuffixIter {
            name,
            start: Some(0),
        }
    }
}

impl<'a, Octs: Octets + ?Sized> Iterator for SuffixIter<'a, Octs> {
    type Item = Name<Octs::Range<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        let start = self.start?;
        let res = unsafe { self.name.range_from_unchecked(start) };
        let label = res.first();
        if label.is_root() {
            self.start = None;
        } else {
            self.start = Some(start + usize::from(label.compose_len()))
        }
        Some(res)
    }
}

//============ Error Types ===================================================

//------------ NameError -----------------------------------------------------

/// A domain name wasn’t encoded correctly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NameError(DnameErrorEnum);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DnameErrorEnum {
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

impl From<LabelTypeError> for NameError {
    fn from(err: LabelTypeError) -> Self {
        Self(DnameErrorEnum::BadLabel(err))
    }
}

impl From<SplitLabelError> for NameError {
    fn from(err: SplitLabelError) -> Self {
        Self(match err {
            SplitLabelError::Pointer(_) => DnameErrorEnum::CompressedName,
            SplitLabelError::BadType(t) => DnameErrorEnum::BadLabel(t),
            SplitLabelError::ShortInput => DnameErrorEnum::ShortInput,
        })
    }
}

impl From<NameError> for FormError {
    fn from(err: NameError) -> FormError {
        FormError::new(match err.0 {
            DnameErrorEnum::BadLabel(_) => "unknown label type",
            DnameErrorEnum::CompressedName => "compressed domain name",
            DnameErrorEnum::LongName => "long domain name",
            DnameErrorEnum::RelativeName => "relative domain name",
            DnameErrorEnum::TrailingData => "trailing data in buffer",
            DnameErrorEnum::ShortInput => "unexpected end of buffer",
        })
    }
}

impl From<NameError> for ParseError {
    fn from(err: NameError) -> ParseError {
        match err.0 {
            DnameErrorEnum::ShortInput => ParseError::ShortInput,
            _ => ParseError::Form(err.into()),
        }
    }
}

//--- Display and Error

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            DnameErrorEnum::BadLabel(ref err) => err.fmt(f),
            DnameErrorEnum::CompressedName => {
                f.write_str("compressed domain name")
            }
            DnameErrorEnum::LongName => f.write_str("long domain name"),
            DnameErrorEnum::RelativeName => f.write_str("relative name"),
            DnameErrorEnum::TrailingData => f.write_str("trailing data"),
            DnameErrorEnum::ShortInput => ParseError::ShortInput.fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NameError {}

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
        fn assert_to_name<T: ToName + ?Sized>(_: &T) {}

        assert_to_name(Name::from_slice(b"\0".as_ref()).unwrap());
        assert_to_name(&Name::from_octets(b"\0").unwrap());
        assert_to_name(&Name::from_octets(b"\0".as_ref()).unwrap());

        #[cfg(feature = "std")]
        {
            assert_to_name(
                &Name::from_octets(Vec::from(b"\0".as_ref())).unwrap(),
            );
        }
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn impls_bytes() {
        fn assert_to_name<T: ToName + ?Sized>(_: &T) {}

        assert_to_name(
            &Name::from_octets(Bytes::from(b"\0".as_ref())).unwrap(),
        );
    }

    #[test]
    fn root() {
        assert_eq!(Name::root_ref().as_slice(), b"\0");
        #[cfg(feature = "std")]
        {
            assert_eq!(Name::root_vec().as_slice(), b"\0");
        }
        assert_eq!(Name::root_slice().as_slice(), b"\0");
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn root_bytes() {
        assert_eq!(Name::root_bytes().as_slice(), b"\0");
    }

    #[test]
    #[cfg(feature = "std")]
    fn from_slice() {
        // a simple good name
        assert_eq!(
            Name::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .as_slice(),
            b"\x03www\x07example\x03com\0"
        );

        // relative name
        assert_eq!(
            Name::from_slice(b"\x03www\x07example\x03com"),
            Err(NameError(DnameErrorEnum::RelativeName))
        );

        // bytes shorter than what label length says.
        assert_eq!(
            Name::from_slice(b"\x03www\x07exa"),
            Err(NameError(DnameErrorEnum::ShortInput))
        );

        // label 63 long ok, 64 bad.
        let mut slice = [0u8; 65];
        slice[0] = 63;
        assert!(Name::from_slice(&slice[..]).is_ok());
        let mut slice = [0u8; 66];
        slice[0] = 64;
        assert!(Name::from_slice(&slice[..]).is_err());

        // name 255 long ok, 256 bad.
        let mut buf = std::vec::Vec::new();
        for _ in 0..25 {
            buf.extend_from_slice(b"\x09123456789");
        }
        assert_eq!(buf.len(), 250);
        let mut tmp = buf.clone();
        tmp.extend_from_slice(b"\x03123\0");
        assert_eq!(Name::from_slice(&tmp).map(|_| ()), Ok(()));
        buf.extend_from_slice(b"\x041234\0");
        assert!(Name::from_slice(&buf).is_err());

        // trailing data
        assert!(Name::from_slice(b"\x03com\0\x03www\0").is_err());

        // bad label heads: compressed, other types.
        assert_eq!(
            Name::from_slice(b"\xa2asdasds"),
            Err(LabelTypeError::Undefined.into())
        );
        assert_eq!(
            Name::from_slice(b"\x62asdasds"),
            Err(LabelTypeError::Extended(0x62).into())
        );
        assert_eq!(
            Name::from_slice(b"\xccasdasds"),
            Err(NameError(DnameErrorEnum::CompressedName))
        );

        // empty input
        assert_eq!(
            Name::from_slice(b""),
            Err(NameError(DnameErrorEnum::ShortInput))
        );
    }

    #[test]
    fn test_dname_from_addr() {
        type TestName = Name<octseq::array::Array<128>>;

        assert_eq!(
            TestName::reverse_from_addr([192, 0, 2, 12].into()).unwrap(),
            TestName::from_str("12.2.0.192.in-addr.arpa").unwrap()
        );
        assert_eq!(
            TestName::reverse_from_addr(
                [0x2001, 0xdb8, 0x1234, 0x0, 0x5678, 0x1, 0x9abc, 0xdef]
                    .into()
            )
            .unwrap(),
            TestName::from_str(
                "f.e.d.0.c.b.a.9.1.0.0.0.8.7.6.5.\
                 0.0.0.0.4.3.2.1.8.b.d.0.1.0.0.2.\
                 ip6.arpa"
            )
            .unwrap()
        );
    }
    // `Name::from_chars` is covered in the `FromStr` test.
    //
    // No tests for the simple conversion methods because, well, simple.

    #[test]
    fn into_relative() {
        assert_eq!(
            Name::from_octets(b"\x03www\0".as_ref())
                .unwrap()
                .into_relative()
                .as_slice(),
            b"\x03www"
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn make_canonical() {
        let mut name = RelativeName::vec_from_str("wWw.exAmpLE.coM").unwrap();
        name.make_canonical();
        assert_eq!(
            name,
            RelativeName::from_octets(b"\x03www\x07example\x03com").unwrap()
        );
    }

    #[test]
    fn is_root() {
        assert!(Name::from_slice(b"\0").unwrap().is_root());
        assert!(!Name::from_slice(b"\x03www\0").unwrap().is_root());
        assert!(Name::root_ref().is_root());
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
        cmp_iter(Name::root_ref().iter(), &[b""]);
        cmp_iter(
            Name::from_slice(b"\x03www\x07example\x03com\0")
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
        cmp_iter_back(Name::root_ref().iter(), &[b""]);
        cmp_iter_back(
            Name::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .iter(),
            &[b"", b"com", b"example", b"www"],
        );
    }

    #[test]
    fn iter_suffixes() {
        cmp_iter(Name::root_ref().iter_suffixes(), &[b"\0"]);
        cmp_iter(
            Name::from_octets(b"\x03www\x07example\x03com\0".as_ref())
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
        assert_eq!(Name::root_ref().label_count(), 1);
        assert_eq!(
            Name::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .label_count(),
            4
        );
    }

    #[test]
    fn first() {
        assert_eq!(Name::root_ref().first().as_slice(), b"");
        assert_eq!(
            Name::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .first()
                .as_slice(),
            b"www"
        );
    }

    #[test]
    fn last() {
        assert_eq!(Name::root_ref().last().as_slice(), b"");
        assert_eq!(
            Name::from_slice(b"\x03www\x07example\x03com\0")
                .unwrap()
                .last()
                .as_slice(),
            b""
        );
    }

    #[test]
    fn starts_with() {
        let root = Name::root_ref();
        let wecr = Name::from_octets(b"\x03www\x07example\x03com\0".as_ref())
            .unwrap();

        assert!(root.starts_with(&root));
        assert!(wecr.starts_with(&wecr));

        assert!(root.starts_with(&RelativeName::empty_ref()));
        assert!(wecr.starts_with(&RelativeName::empty_ref()));

        let test = RelativeName::from_slice(b"\x03www").unwrap();
        assert!(!root.starts_with(&test));
        assert!(wecr.starts_with(&test));

        let test = RelativeName::from_slice(b"\x03www\x07example").unwrap();
        assert!(!root.starts_with(&test));
        assert!(wecr.starts_with(&test));

        let test =
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap();
        assert!(!root.starts_with(&test));
        assert!(wecr.starts_with(&test));

        let test = RelativeName::from_slice(b"\x07example\x03com").unwrap();
        assert!(!root.starts_with(&test));
        assert!(!wecr.starts_with(&test));

        let test = RelativeName::from_octets(b"\x03www".as_ref())
            .unwrap()
            .chain(
                RelativeName::from_octets(b"\x07example".as_ref()).unwrap(),
            )
            .unwrap();
        assert!(!root.starts_with(&test));
        assert!(wecr.starts_with(&test));

        let test = test
            .chain(RelativeName::from_octets(b"\x03com".as_ref()).unwrap())
            .unwrap();
        assert!(!root.starts_with(&test));
        assert!(wecr.starts_with(&test));
    }

    #[test]
    fn ends_with() {
        let root = Name::root_ref();
        let wecr = Name::from_octets(b"\x03www\x07example\x03com\0".as_ref())
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
        let wecr = Name::from_slice(b"\x03www\x07example\x03com\0").unwrap();

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
        let wecr = Name::from_slice(b"\x03www\x07example\x03com\0").unwrap();

        assert_eq!(wecr.slice(..4).as_slice(), b"\x03www");
        assert_eq!(wecr.slice(..12).as_slice(), b"\x03www\x07example");
        assert_eq!(wecr.slice(4..12).as_slice(), b"\x07example");
        assert_eq!(wecr.slice(4..16).as_slice(), b"\x07example\x03com");

        assert_panic!(wecr.slice(0..3));
        assert_panic!(wecr.slice(1..4));
        assert_panic!(wecr.slice(0..11));
        assert_panic!(wecr.slice(1..12));
        assert_panic!(wecr.slice(0..17));
        assert_panic!(wecr.slice(4..17));
        assert_panic!(wecr.slice(0..18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn slice_from() {
        let wecr = Name::from_slice(b"\x03www\x07example\x03com\0").unwrap();

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
    fn range() {
        let wecr = Name::from_octets(b"\x03www\x07example\x03com\0".as_ref())
            .unwrap();

        assert_eq!(wecr.range(0..4).as_slice(), b"\x03www");
        assert_eq!(wecr.range(0..12).as_slice(), b"\x03www\x07example");
        assert_eq!(wecr.range(4..12).as_slice(), b"\x07example");
        assert_eq!(wecr.range(4..16).as_slice(), b"\x07example\x03com");

        assert_panic!(wecr.range(0..3));
        assert_panic!(wecr.range(1..4));
        assert_panic!(wecr.range(0..11));
        assert_panic!(wecr.range(1..12));
        assert_panic!(wecr.range(0..17));
        assert_panic!(wecr.range(4..17));
        assert_panic!(wecr.range(0..18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn range_from() {
        let wecr = Name::from_octets(b"\x03www\x07example\x03com\0".as_ref())
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
    fn split() {
        let wecr = Name::from_octets(b"\x03www\x07example\x03com\0".as_ref())
            .unwrap();

        let (left, right) = wecr.split(0);
        assert_eq!(left.as_slice(), b"");
        assert_eq!(right.as_slice(), b"\x03www\x07example\x03com\0");

        let (left, right) = wecr.split(4);
        assert_eq!(left.as_slice(), b"\x03www");
        assert_eq!(right.as_slice(), b"\x07example\x03com\0");

        let (left, right) = wecr.split(12);
        assert_eq!(left.as_slice(), b"\x03www\x07example");
        assert_eq!(right.as_slice(), b"\x03com\0");

        let (left, right) = wecr.split(16);
        assert_eq!(left.as_slice(), b"\x03www\x07example\x03com");
        assert_eq!(right.as_slice(), b"\0");

        assert_panic!(wecr.split(1));
        assert_panic!(wecr.split(14));
        assert_panic!(wecr.split(17));
        assert_panic!(wecr.split(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn truncate() {
        let wecr = Name::from_octets(b"\x03www\x07example\x03com\0".as_ref())
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
        let wecr = Name::from_octets(b"\x03www\x07example\x03com\0".as_ref())
            .unwrap();

        let (label, wecr) = wecr.split_first().unwrap();
        assert_eq!(label, b"www".as_ref());
        assert_eq!(wecr.as_slice(), b"\x07example\x03com\0");

        let (label, wecr) = wecr.split_first().unwrap();
        assert_eq!(label, b"example");
        assert_eq!(wecr.as_slice(), b"\x03com\0");

        let (label, wecr) = wecr.split_first().unwrap();
        assert_eq!(label, b"com");
        assert_eq!(wecr.as_slice(), b"\0");
        assert!(wecr.split_first().is_none());
    }

    #[test]
    fn parent() {
        let wecr = Name::from_octets(b"\x03www\x07example\x03com\0".as_ref())
            .unwrap();

        let wecr = wecr.parent().unwrap();
        assert_eq!(wecr.as_slice(), b"\x07example\x03com\0");
        let wecr = wecr.parent().unwrap();
        assert_eq!(wecr.as_slice(), b"\x03com\0");
        let wecr = wecr.parent().unwrap();
        assert_eq!(wecr.as_slice(), b"\0");
        assert!(wecr.parent().is_none());
    }

    #[test]
    fn strip_suffix() {
        let wecr = Name::from_octets(b"\x03www\x07example\x03com\0".as_ref())
            .unwrap();
        let ecr =
            Name::from_octets(b"\x07example\x03com\0".as_ref()).unwrap();
        let cr = Name::from_octets(b"\x03com\0".as_ref()).unwrap();
        let wenr = Name::from_octets(b"\x03www\x07example\x03net\0".as_ref())
            .unwrap();
        let enr =
            Name::from_octets(b"\x07example\x03net\0".as_ref()).unwrap();
        let nr = Name::from_octets(b"\x03net\0".as_ref()).unwrap();

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
                .strip_suffix(&Name::root_slice())
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
            Name::parse(&mut p).unwrap().as_slice(),
            b"\x03www\x07example\x03com\0"
        );
        assert_eq!(p.peek_all(), b"af");

        // Short buffer in middle of label.
        let mut p = Parser::from_static(b"\x03www\x07exam");
        assert_eq!(Name::parse(&mut p), Err(ParseError::ShortInput));

        // Short buffer at end of label.
        let mut p = Parser::from_static(b"\x03www\x07example");
        assert_eq!(Name::parse(&mut p), Err(ParseError::ShortInput));

        // Compressed name.
        let mut p = Parser::from_static(b"\x03com\x03www\x07example\xc0\0");
        p.advance(4).unwrap();
        assert_eq!(
            Name::parse(&mut p),
            Err(NameError(DnameErrorEnum::CompressedName).into())
        );

        // Bad label header.
        let mut p = Parser::from_static(b"\x03www\x07example\xbffoo");
        assert!(Name::parse(&mut p).is_err());

        // Long name: 255 bytes is fine.
        let mut buf = Vec::new();
        for _ in 0..50 {
            buf.extend_from_slice(b"\x041234");
        }
        buf.extend_from_slice(b"\x03123\0");
        assert_eq!(buf.len(), 255);
        let mut p = Parser::from_ref(buf.as_slice());
        assert!(Name::parse(&mut p).is_ok());
        assert_eq!(p.peek_all(), b"");

        // Long name: 256 bytes are bad.
        let mut buf = Vec::new();
        for _ in 0..51 {
            buf.extend_from_slice(b"\x041234");
        }
        buf.extend_from_slice(b"\0");
        assert_eq!(buf.len(), 256);
        let mut p = Parser::from_ref(buf.as_slice());
        assert_eq!(
            Name::parse(&mut p),
            Err(NameError(DnameErrorEnum::LongName).into())
        );
    }

    // I don’t think we need tests for `Compose::compose` since it only
    // copies the underlying bytes.

    #[test]
    #[cfg(feature = "std")]
    fn compose_canonical() {
        use octseq::builder::infallible;

        let mut buf = Vec::new();
        infallible(
            Name::from_slice(b"\x03wWw\x07exaMPle\x03com\0")
                .unwrap()
                .compose_canonical(&mut buf),
        );
        assert_eq!(buf.as_slice(), b"\x03www\x07example\x03com\0");
    }

    #[test]
    #[cfg(feature = "std")]
    fn from_str() {
        // Another simple test. `NameBuilder` does all the heavy lifting,
        // so we don’t need to test all the escape sequence shenanigans here.
        // Just check that we’ll always get a name, final dot or not, unless
        // the string is empty.
        use core::str::FromStr;
        use std::vec::Vec;

        assert_eq!(Name::<Vec<u8>>::from_str(".").unwrap().as_slice(), b"\0");
        assert_eq!(
            Name::<Vec<u8>>::from_str("www.example.com")
                .unwrap()
                .as_slice(),
            b"\x03www\x07example\x03com\0"
        );
        assert_eq!(
            Name::<Vec<u8>>::from_str("www.example.com.")
                .unwrap()
                .as_slice(),
            b"\x03www\x07example\x03com\0"
        );
    }

    #[test]
    fn eq() {
        assert_eq!(
            Name::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            Name::from_slice(b"\x03www\x07example\x03com\0").unwrap()
        );
        assert_eq!(
            Name::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            Name::from_slice(b"\x03wWw\x07eXAMple\x03Com\0").unwrap()
        );
        assert_eq!(
            Name::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            &RelativeName::from_octets(b"\x03www".as_ref())
                .unwrap()
                .chain(
                    RelativeName::from_octets(b"\x07example\x03com".as_ref())
                        .unwrap()
                )
                .unwrap()
                .chain(Name::root_ref())
                .unwrap()
        );
        assert_eq!(
            Name::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            &RelativeName::from_octets(b"\x03wWw".as_ref())
                .unwrap()
                .chain(
                    RelativeName::from_octets(b"\x07eXAMple\x03coM".as_ref())
                        .unwrap()
                )
                .unwrap()
                .chain(Name::root_ref())
                .unwrap()
        );
        assert_ne!(
            Name::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            Name::from_slice(b"\x03ww4\x07example\x03com\0").unwrap()
        );
        assert_ne!(
            Name::from_slice(b"\x03www\x07example\x03com\0").unwrap(),
            &RelativeName::from_octets(b"\x03www".as_ref())
                .unwrap()
                .chain(
                    RelativeName::from_octets(b"\x073xample\x03com".as_ref())
                        .unwrap()
                )
                .unwrap()
                .chain(Name::root_ref())
                .unwrap()
        );
    }

    #[test]
    fn cmp() {
        use core::cmp::Ordering;

        // The following is taken from section 6.1 of RFC 4034.
        let names = [
            Name::from_slice(b"\x07example\0").unwrap(),
            Name::from_slice(b"\x01a\x07example\0").unwrap(),
            Name::from_slice(b"\x08yljkjljk\x01a\x07example\0").unwrap(),
            Name::from_slice(b"\x01Z\x01a\x07example\0").unwrap(),
            Name::from_slice(b"\x04zABC\x01a\x07example\0").unwrap(),
            Name::from_slice(b"\x01z\x07example\0").unwrap(),
            Name::from_slice(b"\x01\x01\x01z\x07example\0").unwrap(),
            Name::from_slice(b"\x01*\x01z\x07example\0").unwrap(),
            Name::from_slice(b"\x01\xc8\x01z\x07example\0").unwrap(),
        ];
        for i in 0..names.len() {
            for j in 0..names.len() {
                let ord = i.cmp(&j);
                assert_eq!(names[i].partial_cmp(names[j]), Some(ord));
                assert_eq!(names[i].cmp(names[j]), ord);
            }
        }

        let n1 = Name::from_slice(b"\x03www\x07example\x03com\0").unwrap();
        let n2 = Name::from_slice(b"\x03wWw\x07eXAMple\x03Com\0").unwrap();
        assert_eq!(n1.partial_cmp(n2), Some(Ordering::Equal));
        assert_eq!(n1.cmp(n2), Ordering::Equal);
    }

    #[test]
    #[cfg(feature = "std")]
    fn hash() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut s1 = DefaultHasher::new();
        let mut s2 = DefaultHasher::new();
        Name::from_slice(b"\x03www\x07example\x03com\0")
            .unwrap()
            .hash(&mut s1);
        Name::from_slice(b"\x03wWw\x07eXAMple\x03Com\0")
            .unwrap()
            .hash(&mut s2);
        assert_eq!(s1.finish(), s2.finish());
    }

    // Scan skipped for now.

    #[test]
    #[cfg(feature = "std")]
    fn display() {
        use std::string::ToString;

        fn cmp(bytes: &[u8], fmt: &str, fmt_with_dot: &str) {
            let name = Name::from_octets(bytes).unwrap();
            assert_eq!(name.to_string(), fmt);
            assert_eq!(format!("{}", name.fmt_with_dot()), fmt_with_dot);
        }

        cmp(b"\0", ".", ".");
        cmp(b"\x03com\0", "com", "com.");
        cmp(b"\x07example\x03com\0", "example.com", "example.com.");
    }

    #[cfg(all(feature = "serde", feature = "std"))]
    #[test]
    fn ser_de() {
        use serde_test::{assert_tokens, Configure, Token};

        let name = Name::<Vec<u8>>::from_str("www.example.com.").unwrap();
        assert_tokens(
            &name.clone().compact(),
            &[
                Token::NewtypeStruct { name: "Name" },
                Token::ByteBuf(b"\x03www\x07example\x03com\0"),
            ],
        );
        assert_tokens(
            &name.readable(),
            &[
                Token::NewtypeStruct { name: "Name" },
                Token::Str("www.example.com"),
            ],
        );
        assert_tokens(
            &Name::root_vec().readable(),
            &[Token::NewtypeStruct { name: "Name" }, Token::Str(".")],
        );
    }
}
