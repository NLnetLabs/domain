//! Uncompressed, relative domain names.
//!
//! This is a private module. Its public types are re-exported by the parent.

use super::super::wire::ParseError;
use super::absolute::Name;
use super::builder::{FromStrError, NameBuilder, PushError};
use super::chain::{Chain, LongChainError};
use super::label::{Label, LabelTypeError, SplitLabelError};
use super::traits::{ToLabelIter, ToRelativeName};
#[cfg(feature = "bytes")]
use bytes::Bytes;
use core::cmp::Ordering;
use core::ops::{Bound, RangeBounds};
use core::str::FromStr;
use core::{borrow, cmp, fmt, hash};
use octseq::builder::{
    EmptyBuilder, FreezeBuilder, FromBuilder, IntoBuilder, Truncate,
};
use octseq::octets::{Octets, OctetsFrom};
#[cfg(feature = "serde")]
use octseq::serde::{DeserializeOctets, SerializeOctets};
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ RelativeName --------------------------------------------------

/// An uncompressed, relative domain name.
///
/// A relative domain name is one that doesn’t end with the root label. As the
/// name suggests, it is relative to some other domain name. This type wraps
/// a octets sequence containing such a relative name similarly to the way
/// [`Name`] wraps an absolute one. In fact, it behaves very similarly to
/// [`Name`] taking into account differences when slicing and dicing names.
///
/// `RelativeName` guarantees that the name is at most 254 bytes long. As the
/// length limit for a domain name is actually 255 bytes, this means that you
/// can always safely turn a `RelativeName` into a `Name` by adding the root
/// label (which is exactly one byte long).
///
/// [`Bytes`]: ../../../bytes/struct.Bytes.html
/// [`Name`]: struct.Name.html
#[derive(Clone)]
pub struct RelativeName<Octs: ?Sized>(Octs);

/// # Creating Values
///
impl<Octs> RelativeName<Octs> {
    /// Creates a relative domain name from octets without checking.
    ///
    /// Since the content of the octets sequence can be anything, really,
    /// this is an unsafe function.
    ///
    /// # Safety
    ///
    /// The octets sequence passed via `octets` must contain a correctly
    /// encoded relative domain name. It must be at most 254 octets long.
    /// There must be no root labels anywhere in the name.
    pub const unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        RelativeName(octets)
    }

    /// Creates a relative domain name from an octets sequence.
    ///
    /// This checks that `octets` contains a properly encoded relative domain
    /// name and fails if it doesn’t.
    pub fn from_octets(octets: Octs) -> Result<Self, RelativeNameError>
    where
        Octs: AsRef<[u8]>,
    {
        RelativeName::check_slice(octets.as_ref())?;
        Ok(unsafe { RelativeName::from_octets_unchecked(octets) })
    }

    /// Creates an empty relative domain name.
    #[must_use]
    pub fn empty() -> Self
    where
        Octs: From<&'static [u8]>,
    {
        unsafe { RelativeName::from_octets_unchecked(b"".as_ref().into()) }
    }

    /// Creates a relative domain name representing the wildcard label.
    ///
    /// The wildcard label is intended to match any label. There are special
    /// rules for names with wildcard labels. Note that the comparison traits
    /// implemented for domain names do *not* consider wildcards and treat
    /// them as regular labels.
    #[must_use]
    pub fn wildcard() -> Self
    where
        Octs: From<&'static [u8]>,
    {
        unsafe {
            RelativeName::from_octets_unchecked(b"\x01*".as_ref().into())
        }
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
    pub fn from_chars<C>(chars: C) -> Result<Self, RelativeFromStrError>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
            + FreezeBuilder<Octets = Octs>
            + AsRef<[u8]>
            + AsMut<[u8]>,
        C: IntoIterator<Item = char>,
    {
        let mut builder = NameBuilder::<Octs::Builder>::new();
        builder.append_chars(chars)?;
        if builder.in_label() || builder.is_empty() {
            Ok(builder.finish())
        } else {
            Err(RelativeFromStrError::AbsoluteName)
        }
    }
}

impl RelativeName<[u8]> {
    /// Creates a domain name from an octet slice without checking.
    ///
    /// # Safety
    ///
    /// The same rules as for `from_octets_unchecked` apply.
    pub(super) unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        &*(slice as *const [u8] as *const RelativeName<[u8]>)
    }

    /// Creates a relative domain name from an octet slice.
    ///
    /// Note that the input must be in wire format, as shown below.
    ///
    /// # Example
    ///
    /// ```
    /// use domain::base::name::RelativeName;
    /// RelativeName::from_slice(b"\x0c_submissions\x04_tcp");
    /// ```
    pub fn from_slice(slice: &[u8]) -> Result<&Self, RelativeNameError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Returns an empty relative name atop a unsized slice.
    #[must_use]
    pub fn empty_slice() -> &'static Self {
        unsafe { Self::from_slice_unchecked(b"") }
    }

    #[must_use]
    pub fn wildcard_slice() -> &'static Self {
        unsafe { Self::from_slice_unchecked(b"\x01*") }
    }

    /// Checks whether an octet slice contains a correctly encoded name.
    pub(super) fn check_slice(
        mut slice: &[u8],
    ) -> Result<(), RelativeNameError> {
        if slice.len() > 254 {
            return Err(RelativeNameErrorEnum::LongName.into());
        }
        while !slice.is_empty() {
            let (label, tail) = Label::split_from(slice)?;
            if label.is_root() {
                return Err(RelativeNameErrorEnum::AbsoluteName.into());
            }
            slice = tail;
        }
        Ok(())
    }
}

impl RelativeName<&'static [u8]> {
    /// Creates an empty relative name atop a slice reference.
    #[must_use]
    pub fn empty_ref() -> Self {
        Self::empty()
    }

    /// Creates a wildcard relative name atop a slice reference.
    #[must_use]
    pub fn wildcard_ref() -> Self {
        Self::wildcard()
    }
}

#[cfg(feature = "std")]
impl RelativeName<Vec<u8>> {
    /// Creates an empty relative name atop a `Vec<u8>`.
    #[must_use]
    pub fn empty_vec() -> Self {
        Self::empty()
    }

    /// Creates a wildcard relative name atop a `Vec<u8>`.
    #[must_use]
    pub fn wildcard_vec() -> Self {
        Self::wildcard()
    }

    /// Parses a string into a relative name atop a `Vec<u8>`.
    pub fn vec_from_str(s: &str) -> Result<Self, RelativeFromStrError> {
        FromStr::from_str(s)
    }
}

#[cfg(feature = "bytes")]
impl RelativeName<Bytes> {
    /// Creates an empty relative name atop a bytes value.
    pub fn empty_bytes() -> Self {
        Self::empty()
    }

    /// Creates a wildcard relative name atop a bytes value.
    pub fn wildcard_bytes() -> Self {
        Self::wildcard()
    }

    /// Parses a string into a relative name atop a `Bytes`.
    pub fn bytes_from_str(s: &str) -> Result<Self, RelativeFromStrError> {
        FromStr::from_str(s)
    }
}

/// # Conversions
///
impl<Octs: ?Sized> RelativeName<Octs> {
    /// Returns a reference to the underlying octets.
    pub fn as_octets(&self) -> &Octs {
        &self.0
    }

    /// Converts the name into the underlying octets.
    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.0
    }

    /// Returns a domain name using a reference to the octets.
    pub fn for_ref(&self) -> RelativeName<&Octs> {
        unsafe { RelativeName::from_octets_unchecked(&self.0) }
    }

    /// Returns a reference to an octets slice with the content of the name.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    /// Returns a domain name for the octets slice of the content.
    pub fn for_slice(&self) -> &RelativeName<[u8]>
    where
        Octs: AsRef<[u8]>,
    {
        unsafe { RelativeName::from_slice_unchecked(self.0.as_ref()) }
    }

    /// Converts the name into its canonical form.
    pub fn make_canonical(&mut self)
    where
        Octs: AsMut<[u8]>,
    {
        Label::make_slice_canonical(self.0.as_mut());
    }
}

impl<Octs> RelativeName<Octs> {
    /// Converts the name into a domain name builder for appending data.
    ///
    /// This method is only available for octets sequences that have an
    /// associated octets builder such as `Vec<u8>` or `Bytes`.
    pub fn into_builder(self) -> NameBuilder<<Octs as IntoBuilder>::Builder>
    where
        Octs: IntoBuilder,
    {
        unsafe { NameBuilder::from_builder_unchecked(self.0.into_builder()) }
    }

    /// Converts the name into an absolute name by appending the root label.
    ///
    /// This manipulates the name itself and thus is only available for
    /// octets sequences that can be converted into an octets builder and back
    /// such as `Vec<u8>`.
    ///
    /// [`chain_root`]: #method.chain_root
    pub fn into_absolute(self) -> Result<Name<Octs>, PushError>
    where
        Octs: IntoBuilder,
        <Octs as IntoBuilder>::Builder:
            FreezeBuilder<Octets = Octs> + AsRef<[u8]> + AsMut<[u8]>,
    {
        self.into_builder().into_name()
    }

    /// Chains another name to the end of this name.
    ///
    /// Depending on whether `other` is an absolute or relative domain name,
    /// the resulting name will behave like an absolute or relative name.
    ///
    /// The method will fail if the combined length of the two names is
    /// greater than the size limit of 255. Note that in this case you will
    /// loose both `self` and `other`, so it might be worthwhile to check
    /// first.
    pub fn chain<N: ToLabelIter>(
        self,
        other: N,
    ) -> Result<Chain<Self, N>, LongChainError>
    where
        Octs: AsRef<[u8]>,
    {
        Chain::new(self, other)
    }

    /// Creates an absolute name by chaining the root label to it.
    pub fn chain_root(self) -> Chain<Self, Name<&'static [u8]>>
    where
        Octs: AsRef<[u8]>,
    {
        self.chain(Name::root()).unwrap()
    }
}

/// # Properties
///
impl<Octs: AsRef<[u8]> + ?Sized> RelativeName<Octs> {
    /// Returns the length of the name.
    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    /// Returns whether the name is empty.
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
}

/// # Working with Labels
///
impl<Octs: AsRef<[u8]> + ?Sized> RelativeName<Octs> {
    /// Returns an iterator over the labels of the domain name.
    pub fn iter(&self) -> NameIter {
        NameIter::new(self.0.as_ref())
    }

    /// Returns the number of labels in the name.
    pub fn label_count(&self) -> usize {
        self.iter().count()
    }

    /// Returns a reference to the first label if the name isn’t empty.
    pub fn first(&self) -> Option<&Label> {
        self.iter().next()
    }

    /// Returns a reference to the last label if the name isn’t empty.
    pub fn last(&self) -> Option<&Label> {
        self.iter().next_back()
    }

    /// Returns the number of dots in the string representation of the name.
    ///
    /// Specifically, returns a value equal to the number of labels minus one,
    /// except for an empty name where it returns a zero, also.
    pub fn ndots(&self) -> usize {
        if self.0.as_ref().is_empty() {
            0
        } else {
            self.label_count() - 1
        }
    }

    /// Determines whether `base` is a prefix of `self`.
    pub fn starts_with<N: ToLabelIter>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<N: ToLabelIter>(&self, base: &N) -> bool {
        <Self as ToLabelIter>::ends_with(self, base)
    }

    /// Returns whether an index points to the first octet of a label.
    pub fn is_label_start(&self, mut index: usize) -> bool {
        if index == 0 {
            return true;
        }
        let mut tmp = self.as_slice();
        while !tmp.is_empty() {
            let (label, tail) = Label::split_from(tmp).unwrap();
            let len = label.len() + 1;
            match index.cmp(&len) {
                Ordering::Less => return false,
                Ordering::Equal => return true,
                _ => {}
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
            Bound::Unbounded => {}
        }
    }

    /// Returns a part of the name indicated by start and end positions.
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
    /// The method panics if either position is not the beginning of a label
    /// or is out of bounds.
    ///
    /// [`range`]: #method.range
    pub fn slice(
        &self,
        range: impl RangeBounds<usize>,
    ) -> &RelativeName<[u8]> {
        self.check_bounds(&range);
        unsafe {
            RelativeName::from_slice_unchecked(self.0.as_ref().range(range))
        }
    }

    /// Returns a part of the name indicated by start and end positions.
    ///
    /// The returned name will start at position `begin` and end right before
    /// position `end`. Both positions are given as indexes into the
    /// underlying octets sequence and must point to the begining of a label.
    ///
    /// # Panics
    ///
    /// The method panics if either position is not the beginning of a label
    /// or is out of bounds.
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
}

impl<Octs: AsRef<[u8]> + ?Sized> RelativeName<Octs> {
    /// Splits the name into two at the given position.
    ///
    /// Returns a pair of the left and right part of the split name.
    ///
    /// # Panics
    ///
    /// The method panics if the position is not the beginning of a label
    /// or is beyond the end of the name.
    pub fn split(
        &self,
        mid: usize,
    ) -> (RelativeName<Octs::Range<'_>>, RelativeName<Octs::Range<'_>>)
    where
        Octs: Octets,
    {
        self.check_index(mid);
        unsafe {
            (
                RelativeName::from_octets_unchecked(self.0.range(..mid)),
                RelativeName::from_octets_unchecked(self.0.range(mid..)),
            )
        }
    }

    /// Truncates the name to the given length.
    ///
    /// # Panics
    ///
    /// The method panics if the position is not the beginning of a label
    /// or is beyond the end of the name.
    pub fn truncate(&mut self, len: usize)
    where
        Octs: Truncate,
    {
        self.check_index(len);
        self.0.truncate(len);
    }

    /// Splits off the first label.
    ///
    /// If there is at least one label in the name, returns the first label
    /// as a relative domain name with exactly one label and makes `self`
    /// contain the domain name starting after that first label. If the name
    /// is empty, returns `None`.
    pub fn split_first(
        &self,
    ) -> Option<(&Label, RelativeName<Octs::Range<'_>>)>
    where
        Octs: Octets,
    {
        if self.is_empty() {
            return None;
        }
        let label = self.iter().next()?;
        Some((label, self.split(label.len() + 1).1))
    }

    /// Returns the parent name.
    ///
    /// Returns `None` if the name was empty.
    pub fn parent(&self) -> Option<RelativeName<Octs::Range<'_>>>
    where
        Octs: Octets,
    {
        self.split_first().map(|(_, parent)| parent)
    }

    /// Strips the suffix `base` from the domain name.
    ///
    /// This will fail if `base` isn’t actually a suffix, i.e., if
    /// [`ends_with`] doesn’t return `true`.
    ///
    /// [`ends_with`]: #method.ends_with
    pub fn strip_suffix<N: ToRelativeName>(
        &mut self,
        base: &N,
    ) -> Result<(), StripSuffixError>
    where
        Octs: Truncate,
    {
        if self.ends_with(base) {
            let idx = self.0.as_ref().len() - usize::from(base.compose_len());
            self.0.truncate(idx);
            Ok(())
        } else {
            Err(StripSuffixError(()))
        }
    }
}

//--- AsRef

impl<Octs> AsRef<Octs> for RelativeName<Octs> {
    fn as_ref(&self) -> &Octs {
        &self.0
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> AsRef<[u8]> for RelativeName<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<RelativeName<SrcOcts>> for RelativeName<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: RelativeName<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.0)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

//--- FromStr

impl<Octs> FromStr for RelativeName<Octs>
where
    Octs: FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder
        + FreezeBuilder<Octets = Octs>
        + AsRef<[u8]>
        + AsMut<[u8]>,
{
    type Err = RelativeFromStrError;

    /// Parses a string into an absolute domain name.
    ///
    /// The name needs to be formatted in representation format, i.e., as a
    /// sequence of labels separated by dots. If Internationalized Domain
    /// Name (IDN) labels are to be used, these need to be given in punycode
    /// encoded form.
    ///
    /// This implementation will error if the name ends in a dot since that
    /// indicates an absolute name.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_chars(s.chars())
    }
}

//--- ToLabelIter and ToRelativeName

impl<Octs> ToLabelIter for RelativeName<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
{
    type LabelIter<'a> = NameIter<'a> where Octs: 'a;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        self.iter()
    }

    fn compose_len(&self) -> u16 {
        u16::try_from(self.0.as_ref().len()).expect("long domain name")
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> ToRelativeName for RelativeName<Octs> {
    fn as_flat_slice(&self) -> Option<&[u8]> {
        Some(self.0.as_ref())
    }

    fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
}

//--- IntoIterator

impl<'a, Octs> IntoIterator for &'a RelativeName<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
{
    type Item = &'a Label;
    type IntoIter = NameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- PartialEq and Eq

impl<Octs, N> PartialEq<N> for RelativeName<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    N: ToRelativeName + ?Sized,
{
    fn eq(&self, other: &N) -> bool {
        self.name_eq(other)
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Eq for RelativeName<Octs> {}

//--- PartialOrd and Ord

impl<Octs, N> PartialOrd<N> for RelativeName<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
    N: ToRelativeName + ?Sized,
{
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        Some(self.name_cmp(other))
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> Ord for RelativeName<Octs> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.name_cmp(other)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]> + ?Sized> hash::Hash for RelativeName<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}

//--- Display and Debug

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Display for RelativeName<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.iter();
        match iter.next() {
            Some(label) => label.fmt(f)?,
            None => return Ok(()),
        }
        for label in iter {
            f.write_str(".")?;
            label.fmt(f)?;
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Debug for RelativeName<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RelativeName({})", self)
    }
}

//--- AsRef and Borrow

impl<Octs> AsRef<RelativeName<[u8]>> for RelativeName<Octs>
where
    Octs: AsRef<[u8]> + ?Sized,
{
    fn as_ref(&self) -> &RelativeName<[u8]> {
        self.for_slice()
    }
}

/// Borrow a relative domain name.
///
/// Containers holding an owned `RelativeName<_>` may be queried with name
/// over a slice. This `Borrow<_>` impl supports user code querying containers
/// with compatible-but-different types like the following example:
///
/// ```
/// use std::collections::HashMap;
///
/// use domain::base::RelativeName;
///
/// fn get_description(
///     hash: &HashMap<RelativeName<Vec<u8>>, String>
/// ) -> Option<&str> {
///     let lookup_name: &RelativeName<[u8]> =
///         RelativeName::from_slice(b"\x03ftp").unwrap();
///     hash.get(lookup_name).map(|x| x.as_ref())
/// }
/// ```
impl<Octs> borrow::Borrow<RelativeName<[u8]>> for RelativeName<Octs>
where
    Octs: AsRef<[u8]>,
{
    fn borrow(&self) -> &RelativeName<[u8]> {
        self.for_slice()
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<Octs> serde::Serialize for RelativeName<Octs>
where
    Octs: AsRef<[u8]> + SerializeOctets + ?Sized,
{
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct(
                "RelativeName",
                &format_args!("{}", self),
            )
        } else {
            serializer.serialize_newtype_struct(
                "RelativeName",
                &self.0.as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octs> serde::Deserialize<'de> for RelativeName<Octs>
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
            type Value = RelativeName<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a relative domain name")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                let mut builder = NameBuilder::<Octs::Builder>::new();
                builder.append_chars(v.chars()).map_err(E::custom)?;
                Ok(builder.finish())
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    RelativeName::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    RelativeName::from_octets(octets).map_err(E::custom)
                })
            }
        }

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octs> serde::de::Visitor<'de> for NewtypeVisitor<Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder: FreezeBuilder<Octets = Octs>
                + EmptyBuilder
                + AsRef<[u8]>
                + AsMut<[u8]>,
        {
            type Value = RelativeName<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a relative domain name")
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

        deserializer.deserialize_newtype_struct(
            "RelativeName",
            NewtypeVisitor(PhantomData),
        )
    }
}

//------------ NameIter -----------------------------------------------------

/// An iterator over the labels in an uncompressed name.
#[derive(Clone, Debug)]
pub struct NameIter<'a> {
    slice: &'a [u8],
}

impl<'a> NameIter<'a> {
    pub(super) fn new(slice: &'a [u8]) -> Self {
        NameIter { slice }
    }
}

impl<'a> Iterator for NameIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        let (label, tail) = match Label::split_from(self.slice) {
            Ok(res) => res,
            Err(_) => return None,
        };
        self.slice = tail;
        Some(label)
    }
}

impl<'a> DoubleEndedIterator for NameIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.slice.is_empty() {
            return None;
        }
        let mut tmp = self.slice;
        loop {
            let (label, tail) = Label::split_from(tmp).unwrap();
            if tail.is_empty() {
                let end = self.slice.len() - (label.len() + 1);
                self.slice = &self.slice[..end];
                return Some(label);
            } else {
                tmp = tail
            }
        }
    }
}

//============ Error Types ===================================================

//------------ RelativeNameError --------------------------------------------

/// An error happened while creating a domain name from octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelativeNameError(RelativeNameErrorEnum);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelativeNameErrorEnum {
    /// A bad label was encountered.
    BadLabel(LabelTypeError),

    /// A compressed name was encountered.
    CompressedName,

    /// The data ended before the end of a label.
    ShortInput,

    /// The domain name was longer than 255 octets.
    LongName,

    /// The root label was encountered.
    AbsoluteName,
}

//--- From

impl From<LabelTypeError> for RelativeNameError {
    fn from(err: LabelTypeError) -> Self {
        Self(RelativeNameErrorEnum::BadLabel(err))
    }
}

impl From<SplitLabelError> for RelativeNameError {
    fn from(err: SplitLabelError) -> Self {
        Self(match err {
            SplitLabelError::Pointer(_) => {
                RelativeNameErrorEnum::CompressedName
            }
            SplitLabelError::BadType(t) => RelativeNameErrorEnum::BadLabel(t),
            SplitLabelError::ShortInput => RelativeNameErrorEnum::ShortInput,
        })
    }
}

impl From<RelativeNameErrorEnum> for RelativeNameError {
    fn from(err: RelativeNameErrorEnum) -> Self {
        Self(err)
    }
}

//--- Display and Error

impl fmt::Display for RelativeNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            RelativeNameErrorEnum::BadLabel(err) => err.fmt(f),
            RelativeNameErrorEnum::CompressedName => {
                f.write_str("compressed domain name")
            }
            RelativeNameErrorEnum::ShortInput => {
                ParseError::ShortInput.fmt(f)
            }
            RelativeNameErrorEnum::LongName => {
                f.write_str("long domain name")
            }
            RelativeNameErrorEnum::AbsoluteName => {
                f.write_str("absolute domain name")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RelativeNameError {}

//------------ RelativeFromStrError ------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RelativeFromStrError {
    /// The name could not be parsed.
    FromStr(FromStrError),

    /// The parsed name was ended in a dot.
    AbsoluteName,
}

//--- From

impl From<FromStrError> for RelativeFromStrError {
    fn from(src: FromStrError) -> Self {
        Self::FromStr(src)
    }
}

//--- Display and Error

impl fmt::Display for RelativeFromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RelativeFromStrError::FromStr(err) => err.fmt(f),
            RelativeFromStrError::AbsoluteName => {
                f.write_str("absolute domain name")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RelativeFromStrError {}

//------------ StripSuffixError ----------------------------------------------

/// An attempt was made to strip a suffix that wasn’t actually a suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StripSuffixError(());

//--- Display and Error

impl fmt::Display for StripSuffixError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("suffix not found")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for StripSuffixError {}

//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "std")]
    macro_rules! assert_panic {
        ( $cond:expr ) => {{
            let result = std::panic::catch_unwind(|| $cond);
            assert!(result.is_err());
        }};
    }

    #[test]
    #[cfg(feature = "std")]
    fn impls() {
        fn assert_to_relative_name<T: ToRelativeName + ?Sized>(_: &T) {}

        assert_to_relative_name(
            RelativeName::from_slice(b"\x03www".as_ref()).unwrap(),
        );
        assert_to_relative_name(
            &RelativeName::from_octets(b"\x03www").unwrap(),
        );
        assert_to_relative_name(
            &RelativeName::from_octets(b"\x03www".as_ref()).unwrap(),
        );
        assert_to_relative_name(
            &RelativeName::from_octets(Vec::from(b"\x03www".as_ref()))
                .unwrap(),
        );
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn impl_bytes() {
        fn assert_to_relative_name<T: ToRelativeName + ?Sized>(_: &T) {}

        assert_to_relative_name(
            &RelativeName::from_octets(Bytes::from(b"\x03www".as_ref()))
                .unwrap(),
        );
    }

    #[test]
    fn empty() {
        assert_eq!(RelativeName::empty_slice().as_slice(), b"");
        assert_eq!(RelativeName::empty_ref().as_slice(), b"");

        #[cfg(feature = "std")]
        {
            assert_eq!(RelativeName::empty_vec().as_slice(), b"");
        }
    }

    #[test]
    fn wildcard() {
        assert_eq!(RelativeName::wildcard_slice().as_slice(), b"\x01*");
        assert_eq!(RelativeName::wildcard_ref().as_slice(), b"\x01*");

        #[cfg(feature = "std")]
        {
            assert_eq!(RelativeName::wildcard_vec().as_slice(), b"\x01*");
        }
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn literals_bytes() {
        assert_eq!(RelativeName::empty_bytes().as_slice(), b"");
        assert_eq!(RelativeName::wildcard_bytes().as_slice(), b"\x01*");
    }

    #[test]
    #[cfg(feature = "std")]
    fn from_slice() {
        // good names
        assert_eq!(RelativeName::from_slice(b"").unwrap().as_slice(), b"");
        assert_eq!(
            RelativeName::from_slice(b"\x03www").unwrap().as_slice(),
            b"\x03www"
        );
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07example")
                .unwrap()
                .as_slice(),
            b"\x03www\x07example"
        );

        // absolute names
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07example\x03com\0"),
            Err(RelativeNameError(RelativeNameErrorEnum::AbsoluteName))
        );
        assert_eq!(
            RelativeName::from_slice(b"\0"),
            Err(RelativeNameError(RelativeNameErrorEnum::AbsoluteName))
        );

        // bytes shorter than what label length says.
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07exa"),
            Err(RelativeNameError(RelativeNameErrorEnum::ShortInput))
        );

        // label 63 long ok, 64 bad.
        let mut slice = [0u8; 64];
        slice[0] = 63;
        assert!(RelativeName::from_slice(&slice[..]).is_ok());
        let mut slice = [0u8; 65];
        slice[0] = 64;
        assert!(RelativeName::from_slice(&slice[..]).is_err());

        // name 254 long ok, 255 bad.
        let mut buf = Vec::new();
        for _ in 0..25 {
            buf.extend_from_slice(b"\x09123456789");
        }
        assert_eq!(buf.len(), 250);
        let mut tmp = buf.clone();
        tmp.extend_from_slice(b"\x03123");
        assert_eq!(RelativeName::from_slice(&tmp).map(|_| ()), Ok(()));
        buf.extend_from_slice(b"\x041234");
        assert!(RelativeName::from_slice(&buf).is_err());

        // bad label heads: compressed, other types.
        assert_eq!(
            RelativeName::from_slice(b"\xa2asdasds"),
            Err(LabelTypeError::Undefined.into())
        );
        assert_eq!(
            RelativeName::from_slice(b"\x62asdasds"),
            Err(LabelTypeError::Extended(0x62).into())
        );
        assert_eq!(
            RelativeName::from_slice(b"\xccasdasds"),
            Err(RelativeNameError(RelativeNameErrorEnum::CompressedName))
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn from_str() {
        // empty name
        assert_eq!(RelativeName::vec_from_str("").unwrap().as_slice(), b"");

        // relative name
        assert_eq!(
            RelativeName::vec_from_str("www.example")
                .unwrap()
                .as_slice(),
            b"\x03www\x07example"
        );

        // absolute name
        assert!(RelativeName::vec_from_str("www.example.com.").is_err());
    }

    #[test]
    #[cfg(feature = "std")]
    fn into_absolute() {
        assert_eq!(
            RelativeName::from_octets(Vec::from(
                b"\x03www\x07example\x03com".as_ref()
            ))
            .unwrap()
            .into_absolute()
            .unwrap()
            .as_slice(),
            b"\x03www\x07example\x03com\0"
        );

        // Check that a 254 octets long relative name converts fine.
        let mut buf = Vec::new();
        for _ in 0..25 {
            buf.extend_from_slice(b"\x09123456789");
        }
        assert_eq!(buf.len(), 250);
        let mut tmp = buf.clone();
        tmp.extend_from_slice(b"\x03123");
        RelativeName::from_octets(tmp)
            .unwrap()
            .into_absolute()
            .unwrap();
    }

    #[test]
    #[cfg(feature = "std")]
    fn make_canonical() {
        let mut name = Name::vec_from_str("wWw.exAmpLE.coM.").unwrap();
        name.make_canonical();
        assert_eq!(
            name,
            Name::from_octets(b"\x03www\x07example\x03com\0").unwrap()
        );
    }

    // chain is tested with the Chain type.

    #[test]
    fn chain_root() {
        assert_eq!(
            Name::from_octets(b"\x03www\x07example\x03com\0").unwrap(),
            RelativeName::from_octets(b"\x03www\x07example\x03com")
                .unwrap()
                .chain_root()
        );
    }

    #[test]
    fn iter() {
        use crate::base::name::absolute::test::cmp_iter;

        cmp_iter(RelativeName::empty_ref().iter(), &[]);
        cmp_iter(RelativeName::wildcard_ref().iter(), &[b"*"]);
        cmp_iter(
            RelativeName::from_slice(b"\x03www\x07example\x03com")
                .unwrap()
                .iter(),
            &[b"www", b"example", b"com"],
        );
    }

    #[test]
    fn iter_back() {
        use crate::base::name::absolute::test::cmp_iter_back;

        cmp_iter_back(RelativeName::empty_ref().iter(), &[]);
        cmp_iter_back(RelativeName::wildcard_ref().iter(), &[b"*"]);
        cmp_iter_back(
            RelativeName::from_slice(b"\x03www\x07example\x03com")
                .unwrap()
                .iter(),
            &[b"com", b"example", b"www"],
        );
    }

    #[test]
    fn label_count() {
        assert_eq!(RelativeName::empty_ref().label_count(), 0);
        assert_eq!(RelativeName::wildcard_slice().label_count(), 1);
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07example\x03com")
                .unwrap()
                .label_count(),
            3
        );
    }

    #[test]
    fn first() {
        assert_eq!(RelativeName::empty_slice().first(), None);
        assert_eq!(
            RelativeName::from_slice(b"\x03www")
                .unwrap()
                .first()
                .unwrap()
                .as_slice(),
            b"www"
        );
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07example")
                .unwrap()
                .first()
                .unwrap()
                .as_slice(),
            b"www"
        );
    }

    #[test]
    fn last() {
        assert_eq!(RelativeName::empty_slice().last(), None);
        assert_eq!(
            RelativeName::from_slice(b"\x03www")
                .unwrap()
                .last()
                .unwrap()
                .as_slice(),
            b"www"
        );
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07example")
                .unwrap()
                .last()
                .unwrap()
                .as_slice(),
            b"example"
        );
    }

    #[test]
    fn ndots() {
        assert_eq!(RelativeName::empty_slice().ndots(), 0);
        assert_eq!(RelativeName::from_slice(b"\x03www").unwrap().ndots(), 0);
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07example")
                .unwrap()
                .ndots(),
            1
        );
    }

    #[test]
    fn starts_with() {
        let matrix = [
            (
                RelativeName::empty_slice(),
                [true, false, false, false, false, false],
            ),
            (
                RelativeName::from_slice(b"\x03www").unwrap(),
                [true, true, false, false, false, false],
            ),
            (
                RelativeName::from_slice(b"\x03www\x07example").unwrap(),
                [true, true, true, false, false, false],
            ),
            (
                RelativeName::from_slice(b"\x03www\x07example\x03com")
                    .unwrap(),
                [true, true, true, true, false, false],
            ),
            (
                RelativeName::from_slice(b"\x07example\x03com").unwrap(),
                [true, false, false, false, true, false],
            ),
            (
                RelativeName::from_slice(b"\x03com").unwrap(),
                [true, false, false, false, false, true],
            ),
        ];
        for i in 0..6 {
            for j in 0..6 {
                assert_eq!(
                    matrix[i].0.starts_with(&matrix[j].0),
                    matrix[i].1[j],
                    "i={}, j={}",
                    i,
                    j
                )
            }
        }
    }

    #[test]
    fn ends_with() {
        let matrix = [
            (
                RelativeName::empty_slice(),
                [true, false, false, false, false, false],
            ),
            (
                RelativeName::from_slice(b"\x03www").unwrap(),
                [true, true, false, false, false, false],
            ),
            (
                RelativeName::from_slice(b"\x03www\x07example").unwrap(),
                [true, false, true, false, false, false],
            ),
            (
                RelativeName::from_slice(b"\x03www\x07example\x03com")
                    .unwrap(),
                [true, false, false, true, true, true],
            ),
            (
                RelativeName::from_slice(b"\x07example\x03com").unwrap(),
                [true, false, false, false, true, true],
            ),
            (
                RelativeName::from_slice(b"\x03com").unwrap(),
                [true, false, false, false, false, true],
            ),
        ];
        for i in 0..matrix.len() {
            for j in 0..matrix.len() {
                assert_eq!(
                    matrix[i].0.ends_with(&matrix[j].0),
                    matrix[i].1[j],
                    "i={}, j={}",
                    i,
                    j
                )
            }
        }
    }

    #[test]
    fn is_label_start() {
        let wec =
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap();

        assert!(wec.is_label_start(0)); // \x03
        assert!(!wec.is_label_start(1)); // w
        assert!(!wec.is_label_start(2)); // w
        assert!(!wec.is_label_start(3)); // w
        assert!(wec.is_label_start(4)); // \x07
        assert!(!wec.is_label_start(5)); // e
        assert!(!wec.is_label_start(6)); // x
        assert!(!wec.is_label_start(7)); // a
        assert!(!wec.is_label_start(8)); // m
        assert!(!wec.is_label_start(9)); // p
        assert!(!wec.is_label_start(10)); // l
        assert!(!wec.is_label_start(11)); // e
        assert!(wec.is_label_start(12)); // \x03
        assert!(!wec.is_label_start(13)); // c
        assert!(!wec.is_label_start(14)); // o
        assert!(!wec.is_label_start(15)); // m
        assert!(wec.is_label_start(16)); // empty label
        assert!(!wec.is_label_start(17)); //
    }

    #[test]
    #[cfg(feature = "std")]
    fn slice() {
        let wec =
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap();
        assert_eq!(wec.slice(0..4).as_slice(), b"\x03www");
        assert_eq!(wec.slice(0..12).as_slice(), b"\x03www\x07example");
        assert_eq!(wec.slice(4..12).as_slice(), b"\x07example");
        assert_eq!(wec.slice(4..16).as_slice(), b"\x07example\x03com");

        assert_panic!(wec.slice(0..3));
        assert_panic!(wec.slice(1..4));
        assert_panic!(wec.slice(0..11));
        assert_panic!(wec.slice(1..12));
        assert_panic!(wec.slice(0..17));
        assert_panic!(wec.slice(4..17));
        assert_panic!(wec.slice(0..18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn range() {
        let wec =
            RelativeName::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();
        assert_eq!(wec.range(0..4).as_slice(), b"\x03www");
        assert_eq!(wec.range(0..12).as_slice(), b"\x03www\x07example");
        assert_eq!(wec.range(4..12).as_slice(), b"\x07example");
        assert_eq!(wec.range(4..16).as_slice(), b"\x07example\x03com");

        assert_panic!(wec.range(0..3));
        assert_panic!(wec.range(1..4));
        assert_panic!(wec.range(0..11));
        assert_panic!(wec.range(1..12));
        assert_panic!(wec.range(0..17));
        assert_panic!(wec.range(4..17));
        assert_panic!(wec.range(0..18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn split() {
        let wec =
            RelativeName::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();

        let (left, right) = wec.split(0);
        assert_eq!(left.as_slice(), b"");
        assert_eq!(right.as_slice(), b"\x03www\x07example\x03com");

        let (left, right) = wec.split(4);
        assert_eq!(left.as_slice(), b"\x03www");
        assert_eq!(right.as_slice(), b"\x07example\x03com");

        let (left, right) = wec.split(12);
        assert_eq!(left.as_slice(), b"\x03www\x07example");
        assert_eq!(right.as_slice(), b"\x03com");

        let (left, right) = wec.split(16);
        assert_eq!(left.as_slice(), b"\x03www\x07example\x03com");
        assert_eq!(right.as_slice(), b"");

        assert_panic!(wec.split(1));
        assert_panic!(wec.split(14));
        assert_panic!(wec.split(17));
        assert_panic!(wec.split(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn truncate() {
        let wec =
            RelativeName::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();

        let mut tmp = wec.clone();
        tmp.truncate(0);
        assert_eq!(tmp.as_slice(), b"");

        let mut tmp = wec.clone();
        tmp.truncate(4);
        assert_eq!(tmp.as_slice(), b"\x03www");

        let mut tmp = wec.clone();
        tmp.truncate(12);
        assert_eq!(tmp.as_slice(), b"\x03www\x07example");

        let mut tmp = wec.clone();
        tmp.truncate(16);
        assert_eq!(tmp.as_slice(), b"\x03www\x07example\x03com");

        assert_panic!(wec.clone().truncate(1));
        assert_panic!(wec.clone().truncate(14));
        assert_panic!(wec.clone().truncate(17));
        assert_panic!(wec.clone().truncate(18));
    }

    #[test]
    fn split_first() {
        let wec =
            RelativeName::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();

        let (label, wec) = wec.split_first().unwrap();
        assert_eq!(label.as_slice(), b"www");
        assert_eq!(wec.as_slice(), b"\x07example\x03com");

        let (label, wec) = wec.split_first().unwrap();
        assert_eq!(label.as_slice(), b"example");
        assert_eq!(wec.as_slice(), b"\x03com");

        let (label, wec) = wec.split_first().unwrap();
        assert_eq!(label.as_slice(), b"com");
        assert_eq!(wec.as_slice(), b"");
        assert!(wec.split_first().is_none());
    }

    #[test]
    fn parent() {
        let wec =
            RelativeName::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();

        let wec = wec.parent().unwrap();
        assert_eq!(wec.as_slice(), b"\x07example\x03com");

        let wec = wec.parent().unwrap();
        assert_eq!(wec.as_slice(), b"\x03com");

        let wec = wec.parent().unwrap();
        assert_eq!(wec.as_slice(), b"");

        assert!(wec.parent().is_none());
    }

    #[test]
    fn strip_suffix() {
        let wec =
            RelativeName::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();
        let ec = RelativeName::from_octets(b"\x07example\x03com".as_ref())
            .unwrap();
        let c = RelativeName::from_octets(b"\x03com".as_ref()).unwrap();
        let wen =
            RelativeName::from_octets(b"\x03www\x07example\x03net".as_ref())
                .unwrap();
        let en = RelativeName::from_octets(b"\x07example\x03net".as_ref())
            .unwrap();
        let n = RelativeName::from_slice(b"\x03net".as_ref()).unwrap();

        let mut tmp = wec.clone();
        assert_eq!(tmp.strip_suffix(&wec), Ok(()));
        assert_eq!(tmp.as_slice(), b"");

        let mut tmp = wec.clone();
        assert_eq!(tmp.strip_suffix(&ec), Ok(()));
        assert_eq!(tmp.as_slice(), b"\x03www");

        let mut tmp = wec.clone();
        assert_eq!(tmp.strip_suffix(&c), Ok(()));
        assert_eq!(tmp.as_slice(), b"\x03www\x07example");

        let mut tmp = wec.clone();
        assert_eq!(tmp.strip_suffix(&RelativeName::empty_ref()), Ok(()));
        assert_eq!(tmp.as_slice(), b"\x03www\x07example\x03com");

        assert!(wec.clone().strip_suffix(&wen).is_err());
        assert!(wec.clone().strip_suffix(&en).is_err());
        assert!(wec.clone().strip_suffix(&n).is_err());
    }

    // No test for Compose since the implementation is so simple.

    #[test]
    fn eq() {
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap(),
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap()
        );
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap(),
            RelativeName::from_slice(b"\x03wWw\x07eXAMple\x03Com").unwrap()
        );
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap(),
            &RelativeName::from_octets(b"\x03www")
                .unwrap()
                .chain(
                    RelativeName::from_octets(b"\x07example\x03com").unwrap()
                )
                .unwrap()
        );
        assert_eq!(
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap(),
            &RelativeName::from_octets(b"\x03wWw")
                .unwrap()
                .chain(
                    RelativeName::from_octets(b"\x07eXAMple\x03coM").unwrap()
                )
                .unwrap()
        );

        assert_ne!(
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap(),
            RelativeName::from_slice(b"\x03ww4\x07example\x03com").unwrap()
        );
        assert_ne!(
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap(),
            &RelativeName::from_octets(b"\x03www")
                .unwrap()
                .chain(
                    RelativeName::from_octets(b"\x073xample\x03com").unwrap()
                )
                .unwrap()
        );
    }

    #[test]
    fn cmp() {
        use core::cmp::Ordering;

        // The following is taken from section 6.1 of RFC 4034.
        let names = [
            RelativeName::from_slice(b"\x07example").unwrap(),
            RelativeName::from_slice(b"\x01a\x07example").unwrap(),
            RelativeName::from_slice(b"\x08yljkjljk\x01a\x07example")
                .unwrap(),
            RelativeName::from_slice(b"\x01Z\x01a\x07example").unwrap(),
            RelativeName::from_slice(b"\x04zABC\x01a\x07example").unwrap(),
            RelativeName::from_slice(b"\x01z\x07example").unwrap(),
            RelativeName::from_slice(b"\x01\x01\x01z\x07example").unwrap(),
            RelativeName::from_slice(b"\x01*\x01z\x07example").unwrap(),
            RelativeName::from_slice(b"\x01\xc8\x01z\x07example").unwrap(),
        ];
        for i in 0..names.len() {
            for j in 0..names.len() {
                let ord = i.cmp(&j);
                assert_eq!(names[i].partial_cmp(names[j]), Some(ord));
                assert_eq!(names[i].cmp(names[j]), ord);
            }
        }

        let n1 =
            RelativeName::from_slice(b"\x03www\x07example\x03com").unwrap();
        let n2 =
            RelativeName::from_slice(b"\x03wWw\x07eXAMple\x03Com").unwrap();
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
        RelativeName::from_slice(b"\x03www\x07example\x03com")
            .unwrap()
            .hash(&mut s1);
        RelativeName::from_slice(b"\x03wWw\x07eXAMple\x03Com")
            .unwrap()
            .hash(&mut s2);
        assert_eq!(s1.finish(), s2.finish());
    }

    #[test]
    #[cfg(feature = "std")]
    fn display() {
        use std::string::ToString;

        fn cmp(bytes: &[u8], fmt: &str) {
            let name = RelativeName::from_octets(bytes).unwrap();
            assert_eq!(name.to_string(), fmt);
        }

        cmp(b"", "");
        cmp(b"\x03com", "com");
        cmp(b"\x07example\x03com", "example.com");
    }

    #[cfg(all(feature = "serde", feature = "std"))]
    #[test]
    fn ser_de() {
        use serde_test::{assert_tokens, Configure, Token};

        let name = RelativeName::from_octets(Vec::from(
            b"\x03www\x07example\x03com".as_ref(),
        ))
        .unwrap();
        assert_tokens(
            &name.clone().compact(),
            &[
                Token::NewtypeStruct {
                    name: "RelativeName",
                },
                Token::ByteBuf(b"\x03www\x07example\x03com"),
            ],
        );
        assert_tokens(
            &name.readable(),
            &[
                Token::NewtypeStruct {
                    name: "RelativeName",
                },
                Token::Str("www.example.com"),
            ],
        );
    }
}
