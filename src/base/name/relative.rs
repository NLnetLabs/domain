use super::super::octets::{
    Compose, IntoBuilder, OctetsBuilder, OctetsExt, OctetsFrom, OctetsRef,
    ParseError, ShortBuf,
};
#[cfg(feature = "serde")]
use super::super::octets::{
    DeserializeOctets, EmptyBuilder, FromBuilder, SerializeOctets,
};
use super::builder::{DnameBuilder, PushError};
use super::chain::{Chain, LongChainError};
use super::dname::Dname;
use super::label::{Label, LabelTypeError, SplitLabelError};
use super::traits::{ToEitherDname, ToLabelIter, ToRelativeDname};
#[cfg(feature = "bytes")]
use bytes::Bytes;
use core::cmp::Ordering;
/// Uncompressed, relative domain names.
///
/// This is a private module. Its public types are re-exported by the parent.
use core::{cmp, fmt, hash, ops};
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ RelativeDname -------------------------------------------------

/// An uncompressed, relative domain name.
///
/// A relative domain name is one that doesn’t end with the root label. As the
/// name suggests, it is relative to some other domain name. This type wraps
/// a octets sequence containing such a relative name similarly to the way
/// [`Dname`] wraps an absolute one. In fact, it behaves very similarly to
/// [`Dname`] taking into account differences when slicing and dicing names.
///
/// `RelativeDname` guarantees that the name is at most 254 bytes long. As the
/// length limit for a domain name is actually 255 bytes, this means that you
/// can always safely turn a `RelativeDname` into a `Dname` by adding the root
/// label (which is exactly one byte long).
///
/// [`Bytes`]: ../../../bytes/struct.Bytes.html
/// [`Dname`]: struct.Dname.html
#[derive(Clone)]
pub struct RelativeDname<Octets: ?Sized>(Octets);

/// # Creating Values
///
impl<Octets> RelativeDname<Octets> {
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
    pub const unsafe fn from_octets_unchecked(octets: Octets) -> Self {
        RelativeDname(octets)
    }

    /// Creates a relative domain name from an octets sequence.
    ///
    /// This checks that `octets` contains a properly encoded relative domain
    /// name and fails if it doesn’t.
    pub fn from_octets(octets: Octets) -> Result<Self, RelativeDnameError>
    where
        Octets: AsRef<[u8]>,
    {
        RelativeDname::check_slice(octets.as_ref())?;
        Ok(unsafe { RelativeDname::from_octets_unchecked(octets) })
    }

    /// Creates an empty relative domain name.
    pub fn empty() -> Self
    where
        Octets: From<&'static [u8]>,
    {
        unsafe { RelativeDname::from_octets_unchecked(b"".as_ref().into()) }
    }

    /// Creates a relative domain name representing the wildcard label.
    ///
    /// The wildcard label is intended to match any label. There are special
    /// rules for names with wildcard labels. Note that the comparison traits
    /// implemented for domain names do *not* consider wildcards and treat
    /// them as regular labels.
    pub fn wildcard() -> Self
    where
        Octets: From<&'static [u8]>,
    {
        unsafe {
            RelativeDname::from_octets_unchecked(b"\x01*".as_ref().into())
        }
    }
}

impl RelativeDname<[u8]> {
    /// Creates a domain name from an octet slice without checking.
    ///
    /// # Safety
    ///
    /// The same rules as for `from_octets_unchecked` apply.
    pub(super) unsafe fn from_slice_unchecked(slice: &[u8]) -> &Self {
        &*(slice as *const [u8] as *const RelativeDname<[u8]>)
    }

    /// Creates a relative domain name from an octet slice.
    pub fn from_slice(slice: &[u8]) -> Result<&Self, RelativeDnameError> {
        Self::check_slice(slice)?;
        Ok(unsafe { Self::from_slice_unchecked(slice) })
    }

    /// Returns an empty relative name atop a unsized slice.
    pub fn empty_slice() -> &'static Self {
        unsafe { Self::from_slice_unchecked(b"") }
    }

    pub fn wildcard_slice() -> &'static Self {
        unsafe { Self::from_slice_unchecked(b"\x01*") }
    }

    /// Checks whether an octet slice contains a correctly encoded name.
    pub(super) fn check_slice(
        mut slice: &[u8],
    ) -> Result<(), RelativeDnameError> {
        if slice.len() > 254 {
            return Err(RelativeDnameError::LongName);
        }
        while !slice.is_empty() {
            let (label, tail) = Label::split_from(slice)?;
            if label.is_root() {
                return Err(RelativeDnameError::AbsoluteName);
            }
            slice = tail;
        }
        Ok(())
    }
}

impl RelativeDname<&'static [u8]> {
    /// Creates an empty relative name atop a slice reference.
    pub fn empty_ref() -> Self {
        Self::empty()
    }

    /// Creates a wildcard relative name atop a slice reference.
    pub fn wildcard_ref() -> Self {
        Self::wildcard()
    }
}

#[cfg(feature = "std")]
impl RelativeDname<Vec<u8>> {
    /// Creates an empty relative name atop a `Vec<u8>`.
    pub fn empty_vec() -> Self {
        Self::empty()
    }

    /// Creates a wildcard relative name atop a `Vec<u8>`.
    pub fn wildcard_vec() -> Self {
        Self::wildcard()
    }
}

#[cfg(feature = "bytes")]
impl RelativeDname<Bytes> {
    /// Creates an empty relative name atop a bytes value.
    pub fn empty_bytes() -> Self {
        Self::empty()
    }

    /// Creates a wildcard relative name atop a bytes value.
    pub fn wildcard_bytes() -> Self {
        Self::wildcard()
    }
}

/// # Conversions
///
impl<Octets: ?Sized> RelativeDname<Octets> {
    /// Returns a reference to the underlying octets.
    pub fn as_octets(&self) -> &Octets {
        &self.0
    }

    /// Converts the name into the underlying octets.
    pub fn into_octets(self) -> Octets
    where
        Octets: Sized,
    {
        self.0
    }

    /// Returns a domain name using a reference to the octets.
    pub fn for_ref(&self) -> RelativeDname<&Octets> {
        unsafe { RelativeDname::from_octets_unchecked(&self.0) }
    }

    /// Returns a reference to an octets slice with the content of the name.
    pub fn as_slice(&self) -> &[u8]
    where
        Octets: AsRef<[u8]>,
    {
        self.0.as_ref()
    }

    /// Returns a domain name for the octets slice of the content.
    pub fn for_slice(&self) -> RelativeDname<&[u8]>
    where
        Octets: AsRef<[u8]>,
    {
        unsafe { RelativeDname::from_octets_unchecked(self.0.as_ref()) }
    }
}

impl<Octets> RelativeDname<Octets> {
    /// Converts the name into a domain name builder for appending data.
    ///
    /// This method is only available for octets sequences that have an
    /// associated octets builder such as `Vec<u8>` or `Bytes`.
    pub fn into_builder(
        self,
    ) -> DnameBuilder<<Octets as IntoBuilder>::Builder>
    where
        Octets: IntoBuilder,
    {
        unsafe { DnameBuilder::from_builder_unchecked(self.0.into_builder()) }
    }

    /// Converts the name into an absolute name by appending the root label.
    ///
    /// This manipulates the name itself and thus is only available for
    /// octets sequences that can be converted into an octets builder and back
    /// such as `Vec<u8>`.
    ///
    /// [`chain_root`]: #method.chain_root
    pub fn into_absolute(
        self,
    ) -> Result<
        Dname<<<Octets as IntoBuilder>::Builder as OctetsBuilder>::Octets>,
        PushError,
    >
    where
        Octets: IntoBuilder,
        <Octets as IntoBuilder>::Builder: AsMut<[u8]>,
    {
        self.into_builder().into_dname()
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
    pub fn chain<N: ToEitherDname>(
        self,
        other: N,
    ) -> Result<Chain<Self, N>, LongChainError>
    where
        Octets: AsRef<[u8]>,
    {
        Chain::new(self, other)
    }

    /// Creates an absolute name by chaining the root label to it.
    pub fn chain_root(self) -> Chain<Self, Dname<&'static [u8]>>
    where
        Octets: AsRef<[u8]>,
    {
        self.chain(Dname::root()).unwrap()
    }
}

/// # Working with Labels
///
impl<Octets: AsRef<[u8]> + ?Sized> RelativeDname<Octets> {
    /// Returns an iterator over the labels of the domain name.
    pub fn iter(&self) -> DnameIter {
        DnameIter::new(self.0.as_ref())
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
    pub fn starts_with<'a, N: ToLabelIter<'a>>(
        &'a self,
        base: &'a N,
    ) -> bool {
        <Self as ToLabelIter>::starts_with(self, base)
    }

    /// Determines whether `base` is a suffix of `self`.
    pub fn ends_with<'a, N: ToLabelIter<'a>>(&'a self, base: &'a N) -> bool {
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
    pub fn slice(&self, begin: usize, end: usize) -> &RelativeDname<[u8]> {
        self.check_index(begin);
        RelativeDname::from_slice(&self.0.as_ref()[begin..end])
            .expect("end index not at start of a label")
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
    /// The method panics if the position is not the beginning of a label
    /// or is beyond the end of the name.
    ///
    /// [`range_from`]: #method.range_from
    pub fn slice_from(&self, begin: usize) -> &RelativeDname<[u8]> {
        self.check_index(begin);
        unsafe {
            RelativeDname::from_slice_unchecked(&self.0.as_ref()[begin..])
        }
    }

    /// Returns the part of the name ending before the given position.
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
    /// The method panics if the position is not the beginning of a label
    /// or is beyond the end of the name.
    ///
    /// [`range_to`]: #method.range_to
    pub fn slice_to(&self, end: usize) -> &RelativeDname<[u8]> {
        self.check_index(end);
        unsafe {
            RelativeDname::from_slice_unchecked(&self.0.as_ref()[..end])
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
    pub fn range<'a>(
        &'a self,
        begin: usize,
        end: usize,
    ) -> RelativeDname<<&'a Octets as OctetsRef>::Range>
    where
        &'a Octets: OctetsRef,
    {
        self.check_index(begin);
        RelativeDname::from_octets(self.0.range(begin, end))
            .expect("end index not a start of a label")
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
    /// The method panics if the position is not the beginning of a label
    /// or is beyond the end of the name.
    pub fn range_from<'a>(
        &'a self,
        begin: usize,
    ) -> RelativeDname<<&'a Octets as OctetsRef>::Range>
    where
        &'a Octets: OctetsRef,
    {
        self.check_index(begin);
        unsafe {
            RelativeDname::from_octets_unchecked(self.0.range_from(begin))
        }
    }

    /// Returns the part of the name ending before the given position.
    ///
    /// The returned name will start at beginning of the name and continue
    /// until just before the given postion. The position `end` is considered
    /// as an index into the underlying octets sequence and must point to the
    /// beginning of a label.
    ///
    /// # Panics
    ///
    /// The method panics if the position is not the beginning of a label
    /// or is beyond the end of the name.
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

impl<Octets: AsRef<[u8]>> RelativeDname<Octets> {
    /// Splits the name into two at the given position.
    ///
    /// Afterwards, `self` will contain the name ending before the position
    /// while the name starting at the position will be returned.
    ///
    /// # Panics
    ///
    /// The method panics if the position is not the beginning of a label
    /// or is beyond the end of the name.
    pub fn split_off(&mut self, mid: usize) -> Self
    where
        for<'a> &'a Octets: OctetsRef<Range = Octets>,
    {
        self.check_index(mid);
        let res = self.0.range_from(mid);
        self.0 = self.0.range_to(mid);
        unsafe { Self::from_octets_unchecked(res) }
    }

    /// Splits the name into two at the given position.
    ///
    /// Afterwards, `self` will contain the name starting at the position
    /// while the name ending right before it will be returned.
    ///
    /// # Panics
    ///
    /// The method panics if the position is not the beginning of a label
    /// or is beyond the end of the name.
    pub fn split_to(&mut self, mid: usize) -> Self
    where
        for<'a> &'a Octets: OctetsRef<Range = Octets>,
    {
        self.check_index(mid);
        let res = self.0.range_to(mid);
        self.0 = self.0.range_from(mid);
        unsafe { Self::from_octets_unchecked(res) }
    }

    /// Truncates the name to the given length.
    ///
    /// # Panics
    ///
    /// The method panics if the position is not the beginning of a label
    /// or is beyond the end of the name.
    pub fn truncate(&mut self, len: usize)
    where
        Octets: OctetsExt,
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
    pub fn split_first(&mut self) -> Option<Self>
    where
        for<'a> &'a Octets: OctetsRef<Range = Octets>,
    {
        if self.is_empty() {
            return None;
        }
        let end = match self.iter().next() {
            Some(label) => label.compose_len(),
            None => return None,
        };
        Some(self.split_to(end))
    }

    /// Reduces the name to its parent.
    ///
    /// Returns whether that actually happened, since an empty name doesn’t
    /// have a parent.
    pub fn parent(&mut self) -> bool
    where
        for<'a> &'a Octets: OctetsRef<Range = Octets>,
    {
        self.split_first().is_some()
    }

    /// Strips the suffix `base` from the domain name.
    ///
    /// This will fail if `base` isn’t actually a suffix, i.e., if
    /// [`ends_with`] doesn’t return `true`.
    ///
    /// [`ends_with`]: #method.ends_with
    pub fn strip_suffix<N: ToRelativeDname>(
        &mut self,
        base: &N,
    ) -> Result<(), StripSuffixError>
    where
        for<'a> &'a Octets: OctetsRef<Range = Octets>,
    {
        if self.ends_with(base) {
            let idx = self.0.as_ref().len() - base.len();
            self.0 = self.0.range_to(idx);
            Ok(())
        } else {
            Err(StripSuffixError)
        }
    }
}

//--- Deref and AsRef

impl<Octets: ?Sized> ops::Deref for RelativeDname<Octets> {
    type Target = Octets;

    fn deref(&self) -> &Octets {
        &self.0
    }
}

impl<Octets: AsRef<T> + ?Sized, T: ?Sized> AsRef<T>
    for RelativeDname<Octets>
{
    fn as_ref(&self) -> &T {
        self.0.as_ref()
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets> OctetsFrom<RelativeDname<SrcOctets>>
    for RelativeDname<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(
        source: RelativeDname<SrcOctets>,
    ) -> Result<Self, ShortBuf> {
        Octets::octets_from(source.0)
            .map(|octets| unsafe { Self::from_octets_unchecked(octets) })
    }
}

//--- ToLabelIter and ToRelativeDname

impl<'a, Octets> ToLabelIter<'a> for RelativeDname<Octets>
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

impl<Octets: AsRef<[u8]> + ?Sized> ToRelativeDname for RelativeDname<Octets> {
    fn as_flat_slice(&self) -> Option<&[u8]> {
        Some(self.0.as_ref())
    }

    fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }
}

//--- Compose

impl<Octets: AsRef<[u8]> + ?Sized> Compose for RelativeDname<Octets> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_slice(self.0.as_ref())
    }

    fn compose_canonical<T: OctetsBuilder + AsMut<[u8]>>(
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

//--- IntoIterator

impl<'a, Octets> IntoIterator for &'a RelativeDname<Octets>
where
    Octets: AsRef<[u8]> + ?Sized,
{
    type Item = &'a Label;
    type IntoIter = DnameIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- PartialEq and Eq

impl<Octets, N> PartialEq<N> for RelativeDname<Octets>
where
    Octets: AsRef<[u8]> + ?Sized,
    N: ToRelativeDname + ?Sized,
{
    fn eq(&self, other: &N) -> bool {
        self.name_eq(other)
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> Eq for RelativeDname<Octets> {}

//--- PartialOrd and Ord

impl<Octets, N> PartialOrd<N> for RelativeDname<Octets>
where
    Octets: AsRef<[u8]> + ?Sized,
    N: ToRelativeDname + ?Sized,
{
    fn partial_cmp(&self, other: &N) -> Option<cmp::Ordering> {
        Some(self.name_cmp(other))
    }
}

impl<Octets: AsRef<[u8]> + ?Sized> Ord for RelativeDname<Octets> {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        self.name_cmp(other)
    }
}

//--- Hash

impl<Octets: AsRef<[u8]> + ?Sized> hash::Hash for RelativeDname<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        for item in self.iter() {
            item.hash(state)
        }
    }
}

//--- Display and Debug

impl<Octets: AsRef<[u8]> + ?Sized> fmt::Display for RelativeDname<Octets> {
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

impl<Octets: AsRef<[u8]> + ?Sized> fmt::Debug for RelativeDname<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "RelativeDname({})", self)
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<Octets> serde::Serialize for RelativeDname<Octets>
where
    Octets: AsRef<[u8]> + SerializeOctets,
{
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_newtype_struct(
                "RelativeDname",
                &format_args!("{}", self),
            )
        } else {
            serializer.serialize_newtype_struct(
                "RelativeDname",
                &self.0.as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octets> serde::Deserialize<'de> for RelativeDname<Octets>
where
    Octets: FromBuilder + DeserializeOctets<'de>,
    <Octets as FromBuilder>::Builder: EmptyBuilder + AsMut<[u8]>,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octets> serde::de::Visitor<'de> for InnerVisitor<'de, Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder + AsMut<[u8]>,
        {
            type Value = RelativeDname<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a relative domain name")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> Result<Self::Value, E> {
                let mut builder = DnameBuilder::<Octets::Builder>::new();
                builder.append_chars(v.chars()).map_err(E::custom)?;
                Ok(builder.finish())
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    RelativeDname::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    RelativeDname::from_octets(octets).map_err(E::custom)
                })
            }
        }

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octets> serde::de::Visitor<'de> for NewtypeVisitor<Octets>
        where
            Octets: FromBuilder + DeserializeOctets<'de>,
            <Octets as FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets> + EmptyBuilder + AsMut<[u8]>,
        {
            type Value = RelativeDname<Octets>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a relative domain name")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_str(InnerVisitor(Octets::visitor()))
                } else {
                    Octets::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octets::visitor()),
                    )
                }
            }
        }

        deserializer.deserialize_newtype_struct(
            "RelativeDname",
            NewtypeVisitor(PhantomData),
        )
    }
}

//------------ DnameIter -----------------------------------------------------

/// An iterator over the labels in an uncompressed name.
#[derive(Clone, Debug)]
pub struct DnameIter<'a> {
    slice: &'a [u8],
}

impl<'a> DnameIter<'a> {
    pub(super) fn new(slice: &'a [u8]) -> Self {
        DnameIter { slice }
    }
}

impl<'a> Iterator for DnameIter<'a> {
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

impl<'a> DoubleEndedIterator for DnameIter<'a> {
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

//------------ RelativeDnameError --------------------------------------------

/// An error happened while creating a domain name from octets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelativeDnameError {
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

impl From<LabelTypeError> for RelativeDnameError {
    fn from(err: LabelTypeError) -> Self {
        RelativeDnameError::BadLabel(err)
    }
}

impl From<SplitLabelError> for RelativeDnameError {
    fn from(err: SplitLabelError) -> Self {
        match err {
            SplitLabelError::Pointer(_) => RelativeDnameError::CompressedName,
            SplitLabelError::BadType(t) => RelativeDnameError::BadLabel(t),
            SplitLabelError::ShortInput => RelativeDnameError::ShortInput,
        }
    }
}

//--- Display and Error

impl fmt::Display for RelativeDnameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RelativeDnameError::BadLabel(err) => err.fmt(f),
            RelativeDnameError::CompressedName => {
                f.write_str("compressed domain name")
            }
            RelativeDnameError::ShortInput => ParseError::ShortInput.fmt(f),
            RelativeDnameError::LongName => f.write_str("long domain name"),
            RelativeDnameError::AbsoluteName => {
                f.write_str("absolute domain name")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RelativeDnameError {}

//------------ StripSuffixError ----------------------------------------------

/// An attempt was made to strip a suffix that wasn’t actually a suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StripSuffixError;

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
        fn assert_to_relative_dname<T: ToRelativeDname + ?Sized>(_: &T) {}

        assert_to_relative_dname(
            RelativeDname::from_slice(b"\x03www".as_ref()).unwrap(),
        );
        assert_to_relative_dname(
            &RelativeDname::from_octets(b"\x03www").unwrap(),
        );
        assert_to_relative_dname(
            &RelativeDname::from_octets(b"\x03www".as_ref()).unwrap(),
        );
        assert_to_relative_dname(
            &RelativeDname::from_octets(Vec::from(b"\x03www".as_ref()))
                .unwrap(),
        );
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn impl_bytes() {
        fn assert_to_relative_dname<T: ToRelativeDname + ?Sized>(_: &T) {}

        assert_to_relative_dname(
            &RelativeDname::from_octets(Bytes::from(b"\x03www".as_ref()))
                .unwrap(),
        );
    }

    #[test]
    fn empty() {
        assert_eq!(RelativeDname::empty_slice().as_slice(), b"");
        assert_eq!(RelativeDname::empty_ref().as_slice(), b"");

        #[cfg(feature = "std")]
        {
            assert_eq!(RelativeDname::empty_vec().as_slice(), b"");
        }
    }

    #[test]
    fn wildcard() {
        assert_eq!(RelativeDname::wildcard_slice().as_slice(), b"\x01*");
        assert_eq!(RelativeDname::wildcard_ref().as_slice(), b"\x01*");

        #[cfg(feature = "std")]
        {
            assert_eq!(RelativeDname::wildcard_vec().as_slice(), b"\x01*");
        }
    }

    #[cfg(feature = "bytes")]
    #[test]
    fn literals_bytes() {
        assert_eq!(RelativeDname::empty_bytes().as_slice(), b"");
        assert_eq!(RelativeDname::wildcard_bytes().as_slice(), b"\x01*");
    }

    #[test]
    #[cfg(feature = "std")]
    fn from_slice() {
        // good names
        assert_eq!(RelativeDname::from_slice(b"").unwrap().as_slice(), b"");
        assert_eq!(
            RelativeDname::from_slice(b"\x03www").unwrap().as_slice(),
            b"\x03www"
        );
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07example")
                .unwrap()
                .as_slice(),
            b"\x03www\x07example"
        );

        // absolute names
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07example\x03com\0"),
            Err(RelativeDnameError::AbsoluteName)
        );
        assert_eq!(
            RelativeDname::from_slice(b"\0"),
            Err(RelativeDnameError::AbsoluteName)
        );

        // bytes shorter than what label length says.
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07exa"),
            Err(RelativeDnameError::ShortInput)
        );

        // label 63 long ok, 64 bad.
        let mut slice = [0u8; 64];
        slice[0] = 63;
        assert!(RelativeDname::from_slice(&slice[..]).is_ok());
        let mut slice = [0u8; 65];
        slice[0] = 64;
        assert!(RelativeDname::from_slice(&slice[..]).is_err());

        // name 254 long ok, 255 bad.
        let mut buf = Vec::new();
        for _ in 0..25 {
            buf.extend_from_slice(b"\x09123456789");
        }
        assert_eq!(buf.len(), 250);
        let mut tmp = buf.clone();
        tmp.extend_from_slice(b"\x03123");
        assert_eq!(RelativeDname::from_slice(&tmp).map(|_| ()), Ok(()));
        buf.extend_from_slice(b"\x041234");
        assert!(RelativeDname::from_slice(&buf).is_err());

        // bad label heads: compressed, other types.
        assert_eq!(
            RelativeDname::from_slice(b"\xa2asdasds"),
            Err(LabelTypeError::Undefined.into())
        );
        assert_eq!(
            RelativeDname::from_slice(b"\x62asdasds"),
            Err(LabelTypeError::Extended(0x62).into())
        );
        assert_eq!(
            RelativeDname::from_slice(b"\xccasdasds"),
            Err(RelativeDnameError::CompressedName)
        );
    }

    #[test]
    #[cfg(feature = "std")]
    fn into_absolute() {
        assert_eq!(
            RelativeDname::from_octets(Vec::from(
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
        RelativeDname::from_octets(tmp)
            .unwrap()
            .into_absolute()
            .unwrap();
    }

    // chain is tested with the Chain type.

    #[test]
    fn chain_root() {
        assert_eq!(
            Dname::from_octets(b"\x03www\x07example\x03com\0").unwrap(),
            RelativeDname::from_octets(b"\x03www\x07example\x03com")
                .unwrap()
                .chain_root()
        );
    }

    #[test]
    fn iter() {
        use crate::base::name::dname::test::cmp_iter;

        cmp_iter(RelativeDname::empty_ref().iter(), &[]);
        cmp_iter(RelativeDname::wildcard_ref().iter(), &[b"*"]);
        cmp_iter(
            RelativeDname::from_slice(b"\x03www\x07example\x03com")
                .unwrap()
                .iter(),
            &[b"www", b"example", b"com"],
        );
    }

    #[test]
    fn iter_back() {
        use crate::base::name::dname::test::cmp_iter_back;

        cmp_iter_back(RelativeDname::empty_ref().iter(), &[]);
        cmp_iter_back(RelativeDname::wildcard_ref().iter(), &[b"*"]);
        cmp_iter_back(
            RelativeDname::from_slice(b"\x03www\x07example\x03com")
                .unwrap()
                .iter(),
            &[b"com", b"example", b"www"],
        );
    }

    #[test]
    fn label_count() {
        assert_eq!(RelativeDname::empty_ref().label_count(), 0);
        assert_eq!(RelativeDname::wildcard_slice().label_count(), 1);
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07example\x03com")
                .unwrap()
                .label_count(),
            3
        );
    }

    #[test]
    fn first() {
        assert_eq!(RelativeDname::empty_slice().first(), None);
        assert_eq!(
            RelativeDname::from_slice(b"\x03www")
                .unwrap()
                .first()
                .unwrap()
                .as_slice(),
            b"www"
        );
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07example")
                .unwrap()
                .first()
                .unwrap()
                .as_slice(),
            b"www"
        );
    }

    #[test]
    fn last() {
        assert_eq!(RelativeDname::empty_slice().last(), None);
        assert_eq!(
            RelativeDname::from_slice(b"\x03www")
                .unwrap()
                .last()
                .unwrap()
                .as_slice(),
            b"www"
        );
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07example")
                .unwrap()
                .last()
                .unwrap()
                .as_slice(),
            b"example"
        );
    }

    #[test]
    fn ndots() {
        assert_eq!(RelativeDname::empty_slice().ndots(), 0);
        assert_eq!(RelativeDname::from_slice(b"\x03www").unwrap().ndots(), 0);
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07example")
                .unwrap()
                .ndots(),
            1
        );
    }

    #[test]
    fn starts_with() {
        let matrix = [
            (
                RelativeDname::empty_slice(),
                [true, false, false, false, false, false],
            ),
            (
                RelativeDname::from_slice(b"\x03www").unwrap(),
                [true, true, false, false, false, false],
            ),
            (
                RelativeDname::from_slice(b"\x03www\x07example").unwrap(),
                [true, true, true, false, false, false],
            ),
            (
                RelativeDname::from_slice(b"\x03www\x07example\x03com")
                    .unwrap(),
                [true, true, true, true, false, false],
            ),
            (
                RelativeDname::from_slice(b"\x07example\x03com").unwrap(),
                [true, false, false, false, true, false],
            ),
            (
                RelativeDname::from_slice(b"\x03com").unwrap(),
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
                RelativeDname::empty_slice(),
                [true, false, false, false, false, false],
            ),
            (
                RelativeDname::from_slice(b"\x03www").unwrap(),
                [true, true, false, false, false, false],
            ),
            (
                RelativeDname::from_slice(b"\x03www\x07example").unwrap(),
                [true, false, true, false, false, false],
            ),
            (
                RelativeDname::from_slice(b"\x03www\x07example\x03com")
                    .unwrap(),
                [true, false, false, true, true, true],
            ),
            (
                RelativeDname::from_slice(b"\x07example\x03com").unwrap(),
                [true, false, false, false, true, true],
            ),
            (
                RelativeDname::from_slice(b"\x03com").unwrap(),
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
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap();

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
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap();
        assert_eq!(wec.slice(0, 4).as_slice(), b"\x03www");
        assert_eq!(wec.slice(0, 12).as_slice(), b"\x03www\x07example");
        assert_eq!(wec.slice(4, 12).as_slice(), b"\x07example");
        assert_eq!(wec.slice(4, 16).as_slice(), b"\x07example\x03com");

        assert_panic!(wec.slice(0, 3));
        assert_panic!(wec.slice(1, 4));
        assert_panic!(wec.slice(0, 11));
        assert_panic!(wec.slice(1, 12));
        assert_panic!(wec.slice(0, 17));
        assert_panic!(wec.slice(4, 17));
        assert_panic!(wec.slice(0, 18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn slice_from() {
        let wec =
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap();

        assert_eq!(
            wec.slice_from(0).as_slice(),
            b"\x03www\x07example\x03com"
        );
        assert_eq!(wec.slice_from(4).as_slice(), b"\x07example\x03com");
        assert_eq!(wec.slice_from(12).as_slice(), b"\x03com");
        assert_eq!(wec.slice_from(16).as_slice(), b"");

        assert_panic!(wec.slice_from(17));
        assert_panic!(wec.slice_from(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn slice_to() {
        let wec =
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap();

        assert_eq!(wec.slice_to(0).as_slice(), b"");
        assert_eq!(wec.slice_to(4).as_slice(), b"\x03www");
        assert_eq!(wec.slice_to(12).as_slice(), b"\x03www\x07example");
        assert_eq!(wec.slice_to(16).as_slice(), b"\x03www\x07example\x03com");

        assert_panic!(wec.slice_to(17));
        assert_panic!(wec.slice_to(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn range() {
        let wec =
            RelativeDname::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();
        assert_eq!(wec.range(0, 4).as_slice(), b"\x03www");
        assert_eq!(wec.range(0, 12).as_slice(), b"\x03www\x07example");
        assert_eq!(wec.range(4, 12).as_slice(), b"\x07example");
        assert_eq!(wec.range(4, 16).as_slice(), b"\x07example\x03com");

        assert_panic!(wec.range(0, 3));
        assert_panic!(wec.range(1, 4));
        assert_panic!(wec.range(0, 11));
        assert_panic!(wec.range(1, 12));
        assert_panic!(wec.range(0, 17));
        assert_panic!(wec.range(4, 17));
        assert_panic!(wec.range(0, 18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn range_from() {
        let wec =
            RelativeDname::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();

        assert_eq!(
            wec.range_from(0).as_slice(),
            b"\x03www\x07example\x03com"
        );
        assert_eq!(wec.range_from(4).as_slice(), b"\x07example\x03com");
        assert_eq!(wec.range_from(12).as_slice(), b"\x03com");
        assert_eq!(wec.range_from(16).as_slice(), b"");

        assert_panic!(wec.range_from(17));
        assert_panic!(wec.range_from(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn range_to() {
        let wec =
            RelativeDname::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();

        assert_eq!(wec.range_to(0).as_slice(), b"");
        assert_eq!(wec.range_to(4).as_slice(), b"\x03www");
        assert_eq!(wec.range_to(12).as_slice(), b"\x03www\x07example");
        assert_eq!(wec.range_to(16).as_slice(), b"\x03www\x07example\x03com");

        assert_panic!(wec.range_to(17));
        assert_panic!(wec.range_to(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn split_off() {
        let wec =
            RelativeDname::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();

        let mut tmp = wec.clone();
        assert_eq!(tmp.split_off(0).as_slice(), b"\x03www\x07example\x03com");
        assert_eq!(tmp.as_slice(), b"");

        let mut tmp = wec.clone();
        assert_eq!(tmp.split_off(4).as_slice(), b"\x07example\x03com");
        assert_eq!(tmp.as_slice(), b"\x03www");

        let mut tmp = wec.clone();
        assert_eq!(tmp.split_off(12).as_slice(), b"\x03com");
        assert_eq!(tmp.as_slice(), b"\x03www\x07example");

        let mut tmp = wec.clone();
        assert_eq!(tmp.split_off(16).as_slice(), b"");
        assert_eq!(tmp.as_slice(), b"\x03www\x07example\x03com");

        assert_panic!(wec.clone().split_off(1));
        assert_panic!(wec.clone().split_off(14));
        assert_panic!(wec.clone().split_off(17));
        assert_panic!(wec.clone().split_off(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn split_to() {
        let wec =
            RelativeDname::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();

        let mut tmp = wec.clone();
        assert_eq!(tmp.split_to(0).as_slice(), b"");
        assert_eq!(tmp.as_slice(), b"\x03www\x07example\x03com");

        let mut tmp = wec.clone();
        assert_eq!(tmp.split_to(4).as_slice(), b"\x03www");
        assert_eq!(tmp.as_slice(), b"\x07example\x03com");

        let mut tmp = wec.clone();
        assert_eq!(tmp.split_to(12).as_slice(), b"\x03www\x07example");
        assert_eq!(tmp.as_slice(), b"\x03com");

        let mut tmp = wec.clone();
        assert_eq!(tmp.split_to(16).as_slice(), b"\x03www\x07example\x03com");
        assert_eq!(tmp.as_slice(), b"");

        assert_panic!(wec.clone().split_to(1));
        assert_panic!(wec.clone().split_to(14));
        assert_panic!(wec.clone().split_to(17));
        assert_panic!(wec.clone().split_to(18));
    }

    #[test]
    #[cfg(feature = "std")]
    fn truncate() {
        let wec =
            RelativeDname::from_octets(b"\x03www\x07example\x03com".as_ref())
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
        let mut wec =
            RelativeDname::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();

        assert_eq!(wec.split_first().unwrap().as_slice(), b"\x03www");
        assert_eq!(wec.as_slice(), b"\x07example\x03com");
        assert_eq!(wec.split_first().unwrap().as_slice(), b"\x07example");
        assert_eq!(wec.as_slice(), b"\x03com");
        assert_eq!(wec.split_first().unwrap().as_slice(), b"\x03com");
        assert_eq!(wec.as_slice(), b"");
        assert!(wec.split_first().is_none());
        assert_eq!(wec.as_slice(), b"");
        assert!(wec.split_first().is_none());
        assert_eq!(wec.as_slice(), b"");
    }

    #[test]
    fn parent() {
        let mut wec =
            RelativeDname::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();

        assert!(wec.parent());
        assert_eq!(wec.as_slice(), b"\x07example\x03com");
        assert!(wec.parent());
        assert_eq!(wec.as_slice(), b"\x03com");
        assert!(wec.parent());
        assert_eq!(wec.as_slice(), b"");
        assert!(!wec.parent());
        assert_eq!(wec.as_slice(), b"");
        assert!(!wec.parent());
        assert_eq!(wec.as_slice(), b"");
    }

    #[test]
    fn strip_suffix() {
        let wec =
            RelativeDname::from_octets(b"\x03www\x07example\x03com".as_ref())
                .unwrap();
        let ec = RelativeDname::from_octets(b"\x07example\x03com".as_ref())
            .unwrap();
        let c = RelativeDname::from_octets(b"\x03com".as_ref()).unwrap();
        let wen =
            RelativeDname::from_octets(b"\x03www\x07example\x03net".as_ref())
                .unwrap();
        let en = RelativeDname::from_octets(b"\x07example\x03net".as_ref())
            .unwrap();
        let n = RelativeDname::from_slice(b"\x03net".as_ref()).unwrap();

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
        assert_eq!(tmp.strip_suffix(&RelativeDname::empty_ref()), Ok(()));
        assert_eq!(tmp.as_slice(), b"\x03www\x07example\x03com");

        assert_eq!(wec.clone().strip_suffix(&wen), Err(StripSuffixError));
        assert_eq!(wec.clone().strip_suffix(&en), Err(StripSuffixError));
        assert_eq!(wec.clone().strip_suffix(&n), Err(StripSuffixError));
    }

    // No test for Compose since the implementation is so simple.

    #[test]
    fn eq() {
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap(),
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap()
        );
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap(),
            RelativeDname::from_slice(b"\x03wWw\x07eXAMple\x03Com").unwrap()
        );
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap(),
            &RelativeDname::from_octets(b"\x03www")
                .unwrap()
                .chain(
                    RelativeDname::from_octets(b"\x07example\x03com")
                        .unwrap()
                )
                .unwrap()
        );
        assert_eq!(
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap(),
            &RelativeDname::from_octets(b"\x03wWw")
                .unwrap()
                .chain(
                    RelativeDname::from_octets(b"\x07eXAMple\x03coM")
                        .unwrap()
                )
                .unwrap()
        );

        assert_ne!(
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap(),
            RelativeDname::from_slice(b"\x03ww4\x07example\x03com").unwrap()
        );
        assert_ne!(
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap(),
            &RelativeDname::from_octets(b"\x03www")
                .unwrap()
                .chain(
                    RelativeDname::from_octets(b"\x073xample\x03com")
                        .unwrap()
                )
                .unwrap()
        );
    }

    #[test]
    fn cmp() {
        use core::cmp::Ordering;

        // The following is taken from section 6.1 of RFC 4034.
        let names = [
            RelativeDname::from_slice(b"\x07example").unwrap(),
            RelativeDname::from_slice(b"\x01a\x07example").unwrap(),
            RelativeDname::from_slice(b"\x08yljkjljk\x01a\x07example")
                .unwrap(),
            RelativeDname::from_slice(b"\x01Z\x01a\x07example").unwrap(),
            RelativeDname::from_slice(b"\x04zABC\x01a\x07example").unwrap(),
            RelativeDname::from_slice(b"\x01z\x07example").unwrap(),
            RelativeDname::from_slice(b"\x01\x01\x01z\x07example").unwrap(),
            RelativeDname::from_slice(b"\x01*\x01z\x07example").unwrap(),
            RelativeDname::from_slice(b"\x01\xc8\x01z\x07example").unwrap(),
        ];
        for i in 0..names.len() {
            for j in 0..names.len() {
                let ord = i.cmp(&j);
                assert_eq!(names[i].partial_cmp(names[j]), Some(ord));
                assert_eq!(names[i].cmp(names[j]), ord);
            }
        }

        let n1 =
            RelativeDname::from_slice(b"\x03www\x07example\x03com").unwrap();
        let n2 =
            RelativeDname::from_slice(b"\x03wWw\x07eXAMple\x03Com").unwrap();
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
        RelativeDname::from_slice(b"\x03www\x07example\x03com")
            .unwrap()
            .hash(&mut s1);
        RelativeDname::from_slice(b"\x03wWw\x07eXAMple\x03Com")
            .unwrap()
            .hash(&mut s2);
        assert_eq!(s1.finish(), s2.finish());
    }

    // Display and Debug skipped for now.

    #[cfg(all(feature = "serde", feature = "std"))]
    #[test]
    fn ser_de() {
        use serde_test::{assert_tokens, Configure, Token};

        let name = RelativeDname::from_octets(Vec::from(
            b"\x03www\x07example\x03com".as_ref(),
        ))
        .unwrap();
        assert_tokens(
            &name.clone().compact(),
            &[
                Token::NewtypeStruct {
                    name: "RelativeDname",
                },
                Token::ByteBuf(b"\x03www\x07example\x03com"),
            ],
        );
        assert_tokens(
            &name.readable(),
            &[
                Token::NewtypeStruct {
                    name: "RelativeDname",
                },
                Token::Str("www.example.com"),
            ],
        );
    }
}
