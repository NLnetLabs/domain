//! Domain name-related traits.
//!
//! This is a private module. Its public traits are re-exported by the parent.

use super::absolute::Name;
use super::chain::{Chain, LongChainError};
use super::label::Label;
use super::relative::RelativeName;
#[cfg(feature = "bytes")]
use bytes::Bytes;
use core::convert::Infallible;
use core::{cmp, fmt};
use octseq::builder::{
    infallible, BuilderAppendError, EmptyBuilder, FreezeBuilder, FromBuilder,
    OctetsBuilder, ShortBuf,
};
#[cfg(feature = "std")]
use std::borrow::Cow;

//------------ ToLabelIter ---------------------------------------------------

/// A type that can produce an iterator over its labels.
///
/// This trait is used as a trait bound for both [`ToName`] and
/// [`ToRelativeName`]. It is separate since it has to be generic over the
/// lifetime of the label reference but we don’t want to have this lifetime
/// parameter pollute those traits.
pub trait ToLabelIter {
    /// The type of the iterator over the labels.
    ///
    /// This iterator types needs to be double ended so that we can deal with
    /// name suffixes. It needs to be cloneable to be able to cascade over
    /// parents of a name.
    type LabelIter<'a>: Iterator<Item = &'a Label>
        + DoubleEndedIterator
        + Clone
    where
        Self: 'a;

    /// Returns an iterator over the labels.
    fn iter_labels(&self) -> Self::LabelIter<'_>;

    /// Returns the length in octets of the encoded name.
    fn compose_len(&self) -> u16 {
        self.iter_labels().map(|label| label.compose_len()).sum()
    }

    /// Determines whether `base` is a prefix of `self`.
    fn starts_with<N: ToLabelIter + ?Sized>(&self, base: &N) -> bool {
        let mut self_iter = self.iter_labels();
        let mut base_iter = base.iter_labels();
        loop {
            match (self_iter.next(), base_iter.next()) {
                (Some(sl), Some(bl)) => {
                    if sl != bl {
                        return false;
                    }
                }
                (_, None) => return true,
                (None, Some(_)) => return false,
            }
        }
    }

    /// Determines whether `base` is a suffix of `self`.
    fn ends_with<N: ToLabelIter + ?Sized>(&self, base: &N) -> bool {
        let mut self_iter = self.iter_labels();
        let mut base_iter = base.iter_labels();
        loop {
            match (self_iter.next_back(), base_iter.next_back()) {
                (Some(sl), Some(bl)) => {
                    if sl != bl {
                        return false;
                    }
                }
                (_, None) => return true,
                (None, Some(_)) => return false,
            }
        }
    }
}

impl<'r, N: ToLabelIter + ?Sized> ToLabelIter for &'r N {
    type LabelIter<'a> = N::LabelIter<'a> where 'r: 'a, N: 'a;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        (*self).iter_labels()
    }
}

//------------ ToName -------------------------------------------------------

/// A type that represents an absolute domain name.
///
/// An absolute domain name is a sequence of labels where the last label is
/// the root label and where the wire-format representation is not longer than
/// 255 characters. Implementers of this trait need to provide access to the
/// label sequence via an iterator and know how to compose the wire-format
/// representation into a buffer.
///
/// The most common types implementing this trait are [`Name`],
/// [`ParsedName`], and [`Chain<L, R>`] where `R` is [`ToName`] itself.
///
/// [`ParsedName`]: crate::base::name::ParsedName
pub trait ToName: ToLabelIter {
    /// Converts the name into a single, uncompressed name.
    ///
    /// The default implementation provided by the trait iterates over the
    /// labels of the name and adds them one by one to [`Name`]. This will
    /// work for any name but an optimized implementation can be provided for
    /// some types of names.
    fn try_to_name<Octets>(
        &self,
    ) -> Result<Name<Octets>, BuilderAppendError<Octets>>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        let mut builder =
            Octets::Builder::with_capacity(self.compose_len().into());
        self.iter_labels()
            .try_for_each(|label| label.compose(&mut builder))?;
        Ok(unsafe { Name::from_octets_unchecked(builder.freeze()) })
    }

    /// Converts the name into a single, uncompressed name.
    ///
    /// This is the same as [`try_to_name`][ToName::try_to_name] but for
    /// builder types with an unrestricted buffer.
    fn to_name<Octets>(&self) -> Name<Octets>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder:
            OctetsBuilder<AppendError = Infallible>,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        infallible(self.try_to_name())
    }

    /// Converts the name into a single name in canonical form.
    fn try_to_canonical_name<Octets>(
        &self,
    ) -> Result<Name<Octets>, BuilderAppendError<Octets>>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        let mut builder =
            Octets::Builder::with_capacity(self.compose_len().into());
        self.iter_labels()
            .try_for_each(|label| label.compose_canonical(&mut builder))?;
        Ok(unsafe { Name::from_octets_unchecked(builder.freeze()) })
    }

    /// Converts the name into a single name in canonical form.
    ///
    /// This is the same as
    /// [`try_to_canonical_name`][ToName::try_to_canonical_name] but for
    /// builder types with an unrestricted buffer.
    fn to_canonical_name<Octets>(&self) -> Name<Octets>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder:
            OctetsBuilder<AppendError = Infallible>,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        infallible(self.try_to_canonical_name())
    }

    /// Returns an octets slice of the content if possible.
    ///
    /// If a value stores the domain name as one single octets sequence, it
    /// should return a reference to this sequence here. If the name is
    /// composed from multiple such sequences, it should return `None`.
    ///
    /// This method is used to optimize comparision operations between
    /// two values that are indeed flat names.
    fn as_flat_slice(&self) -> Option<&[u8]> {
        None
    }

    fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if let Some(slice) = self.as_flat_slice() {
            target.append_slice(slice)
        } else {
            for label in self.iter_labels() {
                label.compose(target)?;
            }
            Ok(())
        }
    }

    fn compose_canonical<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        for label in self.iter_labels() {
            label.compose_canonical(target)?;
        }
        Ok(())
    }

    /// Returns a cow of the domain name.
    ///
    /// If the name is available as one single slice – i.e.,
    /// [`as_flat_slice`] returns ‘some,’ creates the borrowed variant from
    /// that slice. Otherwise assembles an owned variant via [`to_name`].
    ///
    /// [`as_flat_slice`]: ToName::as_flat_slice
    /// [`to_name`]: ToName::to_name
    #[cfg(feature = "std")]
    fn to_cow(&self) -> Name<std::borrow::Cow<[u8]>> {
        let octets = self
            .as_flat_slice()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(self.to_vec().into_octets()));
        unsafe { Name::from_octets_unchecked(octets) }
    }

    /// Returns the domain name assembled into a `Vec<u8>`.
    #[cfg(feature = "std")]
    fn to_vec(&self) -> Name<std::vec::Vec<u8>> {
        self.to_name()
    }

    /// Returns the domain name assembled into a bytes value.
    #[cfg(feature = "bytes")]
    fn to_bytes(&self) -> Name<Bytes> {
        self.to_name()
    }

    /// Tests whether `self` and `other` are equal.
    ///
    /// This method can be used to implement [`PartialEq`] on types implementing
    /// [`ToName`] since a blanket implementation for all pairs of `ToName`
    /// is currently impossible.
    ///
    /// Domain names are compared ignoring ASCII case.
    fn name_eq<N: ToName + ?Sized>(&self, other: &N) -> bool {
        if let (Some(left), Some(right)) =
            (self.as_flat_slice(), other.as_flat_slice())
        {
            // We can do this because the length octets of each label are in
            // the ranged 0..64 which is before all ASCII letters.
            left.eq_ignore_ascii_case(right)
        } else {
            self.iter_labels().eq(other.iter_labels())
        }
    }

    /// Returns the ordering between `self` and `other`.
    ///
    /// This method can be used to implement both [`PartialOrd`] and [`Ord`] on
    /// types implementing [`ToName`] since a blanket implementation for all
    /// pairs of [`ToName`]s is currently not possible.
    ///
    /// Domain name order is determined according to the ‘canonical DNS
    /// name order’ as defined in [section 6.1 of RFC 4034][RFC4034-6.1].
    ///
    /// [RFC4034-6.1]: https://tools.ietf.org/html/rfc4034#section-6.1
    fn name_cmp<N: ToName + ?Sized>(&self, other: &N) -> cmp::Ordering {
        let mut self_iter = self.iter_labels();
        let mut other_iter = other.iter_labels();
        loop {
            match (self_iter.next_back(), other_iter.next_back()) {
                (Some(left), Some(right)) => match left.cmp(right) {
                    cmp::Ordering::Equal => {}
                    res => return res,
                },
                (None, Some(_)) => return cmp::Ordering::Less,
                (Some(_), None) => return cmp::Ordering::Greater,
                (None, None) => return cmp::Ordering::Equal,
            }
        }
    }

    /// Returns the composed name ordering.
    fn composed_cmp<N: ToName + ?Sized>(&self, other: &N) -> cmp::Ordering {
        if let (Some(left), Some(right)) =
            (self.as_flat_slice(), other.as_flat_slice())
        {
            return left.cmp(right);
        }
        let mut self_iter = self.iter_labels();
        let mut other_iter = other.iter_labels();
        loop {
            match (self_iter.next(), other_iter.next()) {
                (Some(left), Some(right)) => match left.composed_cmp(right) {
                    cmp::Ordering::Equal => {}
                    other => return other,
                },
                (None, None) => return cmp::Ordering::Equal,
                _ => {
                    // The root label sorts before any other label, so we
                    // can never end up in a situation where one name runs
                    // out of labels while comparing equal.
                    unreachable!()
                }
            }
        }
    }

    /// Returns the lowercase composed ordering.
    fn lowercase_composed_cmp<N: ToName + ?Sized>(
        &self,
        other: &N,
    ) -> cmp::Ordering {
        // Since there isn’t a `cmp_ignore_ascii_case` on slice, we don’t
        // gain much from the shortcut.
        let mut self_iter = self.iter_labels();
        let mut other_iter = other.iter_labels();
        loop {
            match (self_iter.next(), other_iter.next()) {
                (Some(left), Some(right)) => {
                    match left.lowercase_composed_cmp(right) {
                        cmp::Ordering::Equal => {}
                        other => return other,
                    }
                }
                (None, None) => return cmp::Ordering::Equal,
                _ => {
                    // The root label sorts before any other label, so we
                    // can never end up in a situation where one name runs
                    // out of labels while comparing equal.
                    unreachable!()
                }
            }
        }
    }

    /// Returns the number of labels for the RRSIG Labels field.
    ///
    /// This is the actual number of labels without counting the root label
    /// or a possible initial asterisk label.
    fn rrsig_label_count(&self) -> u8 {
        let mut labels = self.iter_labels();
        if labels.next().unwrap().is_wildcard() {
            (labels.count() - 1) as u8
        } else {
            labels.count() as u8
        }
    }

    fn fmt_with_dot(&self) -> DisplayWithDot<'_, Self> {
        DisplayWithDot(self)
    }
}

pub struct DisplayWithDot<'a, T: ?Sized>(&'a T);

impl<T> fmt::Display for DisplayWithDot<'_, T>
where
    T: ToLabelIter + ?Sized,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut labels = self.0.iter_labels();
        let first = match labels.next() {
            Some(first) => first,
            None => unreachable!("at least 1 label must be present"),
        };

        if first.is_root() {
            f.write_str(".")
        } else {
            write!(f, "{}", first)?;
            for label in labels {
                write!(f, ".{}", label)?
            }
            Ok(())
        }
    }
}

impl<'a, N: ToName + ?Sized + 'a> ToName for &'a N {}

//------------ ToRelativeName ------------------------------------------------

/// A type that represents a relative domain name.
///
/// In order to be a relative domain name, a type needs to be able to
/// provide a sequence of labels via an iterator where the last label is not
/// the root label. The type also needs to be able to compose the wire-format
/// representation of the domain name it represents which must not be longer
/// than 254 characters. This limit has been chosen so that by attaching the
/// one character long root label, a valid absolute name can be constructed
/// from the relative name.
///
/// The most important types implementing this trait are [`RelativeName`]
/// and [`Chain<L,R>`] where `R` is a [`ToRelativeName`] itself.
pub trait ToRelativeName: ToLabelIter {
    /// Converts the name into a single, continous name.
    ///
    /// The canonical implementation provided by the trait iterates over the
    /// labels of the name and adds them one by one to [`RelativeName`].
    /// This will work for any name but an optimized implementation can be
    /// provided for some types of names.
    fn try_to_relative_name<Octets>(
        &self,
    ) -> Result<RelativeName<Octets>, BuilderAppendError<Octets>>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        let mut builder =
            Octets::Builder::with_capacity(self.compose_len().into());
        self.iter_labels()
            .try_for_each(|label| label.compose(&mut builder))?;
        Ok(unsafe { RelativeName::from_octets_unchecked(builder.freeze()) })
    }

    /// Converts the name into a single, continous name.
    ///
    /// This is the same as
    /// [`try_to_relative_name`][ToRelativeName::try_to_relative_name]
    /// but for builder types with an unrestricted buffer.
    fn to_relative_name<Octets>(&self) -> RelativeName<Octets>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder:
            OctetsBuilder<AppendError = Infallible>,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        infallible(self.try_to_relative_name())
    }

    /// Converts the name into a single name in canonical form.
    fn try_to_canonical_relative_name<Octets>(
        &self,
    ) -> Result<RelativeName<Octets>, BuilderAppendError<Octets>>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        let mut builder =
            Octets::Builder::with_capacity(self.compose_len().into());
        self.iter_labels()
            .try_for_each(|label| label.compose_canonical(&mut builder))?;
        Ok(unsafe { RelativeName::from_octets_unchecked(builder.freeze()) })
    }

    /// Converts the name into a single name in canonical form.
    ///
    /// This is the same as
    /// [`try_to_canonical_relative_name`][ToRelativeName::try_to_canonical_relative_name]
    /// but for builder types with an unrestricted buffer.
    fn to_canonical_relative_name<Octets>(&self) -> RelativeName<Octets>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder:
            OctetsBuilder<AppendError = Infallible>,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        infallible(self.try_to_canonical_relative_name())
    }

    /// Returns a byte slice of the content if possible.
    ///
    /// This method can is used to optimize comparision operations between
    /// two values that are indeed flat names.
    fn as_flat_slice(&self) -> Option<&[u8]> {
        None
    }

    fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if let Some(slice) = self.as_flat_slice() {
            target.append_slice(slice)
        } else {
            for label in self.iter_labels() {
                label.compose(target)?;
            }
            Ok(())
        }
    }

    fn compose_canonical<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        for label in self.iter_labels() {
            label.compose_canonical(target)?;
        }
        Ok(())
    }

    /// Returns a cow of the relative domain name.
    ///
    /// If the name is available as one single slice – i.e.,
    /// [`as_flat_slice`] returns ‘some,’ creates the borrowed variant from
    /// that slice. Otherwise assembles an owned variant via
    /// [`to_relative_name`].
    ///
    /// [`as_flat_slice`]: ToRelativeName::as_flat_slice
    /// [`to_relative_name`]: ToRelativeName::to_relative_name
    #[cfg(feature = "std")]
    fn to_cow(&self) -> RelativeName<std::borrow::Cow<[u8]>> {
        let octets = self
            .as_flat_slice()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(self.to_vec().into_octets()));
        unsafe { RelativeName::from_octets_unchecked(octets) }
    }

    /// Returns the domain name assembled into a `Vec<u8>`.
    #[cfg(feature = "std")]
    fn to_vec(&self) -> RelativeName<std::vec::Vec<u8>> {
        self.to_relative_name()
    }

    /// Returns the domain name assembled into a bytes value.
    #[cfg(feature = "bytes")]
    fn to_bytes(&self) -> RelativeName<Bytes> {
        self.to_relative_name()
    }

    /// Returns whether the name is empty.
    fn is_empty(&self) -> bool {
        self.iter_labels().next().is_none()
    }

    /// Returns a chain of this name and the provided name.
    fn chain<N: ToLabelIter>(
        self,
        suffix: N,
    ) -> Result<Chain<Self, N>, LongChainError>
    where
        Self: Sized,
    {
        Chain::new(self, suffix)
    }

    /// Returns the absolute name by chaining it with the root label.
    fn chain_root(self) -> Chain<Self, Name<&'static [u8]>>
    where
        Self: Sized,
    {
        // Appending the root label will always work.
        Chain::new(self, Name::root()).unwrap()
    }

    /// Tests whether `self` and `other` are equal.
    ///
    /// This method can be used to implement [`PartialEq`] on types implementing
    /// [`ToName`] since a blanket implementation for all pairs of [`ToName`]
    /// is currently impossible.
    ///
    /// Domain names are compared ignoring ASCII case.
    fn name_eq<N: ToRelativeName + ?Sized>(&self, other: &N) -> bool {
        if let (Some(left), Some(right)) =
            (self.as_flat_slice(), other.as_flat_slice())
        {
            left.eq_ignore_ascii_case(right)
        } else {
            self.iter_labels().eq(other.iter_labels())
        }
    }

    /// Returns the ordering between `self` and `other`.
    ///
    /// This method can be used to implement both `PartialOrd` and `Ord` on
    /// types implementing `ToName` since a blanket implementation for all
    /// pairs of `ToName`s is currently not possible.
    ///
    /// Domain name order is determined according to the ‘canonical DNS
    /// name order’ as defined in [section 6.1 of RFC 4034][RFC4034-6.1].
    /// This section describes how absolute domain names are ordered only.
    /// We will order relative domain names according to these rules as if
    /// they had the same origin, i.e., as if they were relative to the
    /// same name.
    ///
    /// [RFC4034-6.1]: https://tools.ietf.org/html/rfc4034#section-6.1
    fn name_cmp<N: ToRelativeName + ?Sized>(
        &self,
        other: &N,
    ) -> cmp::Ordering {
        let mut self_iter = self.iter_labels();
        let mut other_iter = other.iter_labels();
        loop {
            match (self_iter.next_back(), other_iter.next_back()) {
                (Some(left), Some(right)) => match left.cmp(right) {
                    cmp::Ordering::Equal => {}
                    res => return res,
                },
                (None, Some(_)) => return cmp::Ordering::Less,
                (Some(_), None) => return cmp::Ordering::Greater,
                (None, None) => return cmp::Ordering::Equal,
            }
        }
    }
}

impl<'a, N: ToRelativeName + ?Sized + 'a> ToRelativeName for &'a N {}

//------------ FlattenInto ---------------------------------------------------

pub trait FlattenInto<Target>: Sized {
    type AppendError: Into<ShortBuf>;

    fn try_flatten_into(self) -> Result<Target, Self::AppendError>;

    fn flatten_into(self) -> Target
    where
        Self::AppendError: Into<Infallible>,
    {
        infallible(self.try_flatten_into())
    }
}
