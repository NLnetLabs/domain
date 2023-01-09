//! Domain name-related traits.
//!
//! This is a private module. Its public traits are re-exported by the parent.

use super::builder::PushError;
use super::chain::{Chain, LongChainError};
use super::dname::Dname;
use super::label::Label;
use super::relative::RelativeDname;
#[cfg(feature = "bytes")]
use bytes::Bytes;
use core::cmp;
use octseq::builder::{
    EmptyBuilder, FreezeBuilder, FromBuilder, OctetsBuilder,
};
#[cfg(feature = "std")]
use std::borrow::Cow;

//------------ ToLabelIter ---------------------------------------------------

/// A type that can produce an iterator over its labels.
///
/// This trait is used as a trait bound for both [`ToDname`] and
/// [`ToRelativeDname`]. It is separate since it has to be generic over the
/// lifetime of the label reference but we don’t want to have this lifetime
/// parameter pollute those traits.
///
/// [`ToDname`]: trait.ToDname.html
/// [`ToRelativeDname`]: trait ToRelativeDname.html
#[allow(clippy::len_without_is_empty)]
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

//------------ ToDname -------------------------------------------------------

/// A type that represents an absolute domain name.
///
/// An absolute domain name is a sequence of labels where the last label is
/// the root label and where the wire-format representation is not longer than
/// 255 characters. Implementers of this trait need to provide access to the
/// label sequence via an iterator and know how to compose the wire-format
/// representation into a buffer.
///
/// The most common types implementing this trait are [`Dname`],
/// [`ParsedDname`], and [`Chain<L, R>`] where `R` is `ToDname` itself.
///
/// [`Chain<L, R>`]: struct.Chain.html
/// [`Dname`]: struct.Dname.html
/// [`ParsedDname`]: struct.ParsedDname.html
pub trait ToDname: ToLabelIter {
    /// Converts the name into a single, uncompressed name.
    ///
    /// The canonical implementation provided by the trait iterates over the
    /// labels of the name and adds them one by one to [`Dname`]. This will
    /// work for any name but an optimized implementation can be provided for
    /// some types of names.
    ///
    /// [`Dname`]: struct.Dname.html
    fn to_dname<Octets>(&self) -> Result<Dname<Octets>, PushError>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        let mut builder =
            Octets::Builder::with_capacity(self.compose_len().into());
        for label in self.iter_labels() {
            label
                .compose(&mut builder)
                .map_err(|_| PushError::ShortBuf)?;
        }
        Ok(unsafe { Dname::from_octets_unchecked(builder.freeze()) })
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
    /// that slice. Otherwise assembles an owned variant via [`to_dname`].
    ///
    /// [`as_flat_slice`]: #method.as_flat_slice
    /// [`to_dname`]: #method.to_dname
    #[cfg(feature = "std")]
    fn to_cow(&self) -> Dname<std::borrow::Cow<[u8]>> {
        let octets = self
            .as_flat_slice()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(self.to_vec().into_octets()));
        unsafe { Dname::from_octets_unchecked(octets) }
    }

    /// Returns the domain name assembled into a `Vec<u8>`.
    #[cfg(feature = "std")]
    fn to_vec(&self) -> Dname<std::vec::Vec<u8>> {
        self.to_dname().unwrap()
    }

    /// Returns the domain name assembled into a bytes value.
    #[cfg(feature = "bytes")]
    fn to_bytes(&self) -> Dname<Bytes> {
        self.to_dname().unwrap()
    }

    /// Tests whether `self` and `other` are equal.
    ///
    /// This method can be used to implement `PartialEq` on types implementing
    /// `ToDname` since a blanket implementation for all pairs of `ToDname`
    /// is currently impossible.
    ///
    /// Domain names are compared ignoring ASCII case.
    fn name_eq<N: ToDname + ?Sized>(&self, other: &N) -> bool {
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
    /// This method can be used to implement both `PartialOrd` and `Ord` on
    /// types implementing `ToDname` since a blanket implementation for all
    /// pairs of `ToDname`s is currently not possible.
    ///
    /// Domain name order is determined according to the ‘canonical DNS
    /// name order’ as defined in [section 6.1 of RFC 4034][RFC4034-6.1].
    ///
    /// [RFC4034-6.1]: https://tools.ietf.org/html/rfc4034#section-6.1
    fn name_cmp<N: ToDname + ?Sized>(&self, other: &N) -> cmp::Ordering {
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
    fn composed_cmp<N: ToDname + ?Sized>(&self, other: &N) -> cmp::Ordering {
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
    fn lowercase_composed_cmp<N: ToDname + ?Sized>(
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
}

impl<'a, N: ToDname + ?Sized + 'a> ToDname for &'a N {}

//------------ ToRelativeDname -----------------------------------------------

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
/// The most important types implementing this trait are [`RelativeDname`]
/// and [`Chain<L,R>`] where `R` is a `ToRelativeDname` itself.
///
/// [`Chain<L, R>`]: struct.Chain.html
/// [`RelativeDname`]: struct.RelativeDname.html
pub trait ToRelativeDname: ToLabelIter {
    /// Converts the name into a single, continous name.
    ///
    /// The canonical implementation provided by the trait iterates over the
    /// labels of the name and adds them one by one to [`RelativeDname`].
    /// This will work for any name but an optimized implementation can be
    /// provided for
    /// some types of names.
    ///
    /// [`RelativeDname`]: struct.RelativeDname.html
    fn to_relative_dname<Octets>(
        &self,
    ) -> Result<RelativeDname<Octets>, PushError>
    where
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder: EmptyBuilder,
    {
        let mut builder =
            Octets::Builder::with_capacity(self.compose_len().into());
        for label in self.iter_labels() {
            label
                .compose(&mut builder)
                .map_err(|_| PushError::ShortBuf)?;
        }
        Ok(unsafe { RelativeDname::from_octets_unchecked(builder.freeze()) })
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
    /// that slice. Otherwise assembles an owned variant via [`to_dname`].
    ///
    /// [`as_flat_slice`]: #method.as_flat_slice
    /// [`to_dname`]: #method.to_dname
    #[cfg(feature = "std")]
    fn to_cow(&self) -> RelativeDname<std::borrow::Cow<[u8]>> {
        let octets = self
            .as_flat_slice()
            .map(Cow::Borrowed)
            .unwrap_or_else(|| Cow::Owned(self.to_vec().into_octets()));
        unsafe { RelativeDname::from_octets_unchecked(octets) }
    }

    /// Returns the domain name assembled into a `Vec<u8>`.
    #[cfg(feature = "std")]
    fn to_vec(&self) -> RelativeDname<std::vec::Vec<u8>> {
        self.to_relative_dname().unwrap()
    }

    /// Returns the domain name assembled into a bytes value.
    #[cfg(feature = "bytes")]
    fn to_bytes(&self) -> RelativeDname<Bytes> {
        self.to_relative_dname().unwrap()
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
    fn chain_root(self) -> Chain<Self, Dname<&'static [u8]>>
    where
        Self: Sized,
    {
        // Appending the root label will always work.
        Chain::new(self, Dname::root()).unwrap()
    }

    /// Tests whether `self` and `other` are equal.
    ///
    /// This method can be used to implement `PartialEq` on types implementing
    /// `ToDname` since a blanket implementation for all pairs of `ToDname`
    /// is currently impossible.
    ///
    /// Domain names are compared ignoring ASCII case.
    fn name_eq<N: ToRelativeDname + ?Sized>(&self, other: &N) -> bool {
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
    /// types implementing `ToDname` since a blanket implementation for all
    /// pairs of `ToDname`s is currently not possible.
    ///
    /// Domain name order is determined according to the ‘canonical DNS
    /// name order’ as defined in [section 6.1 of RFC 4034][RFC4034-6.1].
    /// This section describes how absolute domain names are ordered only.
    /// We will order relative domain names according to these rules as if
    /// they had the same origin, i.e., as if they were relative to the
    /// same name.
    ///
    /// [RFC4034-6.1]: https://tools.ietf.org/html/rfc4034#section-6.1
    fn name_cmp<N: ToRelativeDname + ?Sized>(
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

impl<'a, N: ToRelativeDname + ?Sized + 'a> ToRelativeDname for &'a N {}
