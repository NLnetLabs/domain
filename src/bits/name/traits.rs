//! Domain name-related traits.

use std::cmp;
use bytes::BytesMut;
use ::bits::compose::{Compose, Compress};
use super::dname::Dname;
use super::label::Label;
use super::relative::RelativeDname;


//------------ ToLabelIter ---------------------------------------------------

/// A type that can produce an iterator over its labels.
///
/// This trait is used as a trait bound for both [`ToDname`] and
/// [`ToRelativeDname`]. It is separate since it has to be generic over the
/// lifetime of the label reference but we don’t want to have this lifetime
/// parameter pollute those traits.
pub trait ToLabelIter<'a> {
    /// The type of the iterator over the labels.
    ///
    /// This iterator types needs to be double ended so that we can deal with
    /// name suffixes.
    type LabelIter: Iterator<Item=&'a Label> + DoubleEndedIterator;

    /// Returns an iterator over the labels.
    fn iter_labels(&'a self) -> Self::LabelIter;

    /// Determines whether `base` is a prefix of `self`.
    fn starts_with<N: ToLabelIter<'a>>(&'a self, base: &'a N) -> bool {
        let mut self_iter = self.iter_labels();
        let mut base_iter = base.iter_labels();
        loop {
            match (self_iter.next(), base_iter.next()) {
                (Some(sl), Some(bl)) => {
                    if sl != bl { return false }
                }
                (_, None) => return true,
                (None, Some(_)) => return false,
            }
        }
    }

    /// Determines whether `base` is a suffix of `self`.
    fn ends_with<N: ToLabelIter<'a>>(&'a self, base: &'a N) -> bool {
        let mut self_iter = self.iter_labels();
        let mut base_iter = base.iter_labels();
        loop {
            match (self_iter.next_back(), base_iter.next_back()) {
                (Some(sl), Some(bl)) => {
                    if sl != bl { return false }
                }
                (_, None) => return true,
                (None, Some(_)) =>  return false
            }
        }
    }
}

impl<'a, 'b, N: ToLabelIter<'b>> ToLabelIter<'b> for &'a N {
    type LabelIter = N::LabelIter;

    fn iter_labels(&'b self) -> Self::LabelIter {
        (*self).iter_labels()
    }
}


//------------ ToRelativeDname -----------------------------------------------

/// A type that represents a relative domain name.
///
/// In order to be a relative domain name, a type needs to be able to
/// provide a sequence of labels via an iterator where the last label is not
/// the root label. The type also needs to be able to compose the wire-format
/// representation of the domain name it represents which must not be longer
/// than 255 characters.
///
/// The most important types implementing this trait are [`RelativeDname`]
/// and [`Chain<L,R>`] where `R` is a `ToRelativeDname` itself.
///
/// [`Chain<L, R>`]: struct.Chain.html
/// [`RelativeDname`]: struct.RelativeDname.html
pub trait ToRelativeDname: Compose + for<'a> ToLabelIter<'a> {
    /// Creates an uncompressed value of the domain name.
    ///
    /// The method has a default implementation that composes the name into
    /// a new buffer and returns this buffer. If the implementing type can
    /// create a `RelativeDname` more efficiently, then it should provide its
    /// own implementation.
    fn to_name(&self) -> RelativeDname {
        let mut bytes = BytesMut::with_capacity(self.compose_len());
        self.compose(&mut bytes);
        unsafe {
            RelativeDname::from_bytes_unchecked(bytes.freeze())
        }
    }

    /// Returns a byte slice of the content if possible.
    ///
    /// This method can is used to optimize comparision operations between
    /// two values that are indeed flat names.
    fn as_flat_slice(&self) -> Option<&[u8]> {
        None
    }

    fn name_eq<N: ToRelativeDname>(&self, other: &N) -> bool {
        if let (Some(left), Some(right)) = (self.as_flat_slice(),
                                            other.as_flat_slice()) {
            left.eq_ignore_ascii_case(right)
        }
        else {
            self.iter_labels().eq(other.iter_labels())
        }
    }

    fn name_cmp<N: ToRelativeDname>(&self, other: &N) -> cmp::Ordering {
        let mut self_iter = self.iter_labels();
        let mut other_iter = other.iter_labels();
        loop {
            match (self_iter.next_back(), other_iter.next_back()) {
                (Some(left), Some(right)) => {
                    match left.cmp(right) {
                        cmp::Ordering::Equal => {}
                        res => return res
                    }
                }
                (None, Some(_)) => return cmp::Ordering::Less,
                (Some(_), None) => return cmp::Ordering::Greater,
                (None, None) => return cmp::Ordering::Equal
            }
        }
    }
}

impl<'a, N: ToRelativeDname + 'a> ToRelativeDname for &'a N { }


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
pub trait ToDname: Compose + Compress + for<'a> ToLabelIter<'a> {
    /// Creates an uncompressed value of the domain name.
    ///
    /// The method has a default implementation that composes the name into
    /// a new buffer and returns this buffer. If the implementing type can
    /// create a `Dname` more efficiently, then it should provide its
    /// own implementation.
    fn to_name(&self) -> Dname {
        let mut bytes = BytesMut::with_capacity(self.compose_len());
        self.compose(&mut bytes);
        unsafe {
            Dname::from_bytes_unchecked(bytes.freeze())
        }
    }

    /// Returns a byte slice of the content if possible.
    ///
    /// This method can is used to optimize comparision operations between
    /// two values that are indeed flat names.
    fn as_flat_slice(&self) -> Option<&[u8]> {
        None
    }

    fn name_eq<N: ToDname>(&self, other: &N) -> bool {
        if let (Some(left), Some(right)) = (self.as_flat_slice(),
                                            other.as_flat_slice()) {
            left.eq_ignore_ascii_case(right)
        }
        else {
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
    fn name_cmp<N: ToDname>(&self, other: &N) -> cmp::Ordering {
        let mut self_iter = self.iter_labels();
        let mut other_iter = other.iter_labels();
        loop {
            match (self_iter.next_back(), other_iter.next_back()) {
                (Some(left), Some(right)) => {
                    match left.cmp(right) {
                        cmp::Ordering::Equal => {}
                        res => return res
                    }
                }
                (None, Some(_)) => return cmp::Ordering::Less,
                (Some(_), None) => return cmp::Ordering::Greater,
                (None, None) => return cmp::Ordering::Equal
            }
        }
    }
}

impl<'a, N: ToDname + 'a> ToDname for &'a N { }

