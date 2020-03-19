//! A chain of domain names.
//!
//! This is a private module. Its public types are re-exported by the parent
//! crate.

use core::{fmt, iter};
use derive_more::Display;
use super::label::Label;
use crate::octets::{Compose, OctetsBuilder, ShortBuf};
use super::relative::DnameIter;
use super::traits::{ToDname, ToEitherDname, ToLabelIter, ToRelativeDname};
use super::uncertain::UncertainDname;


//------------ Chain ---------------------------------------------------------

/// Two domain names chained together.
///
/// This type is the result of calling the `chain` method on
/// [`RelativeDname`], [`UncertainDname`], or on [`Chain`] itself.
///
/// The chain can be both an absolute or relative domain name—and implements
/// the respective traits [`ToDname`] or [`ToRelativeDname`]—, depending on
/// whether the second name is absolute or relative.
///
/// A chain on an uncertain name is special in that the second name is only
/// used if the uncertain name is relative.
///
/// [`RelativeDname`]: struct.RelativeDname.html#method.chain
/// [`Chain`]: #method.chain
/// [`ToDname`]: trait.ToDname.html
/// [`ToRelativeDname`]: trait.ToRelativeDname.html
/// [`UncertainDname`]: struct.UncertainDname.html#method.chain
#[derive(Clone, Debug)]
pub struct Chain<L, R> {
    /// The first domain name.
    left: L,

    /// The second domain name.
    right: R,
}

impl<L: ToEitherDname, R: ToEitherDname> Chain<L, R> {
    /// Creates a new chain from a first and second name.
    pub(super) fn new(left: L, right: R) -> Result<Self, LongChainError> {
        if left.len() + right.len() > 255 {
            Err(LongChainError)
        }
        else {
            Ok(Chain { left, right })
        }
    }
}

impl<Octets: AsRef<[u8]>, R: ToEitherDname> Chain<UncertainDname<Octets>, R> {
    /// Creates a chain from an uncertain name.
    /// 
    /// This function is separate because the ultimate size depends on the
    /// variant of the left name.
    pub(super) fn new_uncertain(
        left: UncertainDname<Octets>, right: R
    ) -> Result<Self, LongChainError> {
        if let UncertainDname::Relative(ref name) = left {
            if name.len() + right.len() > 255 {
                return Err(LongChainError)
            }
        }
        Ok(Chain { left, right })
    }
}

impl<L: ToRelativeDname, R: ToEitherDname> Chain<L, R> {
    /// Extends the chain with another domain name.
    ///
    /// While the method accepts anything [`Compose`] as the second element of
    /// the chain, the resulting `Chain` will only implement [`ToDname`] or
    /// [`ToRelativeDname`] if if also implements [`ToDname`] or
    /// [`ToRelativeDname`], respectively.
    ///
    /// The method will fail with an error if the chained name is longer than
    /// 255 bytes.
    ///
    /// [`Compose`]: ../compose/trait.Compose.html
    /// [`ToDname`]: trait.ToDname.html
    /// [`ToRelativeDname`]: trait.ToRelativeDname.html
    pub fn chain<N: ToEitherDname>(
        self,
        other: N
    ) -> Result<Chain<Self, N>, LongChainError> {
        Chain::new(self, other)
    }
}

impl<L, R> Chain<L, R> {
    /// Unwraps the chain into its two constituent components.
    pub fn unwrap(self) -> (L, R) {
        (self.left, self.right)
    }
}


//--- Compose

impl<L: ToRelativeDname, R: ToEitherDname> Compose for Chain<L, R> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            self.left.compose(target)?;
            self.right.compose(target)
        })
    }

    fn compose_canonical<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            self.left.compose_canonical(target)?;
            self.right.compose_canonical(target)
        })
    }
}

impl<Octets, R: ToDname> Compose for Chain<UncertainDname<Octets>, R>
where Octets: AsRef<[u8]>, R: ToDname {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        match self.left {
            UncertainDname::Absolute(ref name) => name.compose(target),
            UncertainDname::Relative(ref name) => {
                target.append_all(|target| {
                    name.compose(target)?;
                    self.right.compose(target)
                })
            }
        }
    }

    fn compose_canonical<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        match self.left {
            UncertainDname::Absolute(ref name) => {
                name.compose_canonical(target)
            }
            UncertainDname::Relative(ref name) => {
                target.append_all(|target| {
                    name.compose_canonical(target)?;
                    self.right.compose_canonical(target)
                })
            }
        }
    }
}


//--- ToLabelIter, ToRelativeDname, ToDname

impl<'a, L: ToRelativeDname, R: ToEitherDname> ToLabelIter<'a>
            for Chain<L, R> {
    type LabelIter = ChainIter<'a, L, R>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        ChainIter(self.left.iter_labels().chain(self.right.iter_labels()))
    }
}

impl<'a, Octets, R> ToLabelIter<'a> for Chain<UncertainDname<Octets>, R>
where Octets: AsRef<[u8]>, R: ToDname {
    type LabelIter = UncertainChainIter<'a, Octets, R>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        match self.left {
            UncertainDname::Absolute(ref name) => {
                UncertainChainIter::Absolute(name.iter_labels())
            }
            UncertainDname::Relative(ref name) => {
                UncertainChainIter::Relative(
                    ChainIter(name.iter_labels()
                                  .chain(self.right.iter_labels()))
                )
            }
        }
    }
}

impl<L: ToRelativeDname, R: ToRelativeDname> ToRelativeDname for Chain<L, R> {
}

impl<L: ToRelativeDname, R: ToDname> ToDname for Chain<L, R> {
}

impl<Octets, R> ToDname for Chain<UncertainDname<Octets>, R>
where Octets: AsRef<[u8]>, R: ToDname
{ }


//--- Display

impl<L: fmt::Display, R: fmt::Display> fmt::Display for Chain<L, R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.left, self.right)
    }
}


//------------ ChainIter -----------------------------------------------------

/// The label iterator for chained domain names.
#[derive(Debug)]
pub struct ChainIter<'a, L: ToLabelIter<'a>, R: ToLabelIter<'a>>(
    iter::Chain<L::LabelIter, R::LabelIter>
);

impl<'a, L, R> Clone for ChainIter<'a, L, R>
where L: ToLabelIter<'a>, R: ToLabelIter<'a> {
    fn clone(&self) -> Self {
        ChainIter(self.0.clone())
    }
}

impl<'a, L, R> Iterator for ChainIter<'a, L, R>
        where L: ToLabelIter<'a>, R: ToLabelIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<'a, L, R> DoubleEndedIterator for ChainIter<'a, L, R>
        where L: ToLabelIter<'a>, R: ToLabelIter<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }
}


//------------ UncertainChainIter --------------------------------------------

/// The label iterator for domain name chains with uncertain domain names.
pub enum UncertainChainIter<'a, Octets: AsRef<[u8]>, R: ToLabelIter<'a>> {
    Absolute(DnameIter<'a>),
    Relative(ChainIter<'a, UncertainDname<Octets>, R>),
}

impl<'a, Octets, R> Clone for UncertainChainIter<'a, Octets, R>
where Octets: AsRef<[u8]>, R: ToLabelIter<'a> {
    fn clone(&self) -> Self {
        use UncertainChainIter::*;

        match *self {
            Absolute(ref inner) => Absolute(inner.clone()),
            Relative(ref inner) => Relative(inner.clone())
        }
    }
}

impl<'a, Octets, R> Iterator for UncertainChainIter<'a, Octets, R>
where Octets: AsRef<[u8]>, R: ToLabelIter<'a>
{
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        match *self {
            UncertainChainIter::Absolute(ref mut inner) => inner.next(),
            UncertainChainIter::Relative(ref mut inner) => inner.next()
        }
    }
}

impl<'a, Octets, R> DoubleEndedIterator for UncertainChainIter<'a, Octets, R>
where Octets: AsRef<[u8]>, R: ToLabelIter<'a>
{
    fn next_back(&mut self) -> Option<Self::Item> {
        match *self {
            UncertainChainIter::Absolute(ref mut inner) => inner.next_back(),
            UncertainChainIter::Relative(ref mut inner) => inner.next_back()
        }
    }
}


//------------ LongChainError ------------------------------------------------

/// Chaining domain names would exceed the size limit.
#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
#[display(fmt="long domain name")]
pub struct LongChainError;

#[cfg(feature = "std")]
impl std::error::Error for LongChainError { }


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use std::vec::Vec;
    use unwrap::unwrap;
    use crate::name::{Dname, DnameBuilder, RelativeDname, ToLabelIter};
    use super::*;

    /// Tests that `ToDname` and `ToRelativeDname` are implemented for the
    /// right types.
    #[test]
    fn impls() {
        fn assert_to_dname<T: ToDname>(_: &T) { }
        fn assert_to_relative_dname<T: ToRelativeDname>(_: &T) { }

        let rel = RelativeDname::empty_ref()
                                  .chain(RelativeDname::empty_ref()).unwrap();
        assert_to_relative_dname(&rel);
        assert_to_dname(
            &RelativeDname::empty_ref().chain(Dname::root_ref()).unwrap()
        );
        assert_to_dname(
            &unwrap!(
                unwrap!(
                    RelativeDname::empty_ref().chain(
                        RelativeDname::empty_ref()
                    )
                ).chain(Dname::root_ref())
            )
        );
        assert_to_dname(&rel.clone().chain(Dname::root_ref()).unwrap());
        assert_to_relative_dname(
            &rel.chain(RelativeDname::empty_ref()).unwrap()
        );
        assert_to_dname(
            &UncertainDname::root_vec().chain(Dname::root_vec()).unwrap()
        );
        assert_to_dname(
            &UncertainDname::empty_vec().chain(Dname::root_vec()).unwrap()
        );
    }

    /// Tests that a chain never becomes too long.
    #[test]
    fn name_limit() {
        let mut builder = DnameBuilder::new_vec();
        for _ in 0..25 {
            // 9 bytes label is 10 bytes in total 
            unwrap!(builder.append_label(b"123456789"));
        }
        let left = builder.finish();
        assert_eq!(left.len(), 250);

        let mut builder = DnameBuilder::new_vec();
        unwrap!(builder.append_slice(b"123"));
        let five_abs = unwrap!(builder.clone().into_dname());
        assert_eq!(five_abs.len(), 5);
        unwrap!(builder.push(b'4'));
        let five_rel = builder.clone().finish();
        assert_eq!(five_rel.len(), 5);
        let six_abs = unwrap!(builder.clone().into_dname());
        assert_eq!(six_abs.len(), 6);
        unwrap!(builder.push(b'5'));
        let six_rel = builder.finish();
        assert_eq!(six_rel.len(), 6);

        assert_eq!(
            unwrap!(left.clone().chain(five_abs.clone())).len(),
            255
        );
        assert_eq!(
            unwrap!(left.clone().chain(five_rel.clone())).len(),
            255
        );
        assert!(left.clone().chain(six_abs.clone()).is_err());
        assert!(left.clone().chain(six_rel.clone()).is_err());
        assert!(
            unwrap!(
                left.clone().chain(five_rel.clone())
            ).chain(five_abs.clone()).is_err()
        );
        assert!(
            unwrap!(
                left.clone().chain(five_rel.clone())
            ).chain(five_rel.clone()).is_err()
        );

        let left = UncertainDname::from(left);
        assert_eq!(
            unwrap!(left.clone().chain(five_abs.clone())).len(),
            255
        );
        assert!(left.clone().chain(six_abs.clone()).is_err());

        let left = UncertainDname::from(unwrap!(left.into_absolute()));
        assert_eq!(
            unwrap!(left.clone().chain(six_abs.clone())).len(),
            251
        );
    }

    /// Tests that the label iterators all work as expected.
    #[test]
    fn iter_labels() {
        fn cmp_iter<'a, I: Iterator<Item=&'a Label>>(
            iter: I, labels: &[&[u8]]
        ) {
            let labels = labels.iter().map(|s| Label::from_slice(s).unwrap());
            assert!(iter.eq(labels))
        }

        let w = unwrap!(RelativeDname::from_octets(b"\x03www".as_ref()));
        let ec = unwrap!(
            RelativeDname::from_octets(b"\x07example\x03com".as_ref())
        );
        let ecr = unwrap!(
            Dname::from_octets(b"\x07example\x03com\x00".as_ref())
        );
        let fbr = unwrap!(
            Dname::from_octets(b"\x03foo\x03bar\x00".as_ref())
        );

        cmp_iter(
            unwrap!(w.clone().chain(ec.clone())).iter_labels(), 
            &[b"www", b"example", b"com"]
        );
        cmp_iter(
            unwrap!(w.clone().chain(ecr.clone())).iter_labels(),
            &[b"www", b"example", b"com", b""]
        );
        cmp_iter(
            unwrap!(
                unwrap!(w.clone().chain(ec.clone())).chain(Dname::root_ref())
            ).iter_labels(),
            &[b"www", b"example", b"com", b""]
        );
        
        cmp_iter(
            unwrap!(
                UncertainDname::from(w.clone()).chain(ecr.clone())
            ).iter_labels(),
            &[b"www", b"example", b"com", b""]
        );
        cmp_iter(
            unwrap!(
                UncertainDname::from(ecr.clone()).chain(fbr.clone())
            ).iter_labels(),
            &[b"example", b"com", b""]
        );
    }

    /// Tests that composing works as expected.
    #[test]
    fn compose() {
        let w = unwrap!(RelativeDname::from_octets(b"\x03www".as_ref()));
        let ec = unwrap!(
            RelativeDname::from_octets(b"\x07example\x03com".as_ref())
        );
        let ecr = unwrap!(
            Dname::from_octets(b"\x07example\x03com\x00".as_ref())
        );
        let fbr = unwrap!(
            Dname::from_octets(b"\x03foo\x03bar\x00".as_ref())
        );

        let mut buf = Vec::new();
        unwrap!(unwrap!(w.clone().chain(ec.clone())).compose(&mut buf));
        assert_eq!(buf, b"\x03www\x07example\x03com".as_ref());

        let mut buf = Vec::new();
        unwrap!(unwrap!(w.clone().chain(ecr.clone())).compose(&mut buf));
        assert_eq!(buf, b"\x03www\x07example\x03com\x00");

        let mut buf = Vec::new();
        unwrap!(
            unwrap!(
                unwrap!(w.clone().chain(ec.clone())).chain(Dname::root_ref())
            ).compose(&mut buf)
        );
        assert_eq!(buf, b"\x03www\x07example\x03com\x00");

        let mut buf = Vec::new();
        unwrap!(
            unwrap!(
                UncertainDname::from(w.clone()).chain(ecr.clone())
            ).compose(&mut buf)
        );
        assert_eq!(buf, b"\x03www\x07example\x03com\x00");

        let mut buf = Vec::new();
        unwrap!(
            unwrap!(
                UncertainDname::from(ecr.clone()).chain(fbr.clone())
            ).compose(&mut buf)
        );
        assert_eq!(buf, b"\x07example\x03com\x00");
    }
}

