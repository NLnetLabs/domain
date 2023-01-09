//! A chain of domain names.
//!
//! This is a private module. Its public types are re-exported by the parent
//! crate.

use super::super::scan::Scanner;
use super::label::Label;
use super::relative::DnameIter;
use super::traits::{ToDname, ToLabelIter, ToRelativeDname};
use super::uncertain::UncertainDname;
use core::{fmt, iter};

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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Chain<L, R> {
    /// The first domain name.
    left: L,

    /// The second domain name.
    right: R,
}

impl<L: ToLabelIter, R: ToLabelIter> Chain<L, R> {
    /// Creates a new chain from a first and second name.
    pub(super) fn new(left: L, right: R) -> Result<Self, LongChainError> {
        if left.compose_len() + right.compose_len() > 255 {
            Err(LongChainError)
        } else {
            Ok(Chain { left, right })
        }
    }
}

impl<Octets: AsRef<[u8]>, R: ToLabelIter> Chain<UncertainDname<Octets>, R> {
    /// Creates a chain from an uncertain name.
    ///
    /// This function is separate because the ultimate size depends on the
    /// variant of the left name.
    pub(super) fn new_uncertain(
        left: UncertainDname<Octets>,
        right: R,
    ) -> Result<Self, LongChainError> {
        if let UncertainDname::Relative(ref name) = left {
            if name.compose_len() + right.compose_len() > 255 {
                return Err(LongChainError);
            }
        }
        Ok(Chain { left, right })
    }
}

impl<L, R> Chain<L, R> {
    pub fn scan<S: Scanner<Dname = Self>>(
        scanner: &mut S
    ) -> Result<Self, S::Error> {
        scanner.scan_dname()
    }
}

impl<L: ToRelativeDname, R: ToLabelIter> Chain<L, R> {
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
    pub fn chain<N: ToLabelIter>(
        self,
        other: N,
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

//--- ToLabelIter, ToRelativeDname, ToDname

impl<L: ToRelativeDname, R: ToLabelIter> ToLabelIter for Chain<L, R> {
    type LabelIter<'a> = ChainIter<'a, L, R> where L: 'a, R: 'a;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        ChainIter(self.left.iter_labels().chain(self.right.iter_labels()))
    }

    fn compose_len(&self) -> u16 {
        self.left.compose_len().checked_add(
            self.right.compose_len()
        ).expect("long domain name")
    }
}

impl<Octs, R> ToLabelIter for Chain<UncertainDname<Octs>, R>
where
    Octs: AsRef<[u8]>,
    R: ToDname,
{
    type LabelIter<'a> = UncertainChainIter<'a, Octs, R>
        where Octs: 'a, R: 'a;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        match self.left {
            UncertainDname::Absolute(ref name) => {
                UncertainChainIter::Absolute(name.iter_labels())
            }
            UncertainDname::Relative(ref name) => {
                UncertainChainIter::Relative(ChainIter(
                    name.iter_labels().chain(self.right.iter_labels()),
                ))
            }
        }
    }

    fn compose_len(&self) -> u16 {
        match self.left {
            UncertainDname::Absolute(ref name) => {
                name.compose_len()
            }
            UncertainDname::Relative(ref name) => {
                name.compose_len().checked_add(
                    self.right.compose_len()
                ).expect("long domain name")
            }
        }
    }
}

impl<L: ToRelativeDname, R: ToRelativeDname> ToRelativeDname for Chain<L, R> {}

impl<L: ToRelativeDname, R: ToDname> ToDname for Chain<L, R> {}

impl<Octets, R> ToDname for Chain<UncertainDname<Octets>, R>
where
    Octets: AsRef<[u8]>,
    R: ToDname,
{
}

//--- Display

impl<L: fmt::Display, R: fmt::Display> fmt::Display for Chain<L, R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.left, self.right)
    }
}

//------------ ChainIter -----------------------------------------------------

/// The label iterator for chained domain names.
#[derive(Debug)]
pub struct ChainIter<'a, L: ToLabelIter + 'a, R: ToLabelIter + 'a>(
    iter::Chain<L::LabelIter<'a>, R::LabelIter<'a>>,
);

impl<'a, L, R> Clone for ChainIter<'a, L, R>
where
    L: ToLabelIter,
    R: ToLabelIter,
{
    fn clone(&self) -> Self {
        ChainIter(self.0.clone())
    }
}

impl<'a, L, R> Iterator for ChainIter<'a, L, R>
where
    L: ToLabelIter,
    R: ToLabelIter,
{
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<'a, L, R> DoubleEndedIterator for ChainIter<'a, L, R>
where
    L: ToLabelIter,
    R: ToLabelIter,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        self.0.next_back()
    }
}

//------------ UncertainChainIter --------------------------------------------

/// The label iterator for domain name chains with uncertain domain names.
pub enum UncertainChainIter<'a, Octets: AsRef<[u8]>, R: ToLabelIter> {
    Absolute(DnameIter<'a>),
    Relative(ChainIter<'a, UncertainDname<Octets>, R>),
}

impl<'a, Octets, R> Clone for UncertainChainIter<'a, Octets, R>
where
    Octets: AsRef<[u8]>,
    R: ToLabelIter,
{
    fn clone(&self) -> Self {
        use UncertainChainIter::*;

        match *self {
            Absolute(ref inner) => Absolute(inner.clone()),
            Relative(ref inner) => Relative(inner.clone()),
        }
    }
}

impl<'a, Octets, R> Iterator for UncertainChainIter<'a, Octets, R>
where
    Octets: AsRef<[u8]>,
    R: ToLabelIter,
{
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        match *self {
            UncertainChainIter::Absolute(ref mut inner) => inner.next(),
            UncertainChainIter::Relative(ref mut inner) => inner.next(),
        }
    }
}

impl<'a, Octets, R> DoubleEndedIterator for UncertainChainIter<'a, Octets, R>
where
    Octets: AsRef<[u8]>,
    R: ToLabelIter,
{
    fn next_back(&mut self) -> Option<Self::Item> {
        match *self {
            UncertainChainIter::Absolute(ref mut inner) => inner.next_back(),
            UncertainChainIter::Relative(ref mut inner) => inner.next_back(),
        }
    }
}

//============ Error Types ===================================================

//------------ LongChainError ------------------------------------------------

/// Chaining domain names would exceed the size limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongChainError;

//--- Display and Error

impl fmt::Display for LongChainError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("long domain name")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LongChainError {}

//============ Testing =======================================================

#[cfg(test)]
mod test {
    use super::*;
    use crate::base::name::{Dname, RelativeDname, ToLabelIter};
    use octseq::builder::infallible;

    /// Tests that `ToDname` and `ToRelativeDname` are implemented for the
    /// right types.
    #[test]
    #[cfg(feature = "std")]
    fn impls() {
        fn assert_to_dname<T: ToDname>(_: &T) {}
        fn assert_to_relative_dname<T: ToRelativeDname>(_: &T) {}

        let rel = RelativeDname::empty_ref()
            .chain(RelativeDname::empty_ref())
            .unwrap();
        assert_to_relative_dname(&rel);
        assert_to_dname(
            &RelativeDname::empty_ref().chain(Dname::root_ref()).unwrap(),
        );
        assert_to_dname(
            &RelativeDname::empty_ref()
                .chain(RelativeDname::empty_ref())
                .unwrap()
                .chain(Dname::root_ref())
                .unwrap(),
        );
        assert_to_dname(&rel.clone().chain(Dname::root_ref()).unwrap());
        assert_to_relative_dname(
            &rel.chain(RelativeDname::empty_ref()).unwrap(),
        );
        assert_to_dname(
            &UncertainDname::root_vec().chain(Dname::root_vec()).unwrap(),
        );
        assert_to_dname(
            &UncertainDname::empty_vec()
                .chain(Dname::root_vec())
                .unwrap(),
        );
    }

    /// Tests that a chain never becomes too long.
    #[test]
    #[cfg(feature = "std")]
    fn name_limit() {
        use crate::base::name::DnameBuilder;

        let mut builder = DnameBuilder::new_vec();
        for _ in 0..25 {
            // 9 bytes label is 10 bytes in total
            builder.append_label(b"123456789").unwrap();
        }
        let left = builder.finish();
        assert_eq!(left.len(), 250);

        let mut builder = DnameBuilder::new_vec();
        builder.append_slice(b"123").unwrap();
        let five_abs = builder.clone().into_dname().unwrap();
        assert_eq!(five_abs.len(), 5);
        builder.push(b'4').unwrap();
        let five_rel = builder.clone().finish();
        assert_eq!(five_rel.len(), 5);
        let six_abs = builder.clone().into_dname().unwrap();
        assert_eq!(six_abs.len(), 6);
        builder.push(b'5').unwrap();
        let six_rel = builder.finish();
        assert_eq!(six_rel.len(), 6);

        assert_eq!(
            left.clone().chain(five_abs.clone()).unwrap().compose_len(), 255
        );
        assert_eq!(
            left.clone().chain(five_rel.clone()).unwrap().compose_len(), 255
        );
        assert!(left.clone().chain(six_abs.clone()).is_err());
        assert!(left.clone().chain(six_rel).is_err());
        assert!(left
            .clone()
            .chain(five_rel.clone())
            .unwrap()
            .chain(five_abs.clone())
            .is_err());
        assert!(left
            .clone()
            .chain(five_rel.clone())
            .unwrap()
            .chain(five_rel)
            .is_err());

        let left = UncertainDname::from(left);
        assert_eq!(left.clone().chain(five_abs).unwrap().compose_len(), 255);
        assert!(left.clone().chain(six_abs.clone()).is_err());

        let left = UncertainDname::from(left.into_absolute().unwrap());
        println!("{:?}", left);
        assert_eq!(left.chain(six_abs).unwrap().compose_len(), 251);
    }

    /// Checks the impl of ToLabelIter: iter_labels and compose_len.
    #[test]
    fn to_label_iter_impl() {
        fn check_impl<'a, N: ToLabelIter>(
            name: N, labels: &[&[u8]],
        ) {
            let labels = labels.iter().map(|s| Label::from_slice(s).unwrap());
            assert!(name.iter_labels().eq(labels));
            assert_eq!(
                name.iter_labels().map(|l| l.compose_len()).sum::<u16>(),
                name.compose_len()
            );
        }

        let w = RelativeDname::from_octets(b"\x03www".as_ref()).unwrap();
        let ec = RelativeDname::from_octets(b"\x07example\x03com".as_ref())
            .unwrap();
        let ecr =
            Dname::from_octets(b"\x07example\x03com\x00".as_ref()).unwrap();
        let fbr = Dname::from_octets(b"\x03foo\x03bar\x00".as_ref()).unwrap();

        check_impl(
            w.clone().chain(ec.clone()).unwrap(),
            &[b"www", b"example", b"com"],
        );
        check_impl(
            w.clone().chain(ecr.clone()).unwrap(),
            &[b"www", b"example", b"com", b""],
        );
        check_impl(
            w.clone()
                .chain(ec.clone())
                .unwrap()
                .chain(Dname::root_ref())
                .unwrap(),
            &[b"www", b"example", b"com", b""],
        );

        check_impl(
            UncertainDname::from(w.clone())
                .chain(ecr.clone())
                .unwrap(),
            &[b"www", b"example", b"com", b""],
        );
        check_impl(
            UncertainDname::from(ecr.clone())
                .chain(fbr.clone())
                .unwrap(),
            &[b"example", b"com", b""],
        );
    }

    /// Tests that composing works as expected.
    #[test]
    #[cfg(feature = "std")]
    fn compose() {
        use std::vec::Vec;

        let w = RelativeDname::from_octets(b"\x03www".as_ref()).unwrap();
        let ec = RelativeDname::from_octets(b"\x07example\x03com".as_ref())
            .unwrap();
        let ecr =
            Dname::from_octets(b"\x07example\x03com\x00".as_ref()).unwrap();
        let fbr = Dname::from_octets(b"\x03foo\x03bar\x00".as_ref()).unwrap();

        let mut buf = Vec::new();
        infallible(w.clone().chain(ec.clone()).unwrap().compose(&mut buf));
        assert_eq!(buf, b"\x03www\x07example\x03com".as_ref());

        let mut buf = Vec::new();
        infallible(w.clone().chain(ecr.clone()).unwrap().compose(&mut buf));
        assert_eq!(buf, b"\x03www\x07example\x03com\x00");

        let mut buf = Vec::new();
        infallible(w
            .clone().chain(ec.clone()).unwrap().chain(Dname::root_ref())
            .unwrap().compose(&mut buf)
        );
        assert_eq!(buf, b"\x03www\x07example\x03com\x00");

        let mut buf = Vec::new();
        infallible(UncertainDname::from(w.clone())
            .chain(ecr.clone()).unwrap().compose(&mut buf)
        );
        assert_eq!(buf, b"\x03www\x07example\x03com\x00");

        let mut buf = Vec::new();
        infallible(UncertainDname::from(ecr.clone())
            .chain(fbr.clone()).unwrap().compose(&mut buf)
        );
        assert_eq!(buf, b"\x07example\x03com\x00");
    }
}
