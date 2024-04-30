//! A chain of domain names.
//!
//! This is a private module. Its public types are re-exported by the parent
//! crate.

use super::super::scan::Scanner;
use super::label::Label;
use super::relative::NameIter;
use super::traits::{FlattenInto, ToLabelIter, ToName, ToRelativeName};
use super::uncertain::UncertainName;
use super::Name;
use core::{fmt, iter};
use octseq::builder::{
    BuilderAppendError, EmptyBuilder, FreezeBuilder, FromBuilder,
};

//------------ Chain ---------------------------------------------------------

/// Two domain names chained together.
///
/// This type is the result of calling the `chain` method on
/// [`RelativeName`], [`UncertainName`], or on [`Chain`] itself.
///
/// The chain can be both an absolute or relative domain name—and implements
/// the respective traits [`ToName`] or [`ToRelativeName`]—, depending on
/// whether the second name is absolute or relative.
///
/// A chain on an uncertain name is special in that the second name is only
/// used if the uncertain name is relative.
///
/// [`RelativeName`]: struct.RelativeName.html#method.chain
/// [`Chain`]: #method.chain
/// [`ToName`]: trait.ToName.html
/// [`ToRelativeName`]: trait.ToRelativeName.html
/// [`UncertainName`]: struct.UncertainName.html#method.chain
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
        if usize::from(left.compose_len() + right.compose_len())
            > Name::MAX_LEN
        {
            // TODO can't infer a specific type for Name here
            Err(LongChainError(()))
        } else {
            Ok(Chain { left, right })
        }
    }
}

impl<Octets: AsRef<[u8]>, R: ToLabelIter> Chain<UncertainName<Octets>, R> {
    /// Creates a chain from an uncertain name.
    ///
    /// This function is separate because the ultimate size depends on the
    /// variant of the left name.
    pub(super) fn new_uncertain(
        left: UncertainName<Octets>,
        right: R,
    ) -> Result<Self, LongChainError> {
        if let UncertainName::Relative(ref name) = left {
            if usize::from(name.compose_len() + right.compose_len())
                > Name::MAX_LEN
            {
                return Err(LongChainError(()));
            }
        }
        Ok(Chain { left, right })
    }
}

impl<L, R> Chain<L, R> {
    pub fn scan<S: Scanner<Name = Self>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        scanner.scan_name()
    }
}

impl<L: ToRelativeName, R: ToLabelIter> Chain<L, R> {
    /// Extends the chain with another domain name.
    ///
    /// While the method accepts anything [`Compose`] as the second element of
    /// the chain, the resulting `Chain` will only implement [`ToName`] or
    /// [`ToRelativeName`] if if also implements [`ToName`] or
    /// [`ToRelativeName`], respectively.
    ///
    /// The method will fail with an error if the chained name is longer than
    /// 255 bytes.
    ///
    /// [`Compose`]: ../compose/trait.Compose.html
    /// [`ToName`]: trait.ToName.html
    /// [`ToRelativeName`]: trait.ToRelativeName.html
    pub fn chain<N: ToLabelIter>(
        self,
        other: N,
    ) -> Result<Chain<Self, N>, LongChainError> {
        Chain::new(self, other)
    }
}

impl<L, R> Chain<L, R>
where
    Self: ToLabelIter,
{
    /// Returns an object that displays an absolute name with a final dot.
    ///
    /// The chain itself displays without a final dot unless the chain
    /// results in an absolute name with the root label only. This method can
    /// be used to display a chain that results in an absolute name with a
    /// single dot at its end.
    pub fn fmt_with_dot(&self) -> impl fmt::Display + '_ {
        DisplayWithDot(self)
    }
}

impl<L, R> Chain<L, R> {
    /// Unwraps the chain into its two constituent components.
    pub fn unwrap(self) -> (L, R) {
        (self.left, self.right)
    }
}

//--- ToLabelIter, ToRelativeName, ToName

impl<L: ToRelativeName, R: ToLabelIter> ToLabelIter for Chain<L, R> {
    type LabelIter<'a> = ChainIter<'a, L, R> where L: 'a, R: 'a;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        ChainIter(self.left.iter_labels().chain(self.right.iter_labels()))
    }

    fn compose_len(&self) -> u16 {
        self.left
            .compose_len()
            .checked_add(self.right.compose_len())
            .expect("long domain name")
    }
}

impl<Octs, R> ToLabelIter for Chain<UncertainName<Octs>, R>
where
    Octs: AsRef<[u8]>,
    R: ToName,
{
    type LabelIter<'a> = UncertainChainIter<'a, Octs, R>
        where Octs: 'a, R: 'a;

    fn iter_labels(&self) -> Self::LabelIter<'_> {
        match self.left {
            UncertainName::Absolute(ref name) => {
                UncertainChainIter::Absolute(name.iter_labels())
            }
            UncertainName::Relative(ref name) => {
                UncertainChainIter::Relative(ChainIter(
                    name.iter_labels().chain(self.right.iter_labels()),
                ))
            }
        }
    }

    fn compose_len(&self) -> u16 {
        match self.left {
            UncertainName::Absolute(ref name) => name.compose_len(),
            UncertainName::Relative(ref name) => name
                .compose_len()
                .checked_add(self.right.compose_len())
                .expect("long domain name"),
        }
    }
}

impl<L: ToRelativeName, R: ToRelativeName> ToRelativeName for Chain<L, R> {}

impl<L: ToRelativeName, R: ToName> ToName for Chain<L, R> {}

impl<Octets, R> ToName for Chain<UncertainName<Octets>, R>
where
    Octets: AsRef<[u8]>,
    R: ToName,
{
}

//--- FlattenInto

impl<L, R, Target> FlattenInto<Name<Target>> for Chain<L, R>
where
    L: ToRelativeName,
    R: ToName,
    R: FlattenInto<Name<Target>, AppendError = BuilderAppendError<Target>>,
    Target: FromBuilder,
    <Target as FromBuilder>::Builder: EmptyBuilder,
{
    type AppendError = BuilderAppendError<Target>;

    fn try_flatten_into(self) -> Result<Name<Target>, Self::AppendError> {
        if self.left.is_empty() {
            self.right.try_flatten_into()
        } else {
            let mut builder =
                Target::Builder::with_capacity(self.compose_len().into());
            self.compose(&mut builder)?;
            Ok(unsafe { Name::from_octets_unchecked(builder.freeze()) })
        }
    }
}

//--- Display

impl<L, R> fmt::Display for Chain<L, R>
where
    Self: ToLabelIter,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut empty = true;
        for label in self.iter_labels() {
            if label.is_root() {
                if empty {
                    f.write_str(".")?
                }
            } else {
                if !empty {
                    f.write_str(".")?
                } else {
                    empty = false;
                }
                label.fmt(f)?;
            }
        }
        Ok(())
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
    Absolute(NameIter<'a>),
    Relative(ChainIter<'a, UncertainName<Octets>, R>),
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

//------------ DisplayWithDot ------------------------------------------------

struct DisplayWithDot<'a, L, R>(&'a Chain<L, R>);

impl<'a, L, R> fmt::Display for DisplayWithDot<'a, L, R>
where
    Chain<L, R>: ToLabelIter,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut empty = true;
        for label in self.0.iter_labels() {
            if label.is_root() {
                f.write_str(".")?
            } else {
                if !empty {
                    f.write_str(".")?
                } else {
                    empty = false;
                }
                label.fmt(f)?;
            }
        }
        Ok(())
    }
}

//============ Error Types ===================================================

//------------ LongChainError ------------------------------------------------

/// Chaining domain names would exceed the size limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongChainError(());

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
#[cfg(feature = "std")]
mod test {
    use super::*;
    use crate::base::name::RelativeName;
    use octseq::builder::infallible;

    /// Tests that `ToName` and `ToRelativeName` are implemented for the
    /// right types.
    #[test]
    #[cfg(feature = "std")]
    fn impls() {
        fn assert_to_name<T: ToName>(_: &T) {}
        fn assert_to_relative_name<T: ToRelativeName>(_: &T) {}

        let rel = RelativeName::empty_ref()
            .chain(RelativeName::empty_ref())
            .unwrap();
        assert_to_relative_name(&rel);
        assert_to_name(
            &RelativeName::empty_ref().chain(Name::root_ref()).unwrap(),
        );
        assert_to_name(
            &RelativeName::empty_ref()
                .chain(RelativeName::empty_ref())
                .unwrap()
                .chain(Name::root_ref())
                .unwrap(),
        );
        assert_to_name(&rel.clone().chain(Name::root_ref()).unwrap());
        assert_to_relative_name(
            &rel.chain(RelativeName::empty_ref()).unwrap(),
        );
        assert_to_name(
            &UncertainName::root_vec().chain(Name::root_vec()).unwrap(),
        );
        assert_to_name(
            &UncertainName::empty_vec().chain(Name::root_vec()).unwrap(),
        );
    }

    /// Tests that a chain never becomes too long.
    #[test]
    fn name_limit() {
        use crate::base::name::NameBuilder;

        let mut builder = NameBuilder::new_vec();
        for _ in 0..25 {
            // 9 bytes label is 10 bytes in total
            builder.append_label(b"123456789").unwrap();
        }
        let left = builder.finish();
        assert_eq!(left.len(), 250);

        let mut builder = NameBuilder::new_vec();
        builder.append_slice(b"123").unwrap();
        let five_abs = builder.clone().into_name().unwrap();
        assert_eq!(five_abs.len(), 5);
        builder.push(b'4').unwrap();
        let five_rel = builder.clone().finish();
        assert_eq!(five_rel.len(), 5);
        let six_abs = builder.clone().into_name().unwrap();
        assert_eq!(six_abs.len(), 6);
        builder.push(b'5').unwrap();
        let six_rel = builder.finish();
        assert_eq!(six_rel.len(), 6);

        assert_eq!(
            left.clone().chain(five_abs.clone()).unwrap().compose_len(),
            255
        );
        assert_eq!(
            left.clone().chain(five_rel.clone()).unwrap().compose_len(),
            255
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

        let left = UncertainName::from(left);
        assert_eq!(left.clone().chain(five_abs).unwrap().compose_len(), 255);
        assert!(left.clone().chain(six_abs.clone()).is_err());

        let left = UncertainName::from(left.into_absolute().unwrap());
        println!("{:?}", left);
        assert_eq!(left.chain(six_abs).unwrap().compose_len(), 251);
    }

    /// Checks the impl of ToLabelIter: iter_labels and compose_len.
    #[test]
    fn to_label_iter_impl() {
        fn check_impl<N: ToLabelIter>(name: N, labels: &[&[u8]]) {
            let labels = labels.iter().map(|s| Label::from_slice(s).unwrap());
            assert!(name.iter_labels().eq(labels));
            assert_eq!(
                name.iter_labels().map(|l| l.compose_len()).sum::<u16>(),
                name.compose_len()
            );
        }

        let w = RelativeName::from_octets(b"\x03www".as_ref()).unwrap();
        let ec = RelativeName::from_octets(b"\x07example\x03com".as_ref())
            .unwrap();
        let ecr =
            Name::from_octets(b"\x07example\x03com\x00".as_ref()).unwrap();
        let fbr = Name::from_octets(b"\x03foo\x03bar\x00".as_ref()).unwrap();

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
                .chain(Name::root_ref())
                .unwrap(),
            &[b"www", b"example", b"com", b""],
        );
        check_impl(
            RelativeName::empty_slice()
                .chain(Name::root_slice())
                .unwrap(),
            &[b""],
        );

        check_impl(
            UncertainName::from(w.clone()).chain(ecr.clone()).unwrap(),
            &[b"www", b"example", b"com", b""],
        );
        check_impl(
            UncertainName::from(ecr.clone()).chain(fbr.clone()).unwrap(),
            &[b"example", b"com", b""],
        );
    }

    /// Tests that composing works as expected.
    #[test]
    fn compose() {
        use std::vec::Vec;

        let w = RelativeName::from_octets(b"\x03www".as_ref()).unwrap();
        let ec = RelativeName::from_octets(b"\x07example\x03com".as_ref())
            .unwrap();
        let ecr =
            Name::from_octets(b"\x07example\x03com\x00".as_ref()).unwrap();
        let fbr = Name::from_octets(b"\x03foo\x03bar\x00".as_ref()).unwrap();

        let mut buf = Vec::new();
        infallible(w.clone().chain(ec.clone()).unwrap().compose(&mut buf));
        assert_eq!(buf, b"\x03www\x07example\x03com".as_ref());

        let mut buf = Vec::new();
        infallible(w.clone().chain(ecr.clone()).unwrap().compose(&mut buf));
        assert_eq!(buf, b"\x03www\x07example\x03com\x00");

        let mut buf = Vec::new();
        infallible(
            w.clone()
                .chain(ec.clone())
                .unwrap()
                .chain(Name::root_ref())
                .unwrap()
                .compose(&mut buf),
        );
        assert_eq!(buf, b"\x03www\x07example\x03com\x00");

        let mut buf = Vec::new();
        infallible(
            UncertainName::from(w.clone())
                .chain(ecr.clone())
                .unwrap()
                .compose(&mut buf),
        );
        assert_eq!(buf, b"\x03www\x07example\x03com\x00");

        let mut buf = Vec::new();
        infallible(
            UncertainName::from(ecr.clone())
                .chain(fbr.clone())
                .unwrap()
                .compose(&mut buf),
        );
        assert_eq!(buf, b"\x07example\x03com\x00");
    }

    /// Tests that displaying works as expected.
    ///
    /// The tricky bit is to produce to correct number of dots between the
    /// left and the right part and at the end of the chain. This is made
    /// difficult by empty relative names and absolute root names. So this
    /// is what we are testing below in a number of combinations.
    #[test]
    fn display() {
        fn cmp<E: fmt::Debug, L, R>(
            chain: Result<Chain<L, R>, E>,
            out: &str,
            dot_out: &str,
        ) where
            Chain<L, R>: ToLabelIter,
        {
            use std::string::ToString;

            let chain = chain.unwrap();
            assert_eq!(chain.to_string(), out);
            assert_eq!(chain.fmt_with_dot().to_string(), dot_out);
        }

        // An empty relative name.
        let empty = &RelativeName::from_octets(b"".as_slice()).unwrap();

        // An empty relative name wrapped in an uncertain name.
        let uempty = &UncertainName::from(empty.clone());

        // A non-empty relative name. We are using two labels here just to
        // have that covered as well.
        let rel =
            &RelativeName::from_octets(b"\x03www\x07example".as_slice())
                .unwrap();

        // A non-empty relative name wrapped in an uncertain name.
        let urel = &UncertainName::from(rel.clone());

        // The root name which is an absolute name.
        let root = &Name::from_octets(b"\0".as_slice()).unwrap();

        // The root name wrapped in an uncertain name.
        let uroot = &UncertainName::from(root.clone());

        // A “normal” absolute name.
        let abs = &Name::from_octets(b"\x03com\0".as_slice()).unwrap();

        // A “normal” absolute name wrapped in an uncertain name.
        let uabs = &UncertainName::from(abs.clone());

        // Now we produce all possible cases and their expected result. First
        // result is for normal display, second is for fmt_with_dot.
        //
        // If the left side of the chain is a relative name,
        // the right side can be relative, absolute, or uncertain.
        cmp(empty.chain(empty), "", "");
        cmp(empty.chain(uempty), "", "");
        cmp(empty.chain(rel), "www.example", "www.example");
        cmp(empty.chain(urel), "www.example", "www.example");
        cmp(empty.chain(root), ".", ".");
        cmp(empty.chain(uroot), ".", ".");
        cmp(empty.chain(abs), "com", "com.");
        cmp(empty.chain(uabs), "com", "com.");

        cmp(rel.chain(empty), "www.example", "www.example");
        cmp(rel.chain(uempty), "www.example", "www.example");
        cmp(
            rel.chain(rel),
            "www.example.www.example",
            "www.example.www.example",
        );
        cmp(
            rel.chain(urel),
            "www.example.www.example",
            "www.example.www.example",
        );
        cmp(rel.chain(root), "www.example", "www.example.");
        cmp(rel.chain(uroot), "www.example", "www.example.");
        cmp(rel.chain(abs), "www.example.com", "www.example.com.");
        cmp(rel.chain(uabs), "www.example.com", "www.example.com.");

        // If the left side of a chain is an uncertain name, the right side
        // must be an absolute name.
        cmp(uempty.clone().chain(root), ".", ".");
        cmp(uempty.clone().chain(abs), "com", "com.");
        cmp(urel.clone().chain(root), "www.example", "www.example.");
        cmp(
            urel.clone().chain(abs),
            "www.example.com",
            "www.example.com.",
        );
        cmp(uroot.clone().chain(root), ".", ".");
        cmp(uroot.clone().chain(abs), ".", ".");
        cmp(uabs.clone().chain(root), "com", "com.");
        cmp(uabs.clone().chain(abs), "com", "com.");
    }
}
