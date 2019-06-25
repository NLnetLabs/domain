//! A chain of domain names.
//!
//! This is a private module. Its public types are re-exported by the parent
//! crate.

use std::{error, fmt, iter};
use bytes::BufMut;
use crate::compose::{Compose, Compress, Compressor};
use crate::parse::ShortBuf;
use super::label::Label;
use super::relative::DnameIter;
use super::traits::{ToLabelIter, ToRelativeDname, ToDname};
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

impl<L: Compose, R: Compose> Chain<L, R> {
    /// Creates a new chain from a first and second name.
    pub(super) fn new(left: L, right: R) -> Result<Self, LongChainError> {
        if left.compose_len() + right.compose_len() > 255 {
            Err(LongChainError)
        }
        else {
            Ok(Chain { left, right })
        }
    }
}

impl<R: Compose> Chain<UncertainDname, R> {
    /// Creates a chain from an uncertain name.
    /// 
    /// This function is separate because the ultimate size depends on the
    /// variant of the left name.
    pub(super) fn new_uncertain(left: UncertainDname, right: R)
                                -> Result<Self, LongChainError> {
        if let UncertainDname::Relative(ref name) = left {
            if name.compose_len() + right.compose_len() > 255 {
                return Err(LongChainError)
            }
        }
        Ok(Chain { left, right })
    }
}

impl<L: ToRelativeDname, R: Compose> Chain<L, R> {
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
    pub fn chain<N: Compose>(self, other: N)
                                -> Result<Chain<Self, N>, LongChainError> {
        Chain::new(self, other)
    }
}

impl<L, R> Chain<L, R> {
    /// Unwraps the chain into its two constituent components.
    pub fn unwrap(self) -> (L, R) {
        (self.left, self.right)
    }
}

impl<'a, L: ToRelativeDname, R: for<'r> ToLabelIter<'r>> ToLabelIter<'a>
            for Chain<L, R> {
    type LabelIter = ChainIter<'a, L, R>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        ChainIter(self.left.iter_labels().chain(self.right.iter_labels()))
    }
}

impl<L: ToRelativeDname, R: Compose> Compose for Chain<L, R> {
    fn compose_len(&self) -> usize {
        self.left.compose_len() + self.right.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.left.compose(buf);
        self.right.compose(buf)
    }
}

impl<L: ToRelativeDname, R: ToDname> Compress for Chain<L, R> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        buf.compress_name(self)
    }
}

impl<L: ToRelativeDname, R: ToRelativeDname> ToRelativeDname for Chain<L, R> {
}

impl<L: ToRelativeDname, R: ToDname> ToDname for Chain<L, R> {
}

impl<L: fmt::Display, R: fmt::Display> fmt::Display for Chain<L, R> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.{}", self.left, self.right)
    }
}

impl<'a, R: ToDname> ToLabelIter<'a> for Chain<UncertainDname, R> {
    type LabelIter = UncertainChainIter<'a, R>;

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

impl<R: ToDname> Compose for Chain<UncertainDname, R> {
    fn compose_len(&self) -> usize {
        match self.left {
            UncertainDname::Absolute(ref name) => name.compose_len(),
            UncertainDname::Relative(ref name) => {
                name.compose_len() + self.right.compose_len()
            }
        }
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        match self.left {
            UncertainDname::Absolute(ref name) => name.compose(buf),
            UncertainDname::Relative(ref name) => {
                name.compose(buf);
                self.right.compose(buf)
            }
        }
    }
}


impl<R: ToDname> Compress for Chain<UncertainDname, R> {
    fn compress(&self, buf: &mut Compressor) -> Result<(), ShortBuf> {
        if let UncertainDname::Absolute(ref name) = self.left {
            buf.compress_name(name)
        }
        else {
            // XXX Test this!
            buf.compress_name(self)
        }
    }
}

impl<R: ToDname> ToDname for Chain<UncertainDname, R> { }


//------------ ChainIter -----------------------------------------------------

/// The label iterator for chained domain names.
#[derive(Clone, Debug)]
pub struct ChainIter<'a, L: ToLabelIter<'a>, R: ToLabelIter<'a>>(
    iter::Chain<L::LabelIter, R::LabelIter>
);

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
pub enum UncertainChainIter<'a, R: ToLabelIter<'a>> {
    Absolute(DnameIter<'a>),
    Relative(ChainIter<'a, UncertainDname, R>),
}

impl<'a, R> Iterator for UncertainChainIter<'a, R>
where R: ToLabelIter<'a>
{
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        match *self {
            UncertainChainIter::Absolute(ref mut inner) => inner.next(),
            UncertainChainIter::Relative(ref mut inner) => inner.next()
        }
    }
}

impl<'a, R> DoubleEndedIterator for UncertainChainIter<'a, R>
where R: ToLabelIter<'a>
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

impl error::Error for LongChainError { }


//============ Testing =======================================================

#[cfg(test)]
mod test {
    use bytes::BytesMut;
    use crate::compose::{Compose, Compress, Compressor};
    use crate::name::{
        Dname, DnameBuilder, Label, RelativeDname, ToDname,
        ToLabelIter, ToRelativeDname, UncertainDname
    };

    fn assert_to_dname<T: ToDname>(_: &T) { }
    fn assert_to_relative_dname<T: ToRelativeDname>(_: &T) { }

    /// Tests that `ToDname` and `ToRelativeDname` are implemented for the
    /// right types.
    #[test]
    fn impls() {
        let rel = RelativeDname::empty()
                                .chain(RelativeDname::empty()).unwrap();
        assert_to_dname(&RelativeDname::empty().chain(Dname::root()).unwrap());
        assert_to_relative_dname(&rel);
        assert_to_dname(&rel.clone().chain(Dname::root()).unwrap());
        assert_to_relative_dname(&rel.chain(RelativeDname::empty()).unwrap());
        assert_to_dname(&UncertainDname::root().chain(Dname::root()).unwrap());
    }

    /// Tests that a chain never becomes too long.
    #[test]
    fn name_limit() {
        let mut builder = DnameBuilder::new();
        for _ in 0..25 {
            // 9 bytes label is 10 bytes in total 
            builder.append_label(b"123456789").unwrap();
        }
        let left = builder.finish();
        assert_eq!(left.len(), 250);

        let mut builder = DnameBuilder::new();
        builder.append(b"123").unwrap();
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

        assert_eq!(left.clone().chain(five_abs.clone())
                       .unwrap().compose_len(),
                   255);
        assert_eq!(left.clone().chain(five_rel.clone())
                       .unwrap().compose_len(),
                   255);
        assert!(left.clone().chain(six_abs.clone()).is_err());
        assert!(left.clone().chain(six_rel.clone()).is_err());
        assert!(left.clone().chain(five_rel.clone()).unwrap()
                            .chain(five_abs.clone()).is_err());
        assert!(left.clone().chain(five_rel.clone()).unwrap()
                            .chain(five_rel.clone()).is_err());

        let left = UncertainDname::from(left);
        assert_eq!(left.clone().chain(five_abs.clone())
                       .unwrap().compose_len(),
                   255);
        assert!(left.clone().chain(six_abs.clone()).is_err());

        let left = UncertainDname::from(left.into_absolute());
        assert_eq!(left.clone().chain(six_abs.clone())
                       .unwrap().compose_len(),
                   251);
    }

    fn cmp_iter<'a, I>(iter: I, labels: &[&[u8]])
                where I: Iterator<Item=&'a Label> {
        let labels = labels.iter().map(|s| Label::from_slice(s).unwrap());
        assert!(iter.eq(labels))
    }

    /// Tests that the label iterators all work as expected.
    #[test]
    fn iter_labels() {
        let w = RelativeDname::from_slice(b"\x03www").unwrap();
        let ec = RelativeDname::from_slice(b"\x07example\x03com").unwrap();
        let ecr = Dname::from_slice(b"\x07example\x03com\x00").unwrap();
        let fbr = Dname::from_slice(b"\x03foo\x03bar\x00").unwrap();

        cmp_iter(w.clone().chain(ec.clone()).unwrap().iter_labels(), 
                 &[b"www", b"example", b"com"]);
        cmp_iter(w.clone().chain(ecr.clone()).unwrap().iter_labels(),
                 &[b"www", b"example", b"com", b""]);
        cmp_iter(w.clone().chain(ec.clone()).unwrap()
                          .chain(Dname::root()).unwrap().iter_labels(),
                 &[b"www", b"example", b"com", b""]);
        
        cmp_iter(UncertainDname::from(w.clone())
                                .chain(ecr.clone()).unwrap().iter_labels(),
                 &[b"www", b"example", b"com", b""]);
        cmp_iter(UncertainDname::from(ecr.clone())
                                .chain(fbr.clone()).unwrap().iter_labels(),
                 &[b"example", b"com", b""]);
    }

    /// Tests that composing works as expected.
    #[test]
    fn compose() {
        let w = RelativeDname::from_slice(b"\x03www").unwrap();
        let ec = RelativeDname::from_slice(b"\x07example\x03com").unwrap();
        let ecr = Dname::from_slice(b"\x07example\x03com\x00").unwrap();
        let fbr = Dname::from_slice(b"\x03foo\x03bar\x00").unwrap();

        let mut buf = BytesMut::with_capacity(255);
        w.clone().chain(ec.clone()).unwrap().compose(&mut buf);
        assert_eq!(buf.freeze().as_ref(),
                   b"\x03www\x07example\x03com");

        let mut buf = BytesMut::with_capacity(255);
        w.clone().chain(ecr.clone()).unwrap().compose(&mut buf);
        assert_eq!(buf.freeze().as_ref(),
                   b"\x03www\x07example\x03com\x00");

        let mut buf = BytesMut::with_capacity(255);
        w.clone().chain(ec.clone()).unwrap().chain(Dname::root()).unwrap()
         .compose(&mut buf);
        assert_eq!(buf.freeze().as_ref(),
                   b"\x03www\x07example\x03com\x00");

        let mut buf = BytesMut::with_capacity(255);
        UncertainDname::from(w.clone()).chain(ecr.clone()).unwrap()
            .compose(&mut buf);
        assert_eq!(buf.freeze().as_ref(),
                   b"\x03www\x07example\x03com\x00");

        let mut buf = BytesMut::with_capacity(255);
        UncertainDname::from(ecr.clone()).chain(fbr.clone()).unwrap()
            .compose(&mut buf);
        assert_eq!(buf.freeze().as_ref(),
                   b"\x07example\x03com\x00");
    }

    /// Tests that compressing works as expected.
    #[test]
    fn compress() {
        let w = RelativeDname::from_slice(b"\x03www").unwrap();
        let ec = RelativeDname::from_slice(b"\x07example\x03com").unwrap();
        let ecr = Dname::from_slice(b"\x07example\x03com\x00").unwrap();
        let fbr = Dname::from_slice(b"\x03foo\x03bar\x00").unwrap();

        let mut buf = Compressor::with_capacity(255);
        w.clone().chain(ecr.clone()).unwrap().compress(&mut buf).unwrap();
        assert_eq!(buf.freeze().as_ref(),
                   b"\x03www\x07example\x03com\x00");

        let mut buf = Compressor::with_capacity(255);
        w.clone().chain(ec.clone()).unwrap().chain(Dname::root()).unwrap()
         .compress(&mut buf).unwrap();
        assert_eq!(buf.freeze().as_ref(),
                   b"\x03www\x07example\x03com\x00");

        let mut buf = Compressor::with_capacity(255);
        UncertainDname::from(w.clone()).chain(ecr.clone()).unwrap()
            .compress(&mut buf).unwrap();
        assert_eq!(buf.freeze().as_ref(),
                   b"\x03www\x07example\x03com\x00");

        let mut buf = Compressor::with_capacity(255);
        UncertainDname::from(ecr.clone()).chain(fbr.clone()).unwrap()
            .compress(&mut buf).unwrap();
        assert_eq!(buf.freeze().as_ref(),
                   b"\x07example\x03com\x00");
    }
}
