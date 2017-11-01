//! A chain of domain names.
//!
use std::{error, fmt, iter};
use bytes::BufMut;
use ::bits::compose::Composable;
use super::label::Label;
use super::traits::{ToLabelIter, ToRelativeDname, ToDname};


//------------ Chain ---------------------------------------------------------

/// A type stringing two domain names together.
///
/// This type is the result of calling the `chain` method on
/// [`RelativeDname`] or on [`Chain`] itself.
///
/// The chain can be both an absolute or relative domain name—and implements
/// the respective traits [`ToDname`] or [`ToRelativeDname`]—, depending on
/// whether the second name is absolute or relative.
///
/// [`RelativeDname`]: struct.RelativeDname.html#method.chain
/// [`Chain`]: #method.chain
/// [`ToDname`]: trait.ToDname.html
/// [`ToRelativeDname`]: trait.ToRelativeDname.html
pub struct Chain<L, R> {
    /// The first domain name.
    left: L,

    /// The second domain name.
    right: R,
}

impl<L: Composable, R: Composable> Chain<L, R> {
    /// Creates a new chain from a first and second name.
    pub(super) fn new(left: L, right: R) -> Result<Self, LongNameError> {
        if left.compose_len() + right.compose_len() > 255 {
            Err(LongNameError)
        }
        else {
            Ok(Chain { left, right })
        }
    }
}

impl<L: ToRelativeDname, R: Composable> Chain<L, R> {
    /// Extends the chain with another domain name.
    ///
    /// While the method accepts any `Composable` as the second element of
    /// the chain, the resulting `Chain` will only implement `ToDname` or
    /// `ToRelativeDname` if other implements `ToDname` or `ToRelativeDname`,
    /// respectively.
    ///
    /// The method will fail with an error if the chained name is longer than
    /// 255 bytes.
    pub fn chain<N: Composable>(self, other: N)
                                -> Result<Chain<Self, N>, LongNameError> {
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

impl<L: Composable, R: Composable> Composable for Chain<L, R> {
    fn compose_len(&self) -> usize {
        self.left.compose_len() + self.right.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.left.compose(buf);
        self.right.compose(buf)
    }
}

impl<L: ToRelativeDname, R: ToRelativeDname> ToRelativeDname for Chain<L, R> {
}

impl<L: ToRelativeDname, R: ToDname> ToDname for Chain<L, R> {
}


//------------ ChainIter -----------------------------------------------------

/// A label iterator for chained domain names.
#[derive(Clone, Debug)]
pub struct ChainIter<'a, L: ToLabelIter<'a>, R: ToLabelIter<'a>>(
    iter::Chain<L::LabelIter, R::LabelIter>);

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


//------------ LongNameError -------------------------------------------------

/// An attempt was made to strip a suffix that wasn’t actually a suffix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LongNameError;

impl error::Error for LongNameError {
    fn description(&self) -> &str {
        "suffix not found"
    }
}

impl fmt::Display for LongNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        "suffix not found".fmt(f)
    }
}

