use std::iter;
use bytes::BufMut;
use ::bits::compose::Composable;
use super::label::Label;
use super::traits::{ToLabelIter, ToRelativeDname, ToDname};


//------------ Chain ---------------------------------------------------------

pub struct Chain<L, R> {
    left: L,
    right: R,
}

impl<L, R> Chain<L, R> {
    pub fn new(left: L, right: R) -> Self {
        Chain { left, right }
    }

    pub fn unwrap(self) -> (L, R) {
        (self.left, self.right)
    }

    pub fn chain<N: ToRelativeDname>(self, other: N) -> Chain<Self, N> {
        Chain::new(self, other)
    }
}

impl<'a, L: ToRelativeDname, R: for<'r> ToLabelIter<'r>> ToLabelIter<'a>
            for Chain<L, R> {
    type LabelIter = ChainIter<'a, L, R>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        ChainIter(self.left.iter_labels().chain(self.right.iter_labels()))
    }
}

impl<L: ToRelativeDname, R: ToRelativeDname> ToRelativeDname for Chain<L, R> {
}

impl<L: ToRelativeDname, R: Composable> Composable for Chain<L, R> {
    fn compose_len(&self) -> usize {
        self.left.compose_len() + self.right.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.left.compose(buf);
        self.right.compose(buf)
    }
}

impl<L: ToRelativeDname, R: ToDname> ToDname for Chain<L, R> {
}


//------------ ChainIter -----------------------------------------------------

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
