use std::iter;
use bytes::BufMut;
use super::label::Label;
use super::traits::{ToLabelIter, ToDname, ToFqdn};


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

    pub fn chain<N: ToDname>(self, other: N) -> Chain<Self, N> {
        Chain::new(self, other)
    }
}

impl<'a, L: ToDname, R: ToDname> ToLabelIter<'a> for Chain<L, R> {
    type LabelIter = ChainIter<'a, L, R>;

    fn iter_labels(&'a self) -> Self::LabelIter {
        if self.left.is_absolute() {
            ChainIter::Left(self.left.iter_labels())
        }
        else {
            ChainIter::Chain(
                self.left.iter_labels().chain(self.right.iter_labels())
            )
        }
    }
}

impl<L: ToDname, R: ToDname> ToDname for Chain<L, R> {
    fn len(&self) -> usize {
        if self.left.is_absolute() {
            self.left.len()
        }
        else {
            self.left.len() + self.right.len()
        }
    }

    fn is_absolute(&self) -> bool {
        true
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.left.compose(buf);
        if !self.left.is_absolute() {
            self.right.compose(buf)
        }
    }
}

impl<L: ToDname, R: ToFqdn> ToFqdn for Chain<L, R> {
}


//------------ ChainIter -----------------------------------------------------

pub enum ChainIter<'a, L, R> where L: ToLabelIter<'a>, R: ToLabelIter<'a> {
    Left(L::LabelIter),
    Chain(iter::Chain<L::LabelIter, R::LabelIter>)
}

impl<'a, L: ToLabelIter<'a>, R: ToLabelIter<'a>> Iterator for ChainIter<'a, L, R> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        match *self {
            ChainIter::Left(ref mut iter) => iter.next(),
            ChainIter::Chain(ref mut iter) => iter.next(),
        }
    }
}

