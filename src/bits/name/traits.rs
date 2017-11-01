//! Domain name-related traits.

use ::bits::compose::Composable;
use bytes::BytesMut;
use super::dname::Dname;
use super::label::Label;
use super::relname::RelativeDname;


//------------ ToLabelIter ---------------------------------------------------

pub trait ToLabelIter<'a> {
    type LabelIter: Iterator<Item=&'a Label> + DoubleEndedIterator;

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


//------------ ToRelativeDname -----------------------------------------------

pub trait ToRelativeDname: Composable + for<'a> ToLabelIter<'a> {
    fn to_name(&self) -> RelativeDname {
        let mut bytes = BytesMut::with_capacity(self.compose_len());
        self.compose(&mut bytes);
        unsafe {
            RelativeDname::from_bytes_unchecked(bytes.freeze())
        }
    }
}


//------------ ToDname -------------------------------------------------------

pub trait ToDname: Composable + for<'a> ToLabelIter<'a> {
    fn to_name(&self) -> Dname {
        let mut bytes = BytesMut::with_capacity(self.compose_len());
        self.compose(&mut bytes);
        unsafe {
            Dname::from_bytes_unchecked(bytes.freeze())
        }
    }
}

