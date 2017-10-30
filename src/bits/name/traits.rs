//! Domain name-related traits.

use bytes::BufMut;
use super::label::Label;


//------------ ToLabelIter ---------------------------------------------------

pub trait ToLabelIter<'a> {
    type LabelIter: Iterator<Item=&'a Label>;

    fn iter_labels(&'a self) -> Self::LabelIter;
}


//------------ ToDname -------------------------------------------------------

pub trait ToDname: for<'a> ToLabelIter<'a> {
    fn is_absolute(&self) -> bool;
    fn len(&self) -> usize {
        let mut res = 0;
        for label in self.iter_labels() {
            res += label.len() + 1;
        }
        res
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        for label in self.iter_labels() {
            label.compose(buf);
        }
    }
}


//------------ ToFqdn --------------------------------------------------------

pub trait ToFqdn: ToDname { }

