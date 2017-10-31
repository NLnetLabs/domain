//! Domain name-related traits.

use ::bits::compose::Composable;
use super::label::Label;


//------------ ToLabelIter ---------------------------------------------------

pub trait ToLabelIter<'a> {
    type LabelIter: Iterator<Item=&'a Label> + DoubleEndedIterator;

    fn iter_labels(&'a self) -> Self::LabelIter;
}


//------------ ToRelativeDname -----------------------------------------------

pub trait ToRelativeDname: Composable + for<'a> ToLabelIter<'a> {
}


//------------ ToDname -------------------------------------------------------

pub trait ToDname: Composable + for<'a> ToLabelIter<'a> { }

