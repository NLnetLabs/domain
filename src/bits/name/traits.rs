//! Domain name-related traits.

use ::bits::compose::Composable;
use super::label::Label;


//------------ ToLabelIter ---------------------------------------------------

pub trait ToLabelIter<'a> {
    type LabelIter: Iterator<Item=&'a Label>;

    fn iter_labels(&'a self) -> Self::LabelIter;
}


//------------ ToDname -------------------------------------------------------

pub trait ToDname: Composable + for<'a> ToLabelIter<'a> {
    fn is_absolute(&self) -> bool;
}


//------------ ToFqdn --------------------------------------------------------

pub trait ToFqdn: ToDname { }

