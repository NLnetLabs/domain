//! Iterators for domain names.

use std::borrow::Cow;
use super::label::Label;
use super::{DNameSlice, Labelette, LabelIter, PackedDName};


//------------ NameIter ------------------------------------------------------

/// An iterator over the labels in a domain name.
///
/// This type can work with both compressed and uncompressed domain names.
#[derive(Clone, Debug)]
pub struct NameIter<'a> {
    inner: Flavor<'a>
}

#[derive(Clone, Debug)]
enum Flavor<'a> {
    Slice(&'a DNameSlice),
    Packed(Option<PackedDName<'a>>),
}


impl<'a> NameIter<'a> {
    pub fn from_slice(slice: &'a DNameSlice) -> Self {
        NameIter{inner: Flavor::Slice(slice)}
    }

    pub fn from_packed(name: PackedDName<'a>) -> Self {
        NameIter{inner: Flavor::Packed(Some(name))}
    }

    pub fn to_cow(&self) -> Cow<'a, DNameSlice> {
        match self.inner {
            Flavor::Slice(slice) => {
                Cow::Borrowed(slice)
            }
            Flavor::Packed(Some(ref name)) => {
                name.unpack()
            }
            Flavor::Packed(None) => {
                Cow::Borrowed(DNameSlice::empty())
            }
        }
    }
}


//--- Iterator

impl<'a> Iterator for NameIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner {
            Flavor::Slice(ref mut slice) => {
                match slice.split_first() {
                    Some((label, name)) => {
                        *slice = name;
                        Some(label)
                    }
                    None => None
                }
            }
            Flavor::Packed(ref mut name) => {
                let (res, new_name) = match *name {
                    Some(ref mut name) => {
                        let (res, new_name) = name.split_first().unwrap();
                        (Some(res), new_name)
                    }
                    None => (None, None)
                };
                *name = new_name;
                res
            }
        }
    }
}


//------------ RevNameIter ---------------------------------------------------

/// An iterator over the labels of a domain name in reverse order.
#[derive(Clone, Debug)]
pub struct RevNameIter<'a> {
    labels: Vec<&'a Label>,
}


impl<'a> RevNameIter<'a> {
    pub fn new(iter: NameIter<'a>) -> Self {
        RevNameIter{labels: iter.collect()}
    }

    pub fn from_slice(slice: &'a DNameSlice) -> Self {
        Self::new(NameIter::from_slice(slice))
    }
}


//--- Iterator

impl<'a> Iterator for RevNameIter<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        self.labels.pop()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.labels.len(), Some(self.labels.len()))
    }
}


//------------ NameLabelettes ------------------------------------------------

#[derive(Clone, Debug)]
pub struct NameLabelettes<'a> {
    name: NameIter<'a>,
    label: Option<LabelIter<'a>>
}

impl<'a> NameLabelettes<'a> {
    pub fn new(iter: NameIter<'a>) -> Self {
        NameLabelettes{name: iter, label: None}
    }
}

impl<'a> Iterator for NameLabelettes<'a> {
    type Item = Labelette<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut label) = self.label {
                if let Some(x) = label.next() {
                    return Some(x)
                }
            }
            match self.name.next() {
                None => return None,
                next => self.label = next.map(|l| l.iter())
            }
        }
    }
}


//------------ RevNameLabelettes ---------------------------------------------

#[derive(Clone, Debug)]
pub struct RevNameLabelettes<'a> {
    name: RevNameIter<'a>,
    label: Option<LabelIter<'a>>
}

impl<'a> RevNameLabelettes<'a> {
    pub fn new(iter: RevNameIter<'a>) -> Self {
        RevNameLabelettes{name: iter, label: None}
    }
}

impl<'a> Iterator for RevNameLabelettes<'a> {
    type Item = Labelette<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut label) = self.label {
                if let Some(x) = label.next_back() {
                    return Some(x)
                }
            }
            match self.name.next() {
                None => return None,
                next => self.label = next.map(|l| l.iter())
            }
        }
    }
}

