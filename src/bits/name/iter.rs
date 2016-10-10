//! Iterators for domain names.

use std::borrow::Cow;
use super::label::Label;
use super::{DNameSlice, Labelette, LabelIter, ParsedDName};


//------------ NameLabels ----------------------------------------------------

/// An iterator over the labels in a domain name.
///
/// This type can work with both compressed and uncompressed domain names.
/// It forms the foundation of the [`DName`] trait.
///
/// [`DName`]: trait.DName.html
#[derive(Clone, Debug)]
pub struct NameLabels<'a> {
    inner: Flavor<'a>
}

/// What sort of domain name are we operating on?
#[derive(Clone, Debug)]
enum Flavor<'a> {
    /// Iterating over a domain name slice.
    Slice(&'a DNameSlice),

    /// Iterating over a parsed domain name.
    ///
    /// This is an `Option<_>` because there is no such things as empty
    /// parsed domain names.
    Parsed(Option<ParsedDName<'a>>),
}


impl<'a> NameLabels<'a> {
    /// Creates an iterator for a domain name slice.
    pub fn from_slice(slice: &'a DNameSlice) -> Self {
        NameLabels{inner: Flavor::Slice(slice)}
    }

    /// Creates an iterator for a parsed domain name.
    pub fn from_packed(name: ParsedDName<'a>) -> Self {
        NameLabels{inner: Flavor::Parsed(Some(name))}
    }

    /// Returns a cow of the remaining labels in the domain name.
    pub fn to_cow(&self) -> Cow<'a, DNameSlice> {
        match self.inner {
            Flavor::Slice(slice) => {
                Cow::Borrowed(slice)
            }
            Flavor::Parsed(Some(ref name)) => {
                name.unpack()
            }
            Flavor::Parsed(None) => {
                Cow::Borrowed(DNameSlice::empty())
            }
        }
    }
}


//--- Iterator

impl<'a> Iterator for NameLabels<'a> {
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
            Flavor::Parsed(ref mut name) => {
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


//------------ RevNameLabels -------------------------------------------------

/// An iterator over the labels of a domain name in reverse order.
///
/// Because we don’t know where the various labels in a domain name start,
/// we have to iterate over the entire name in order to determine the reverse
/// order. This type iterates only once and remembers all labels for later.
/// Because this requires an allocation, this is a separate type rather
/// then an implementation of `DoubleEndedIterator` for [`NameLabels`].
///
/// [`NameLabels`]: struct.NameIter.html
#[derive(Clone, Debug)]
pub struct RevNameLabels<'a> {
    labels: Vec<&'a Label>,
}


impl<'a> RevNameLabels<'a> {
    /// Creates a new reverse iterator from a regular iterator.
    pub fn new(iter: NameLabels<'a>) -> Self {
        RevNameLabels{labels: iter.collect()}
    }

    /// Creates a new reverse iterator for a domain name slice.
    pub fn from_slice(slice: &'a DNameSlice) -> Self {
        Self::new(NameLabels::from_slice(slice))
    }
}


//--- Iterator

impl<'a> Iterator for RevNameLabels<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        self.labels.pop()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.labels.len(), Some(self.labels.len()))
    }
}


//------------ NameLabelettes ------------------------------------------------

/// An iterator over the labelettes of a domain name.
///
/// See [`Labelette`] for a discussion what these ominous labelettes are.
///
/// [`Labelette`]: struct.Labelette.html
#[derive(Clone, Debug)]
pub struct NameLabelettes<'a> {
    name: NameLabels<'a>,
    label: Option<LabelIter<'a>>
}

impl<'a> NameLabelettes<'a> {
    /// Creates a new labelette iterator from a label iterator.
    pub fn new(iter: NameLabels<'a>) -> Self {
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

/// An iterator over the labelettes of a domain name in reverse order.
///
/// See [`Labelette`] for a discussion what these ominous labelettes are.
///
/// [`Labelette`]: struct.Labelette.html
#[derive(Clone, Debug)]
pub struct RevNameLabelettes<'a> {
    name: RevNameLabels<'a>,
    label: Option<LabelIter<'a>>
}

impl<'a> RevNameLabelettes<'a> {
    /// Creates a reverse labelette iterator from a reverse label iterator.
    pub fn new(iter: RevNameLabels<'a>) -> Self {
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

