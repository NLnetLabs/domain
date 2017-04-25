//! Iterators for domain names.

use std::mem;
use std::borrow::Cow;
use std::collections::VecDeque;
use super::label::Label;
use super::{DNameBuf, DNameSlice, Labelette, LabelIter, ParsedDName};


//------------ NameLabels ----------------------------------------------------

/// An iterator over the labels in a domain name.
///
/// This type can work with both compressed and uncompressed domain names.
/// It forms the foundation of the [`DName`] trait.
///
/// [`DName`]: trait.DName.html
#[derive(Clone, Debug)]
pub struct NameLabels<'a> {
    inner: Flavor<'a>,
}

/// What sort of iterator are we?
#[derive(Clone, Debug)]
enum Flavor<'a> {
    /// Iterating forward only over a domain name slice.
    Slice(&'a DNameSlice),

    /// Iterating forward only over a parsed domain name.
    Parsed(ParsedDName<'a>),

    /// Iterating both ways over a domain name slice.
    DoubleSlice {
        /// The remaining slice.
        ///
        /// We only keep it for the `to_cow()` method. By storing the raw
        /// bytes we can shorten it quickly by using the length of the labels
        /// only.
        bytes: &'a [u8],

        /// The labels of the remaining name slice.
        labels: VecDeque<&'a Label>,
    },

    /// Iterating both ways over a parsed domain name.
    ///
    /// This will only be used if the parsed name contains compressed labels.
    /// If it does not, starting two-way operation will transform it into
    /// the `DoubleSlice` flavor.
    DoubleParsed(VecDeque<&'a Label>),

    /// Done iterating.
    Empty
}


impl<'a> NameLabels<'a> {
    /// Creates an iterator for a domain name slice.
    pub fn from_slice(slice: &'a DNameSlice) -> Self {
        NameLabels{inner: Flavor::Slice(slice)}
    }

    /// Creates an iterator for a parsed domain name.
    pub fn from_parsed(name: ParsedDName<'a>) -> Self {
        NameLabels{inner: Flavor::Parsed(name)}
    }

    /// Returns a cow of the remaining labels in the domain name.
    pub fn to_cow(&self) -> Cow<'a, DNameSlice> {
        match self.inner {
            Flavor::Slice(slice) => {
                Cow::Borrowed(slice)
            }
            Flavor::Parsed(ref name) => {
                name.unpack()
            }
            Flavor::DoubleSlice{bytes, ..} => {
                Cow::Borrowed(unsafe { DNameSlice::from_bytes_unsafe(bytes) })
            }
            Flavor::DoubleParsed(ref labels) => {
                Cow::Owned(DNameBuf::from_iter(labels.iter().map(|x| *x))
                                    .unwrap())
            }
            Flavor::Empty => Cow::Borrowed(DNameSlice::empty())
        }
    }

    /// Ensures the iterator is ready for double ended iterating.
    fn ensure_double(&mut self) {
        let new_inner = match self.inner {
            Flavor::Slice(slice) => {
                Flavor::DoubleSlice {
                    bytes: slice.as_bytes(),
                    labels: slice.labels().collect(),
                }
            }
            Flavor::Parsed(ref name) => {
                if let Some(slice) = name.as_slice() {
                    Flavor::DoubleSlice {
                        bytes: slice.as_bytes(),
                        labels: slice.labels().collect(),
                    }
                }
                else {
                    Flavor::DoubleParsed(name.labels().collect())
                }
            }
            _ => return
        };
        self.inner = new_inner;
    }
}


//--- Iterator

impl<'a> Iterator for NameLabels<'a> {
    type Item = &'a Label;

    fn next(&mut self) -> Option<Self::Item> {
        let (res, new_inner) = match self.inner {
            Flavor::Slice(ref mut slice) => {
                match slice.split_first() {
                    Some((label, name)) => {
                        *slice = name;
                        return Some(label)
                    }
                    None => (None, Flavor::Empty)
                }
            }
            Flavor::Parsed(ref mut name) => {
                let (res, new_name) = name.split_first().unwrap();
                if let Some(new_name) = new_name {
                    *name = new_name;
                    return Some(res)
                }
                (Some(res), Flavor::Empty)
            }
            Flavor::DoubleSlice{ref mut bytes, ref mut labels} => {
                match labels.pop_front() {
                    Some(label) => {
                        *bytes = &bytes[label.len()..];
                        return Some(label)
                    }
                    None => (None, Flavor::Empty)
                }
            }
            Flavor::DoubleParsed(ref mut labels) => {
                match labels.pop_front() {
                    Some(label) => return Some(label),
                    None => (None, Flavor::Empty)
                }
            }
            Flavor::Empty => return None,
        };
        self.inner = new_inner;
        res
    }
}


//--- DoubleEndedIterator

impl<'a> DoubleEndedIterator for NameLabels<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.ensure_double();
        let (res, new_inner) = match self.inner {
            Flavor::Slice(..) | Flavor::Parsed(..) => unreachable!(),
            Flavor::DoubleSlice{ref mut bytes, ref mut labels} => {
                match labels.pop_back() {
                    Some(label) => {
                        *bytes = &bytes[..bytes.len() - label.len()];
                        return Some(label)
                    }
                    None => (None, Flavor::Empty)
                }
            }
            Flavor::DoubleParsed(ref mut labels) => {
                match labels.pop_back() {
                    Some(label) => return Some(label),
                    None => (None, Flavor::Empty)
                }
            }
            Flavor::Empty => return None,
        };
        self.inner = new_inner;
        res
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
    label: DoubleLabels<'a>,
}


impl<'a> NameLabelettes<'a> {
    /// Creates a new labelette iterator from a label iterator.
    pub fn new(iter: NameLabels<'a>) -> Self {
        NameLabelettes{name: iter, label: DoubleLabels::new()}
    }

    /// Creates a domain name with the remaining labelettes.
    pub fn to_name(&self) -> Cow<'a, DNameSlice> {
        if let Some(cow) = self.label.front().and_then(|iter| iter.to_name()) {
            let mut name = cow.into_owned();
            name.append_iter(self.name.clone()).unwrap();
            self.label.back()
                      .map(|iter| iter.push_name(&mut name).unwrap());
            Cow::Owned(name)
        }
        else {
            let res = self.name.to_cow();
            if let Some(iter) = self.label.back() {
                let mut res = res.into_owned();
                iter.push_name(&mut res).unwrap();
                Cow::Owned(res)
            }
            else {
                res
            }
        }
    }
}

impl<'a> Iterator for NameLabelettes<'a> {
    type Item = Labelette<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut label) = self.label.front_mut() {
                if let Some(x) = label.next() {
                    return Some(x)
                }
            }
            if !self.label.next(self.name.next()) {
                return None
            }
        }
    }
}

impl<'a> DoubleEndedIterator for NameLabelettes<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ref mut label) = self.label.back_mut() {
                if let Some(x) = label.next_back() {
                    return Some(x)
                }
            }
            if !self.label.next_back(self.name.next_back()) {
                return None
            }
        }
    }
}


//------------ DoubleLabels --------------------------------------------------

/// The labels the labelette iterator operates currently on.
#[derive(Clone, Debug)]
enum DoubleLabels<'a> {
    /// Neither front nor back
    None,

    /// Front label, no back label
    Front(LabelIter<'a>),

    /// No front label but a back label
    Back(LabelIter<'a>),

    /// Both but different
    Both(LabelIter<'a>, LabelIter<'a>),

    /// Both on the same label
    Same(LabelIter<'a>),
}

impl<'a> DoubleLabels<'a> {
    fn new() -> Self {
        DoubleLabels::None
    }

    fn front(&self) -> Option<&LabelIter<'a>> {
        match *self {
            DoubleLabels::None | DoubleLabels::Back(..) => None,
            DoubleLabels::Front(ref front) | DoubleLabels::Both(ref front, _)
                => Some(front),
            DoubleLabels::Same(ref same) => Some(same)
        }
    }

    fn front_mut(&mut self) -> Option<&mut LabelIter<'a>> {
        match *self {
            DoubleLabels::None | DoubleLabels::Back(..) => None,
            DoubleLabels::Front(ref mut front)
                | DoubleLabels::Both(ref mut front, _) => Some(front),
            DoubleLabels::Same(ref mut same) => Some(same)
        }
    }

    fn back(&self) -> Option<&LabelIter<'a>> {
        match *self {
            DoubleLabels::None | DoubleLabels::Front(..) => None,
            DoubleLabels::Back(ref back)
                | DoubleLabels::Both(_, ref back) => Some(back),
            DoubleLabels::Same(ref same) => Some(same)
        }
    }

    fn back_mut(&mut self) -> Option<&mut LabelIter<'a>> {
        match *self {
            DoubleLabels::None | DoubleLabels::Front(..) => None,
            DoubleLabels::Back(ref mut back)
                | DoubleLabels::Both(_, ref mut back) => Some(back),
            DoubleLabels::Same(ref mut same) => Some(same)
        }
    }

    fn next(&mut self, front: Option<&'a Label>) -> bool {
        if let Some(front) = front {
            let front = front.iter();
            *self = match mem::replace(self, DoubleLabels::None) {
                DoubleLabels::None | DoubleLabels::Front(_)
                    => DoubleLabels::Front(front),
                DoubleLabels::Back(back) | DoubleLabels::Both(_, back)
                    => DoubleLabels::Both(front, back),
                DoubleLabels::Same(_) => unreachable!(),
            };
            true
        }
        else {
            let (res, new) = match mem::replace(self, DoubleLabels::None) {
                DoubleLabels::Both(_, back)
                    => (true, DoubleLabels::Same(back)),
                _ => (false, DoubleLabels::None)
            };
            *self = new;
            res
        }
    }

    fn next_back(&mut self, back: Option<&'a Label>) -> bool {
        if let Some(back) = back {
            let back = back.iter();
            *self = match mem::replace(self, DoubleLabels::None) {
                DoubleLabels::None | DoubleLabels::Back(_)
                    => DoubleLabels::Back(back),
                DoubleLabels::Front(front) | DoubleLabels::Both(front, _)
                    => DoubleLabels::Both(front, back),
                DoubleLabels::Same(_) => unreachable!()
            };
            true
        }
        else {
            let (res, new) = match mem::replace(self, DoubleLabels::None) {
                DoubleLabels::Both(front, _)
                    => (true, DoubleLabels::Same(front)),
                _ => (false, DoubleLabels::None)
            };
            *self = new;
            res
        }
    }
}

