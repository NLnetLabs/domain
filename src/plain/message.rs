//! Convenient representations of DNS messages.
#![allow(dead_code)]

use super::{AllOptData, Question, Record};
use crate::base;
use crate::base::header::{Header, HeaderCounts};
use crate::base::message;
use crate::base::name::FlattenInto;
use crate::base::opt::{ComposeOptData, OptData, OptHeader, OptRecord};
use crate::base::wire::{Compose, Composer, ParseError};
use crate::rdata::AllRecordData;
use bytes::Bytes;
use octseq::{Octets, OctetsFrom, OctetsInto};
use std::convert::Infallible;
use std::prelude::rust_2021::*;
use std::{borrow, cmp, error, fmt, ops, slice, vec};

//------------ Message -------------------------------------------------------

/// A DNS message as a collection of questions and records.
///
/// This type deviates slightly from the normal definition of the message in
/// that it considers the OPT record not as part of the additional section.
/// Instead it keeps it separate. A consequence of this is that this type can
/// not add any records after the OPT record either. In practice this would
/// only ever be a TSIG record that needs to be synthesized after the message
/// is complete, anyway, and shouldn’t be part of an easily modifiable
/// message.
///
/// Another consequence is that this message will always have an OPT record.
/// Since basically all messages in modern DNS should have an OPT record,
/// this is likely an okay limitation.
#[derive(Clone, Default)]
pub struct Message {
    /// The header of the message.
    header: Header,

    /// The question section.
    question: QuestionSection,

    /// The answer section.
    answer: RecordSection,

    /// The section.
    authority: RecordSection,

    /// The additional section.
    ///
    /// This section should not include the OPT record nor any records
    /// coming after the OPT record, e.g., TSIG.
    additional: AdditionalSection,

    /// The OPT record.
    opt: Opt,
}

impl Message {
    /// Creates a new, empty message with a default header.
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns a reference to the question section.
    pub fn question(&self) -> &QuestionSection {
        &self.question
    }

    /// Returns a mutable reference to the question section.
    pub fn question_mut(&mut self) -> &mut QuestionSection {
        &mut self.question
    }

    /// Returns a reference to the answer section.
    pub fn answer(&self) -> &RecordSection {
        &self.answer
    }

    /// Returns a mutable reference to the answer section.
    pub fn answer_mut(&mut self) -> &mut RecordSection {
        &mut self.answer
    }

    /// Returns a reference to the authority section.
    pub fn authority(&self) -> &RecordSection {
        &self.authority
    }

    /// Returns a mutable reference to the authority section.
    pub fn authority_mut(&mut self) -> &mut RecordSection {
        &mut self.authority
    }

    /// Returns a reference to the additional section.
    ///
    /// The authority section of this type of message does not contain the
    /// OPT record or any records following the OPT record.
    pub fn additional(&self) -> &AdditionalSection {
        &self.additional
    }

    /// Returns a mutable reference to the additional section.
    pub fn additional_mut(&mut self) -> &mut AdditionalSection {
        &mut self.additional
    }

    /// Returns a reference to the OPT record.
    pub fn opt(&self) -> &Opt {
        &self.opt
    }

    /// Returns a mutable reference to the OPT record.
    pub fn opt_mut(&mut self) -> &mut Opt {
        &mut self.opt
    }
}

/// # Conversion from and to base types.
impl Message {
    /// Creates a message from a base message.
    pub fn from_base<Octs: Octets>(
        msg: base::Message<Octs>,
    ) -> Result<Self, ParseError>
    where
        Bytes: for<'a> OctetsFrom<Octs::Range<'a>, Error = Infallible>,
    {
        let header = msg.header();
        let section = msg.question();
        let question = QuestionSection::from_base(section)?;
        let section = section.next_section()?;
        let answer = RecordSection::from_base(section)?;
        let section = section.next_section()?.unwrap();
        let authority = RecordSection::from_base(section)?;
        let section = section.next_section()?.unwrap();
        let (opt, additional) = Section::additional_from_base(section)?;

        Ok(Self {
            header,
            question,
            answer,
            authority,
            additional,
            opt,
        })
    }

    /// Creates a base message.
    pub fn compose<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.header.as_slice())?;
        target.append_slice(
            HeaderCounts::from_counts(
                self.question.len_u16(),
                self.answer.len_u16(),
                self.authority.len_u16(),
                self.additional.len_u16() + 1,
            )
            .as_slice(),
        )?;
        self.question.compose(target)?;
        self.answer.compose(target)?;
        self.authority.compose(target)?;
        self.additional.compose(target)?;
        Ok(())
    }
}

//------------ Opt -----------------------------------------------------------

/// The OPT record of a message.
#[derive(Clone, Default)]
pub struct Opt {
    /// The UDP payload size field from the record header.
    udp_payload_size: u16,

    /// The extended rcode.
    ext_rcode: u8,

    /// The EDNS version.
    version: u8,

    /// The EDNS flags.
    dnssec_ok: bool,

    rdlen: u16,

    data: Vec<AllOptData>,
}

impl Opt {
    fn from_base(base: OptRecord<Bytes>) -> Result<Self, ParseError> {
        let mut data = Vec::new();
        let mut rdlen = 0;
        for item in base.opt().iter_all() {
            let item = item?;
            rdlen += item.compose_len();
            data.push(item.octets_into());
        }
        Ok(Opt {
            udp_payload_size: base.udp_payload_size(),
            ext_rcode: base.ext_rcode(),
            version: base.version(),
            dnssec_ok: base.dnssec_ok(),
            rdlen,
            data,
        })
    }

    fn compose<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        let mut header = OptHeader::default();
        header.set_udp_payload_size(self.udp_payload_size);
        header.set_ext_rcode(self.ext_rcode);
        header.set_dnssec_ok(self.dnssec_ok);
        target.append_slice(header.as_slice())?;
        self.rdlen.compose(target)?;
        self.data.iter().try_for_each(|data| {
            data.code().compose(target)?;
            data.compose_len().compose(target)?;
            data.compose_option(target)
        })
    }
}

//------------ Section -------------------------------------------------------

/// A collection of elements of one of the message sections.
///
/// This type behaves mostly like `Vec<T>`. However, since sections are
/// limited to at most `N` elements, all methods that add additional
/// elements to the section fail rather than panic if the section runs out of
/// space.
#[derive(Clone, Hash, Eq, Ord, PartialEq, PartialOrd)]
pub struct Section<T, const N: usize> {
    elements: Vec<T>,
}

pub type QuestionSection = Section<Question, MAX_SECTION_LEN>;
pub type RecordSection = Section<Record, MAX_SECTION_LEN>;
pub type AdditionalSection = Section<Record, { MAX_SECTION_LEN - 1 }>;

impl<T, const N: usize> Section<T, N> {
    /// Creates a new, empty section.
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a section from a vec without checking the length.
    fn from_vec_unchecked(elements: Vec<T>) -> Self {
        Self { elements }
    }

    /// Creates a new, empty section with the given minimal capacity.
    ///
    /// The section will be able to hold at least `capacity` or 65,535
    /// elements, whatever is smaller.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            elements: Vec::with_capacity(cmp::min(capacity, N)),
        }
    }
}

impl<const N: usize> Section<Question, N> {
    pub fn from_base<Octs: Octets>(
        base: message::QuestionSection<Octs>,
    ) -> Result<Self, ParseError>
    where
        Bytes: for<'a> OctetsFrom<Octs::Range<'a>, Error = Infallible>,
    {
        let mut vec = Vec::new();
        for item in base {
            let item = item?;
            vec.push(item.flatten_into());
        }
        Ok(Self::from_vec_unchecked(vec))
    }

    fn compose<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.elements
            .iter()
            .try_for_each(|elem| elem.compose(target))
    }
}

impl<const N: usize> Section<Record, N> {
    pub fn from_base<Octs: Octets>(
        base: message::RecordSection<Octs>,
    ) -> Result<Self, ParseError>
    where
        Bytes: for<'a> OctetsFrom<Octs::Range<'a>, Error = Infallible>,
    {
        let mut vec = Vec::new();
        for item in base.into_records::<AllRecordData<_, _>>() {
            let item = item?;
            vec.push(item.flatten_into());
        }
        Ok(Self::from_vec_unchecked(vec))
    }

    fn additional_from_base<Octs: Octets>(
        base: message::RecordSection<Octs>,
    ) -> Result<(Opt, Self), ParseError>
    where
        Bytes: for<'a> OctetsFrom<Octs::Range<'a>, Error = Infallible>,
    {
        let mut opt = None;
        let mut vec = Vec::new();
        for item in base.into_records::<AllRecordData<_, _>>() {
            let item = item?;
            match item.try_into_opt() {
                Ok(opt_record) => {
                    opt = Some(Opt::from_base(opt_record.octets_into())?);
                    break;
                }
                Err(item) => vec.push(item.flatten_into()),
            }
        }
        Ok((opt.unwrap_or_default(), Self::from_vec_unchecked(vec)))
    }

    fn compose<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.elements
            .iter()
            .try_for_each(|elem| elem.compose(target))
    }
}

impl<T, const N: usize> Section<T, N> {
    /// Returns the capacity of the section.
    pub fn capacity(&self) -> usize {
        self.elements.capacity()
    }

    /// Reserves capacity for at least this many more elements.
    ///
    /// After this call, the section will have a capacity of at least
    /// `self.len() + additional` elements or 65,535 elements, whatever is
    /// smaller.
    pub fn reserve(&mut self, additional: usize) {
        self.elements
            .reserve(cmp::min(additional, N.saturating_sub(self.len())))
    }

    /// Reserves capacity for exactly this many more elements.
    ///
    /// This is similar to [`reserve`][Self::reserve] but will not
    /// deliberately over-allocate space.
    ///
    /// Note that because the number of elements can not exceed 65,535, the
    /// method will actually reserve less space than requested.
    pub fn reserve_exact(&mut self, additional: usize) {
        self.elements
            .reserve(cmp::min(additional, N.saturating_sub(self.len())))
    }

    /// Returns the number of elements in the section.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    /// Returns the number of elements in the section as an `u16`.
    pub fn len_u16(&self) -> u16 {
        u16::try_from(self.len()).expect("section too large")
    }

    /// Returns whether the section contains no elements.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Shrinks the section’s capacity as much as possible.
    pub fn shrink_to_fit(&mut self) {
        self.elements.shrink_to_fit()
    }

    /// Returns a slice of the elements of the section.
    pub fn as_slice(&self) -> &[T] {
        self.elements.as_slice()
    }

    /// Returns a mutable slice of the elements of the section.
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        self.elements.as_mut_slice()
    }
}

impl<T, const N: usize> Section<T, N> {
    /// Checks that an additional _len_ number of elements can be added.
    fn check_append_len(&self, other: usize) -> Result<(), Exhausted> {
        // This also works safely with 16 bit pointer sizes.
        match self.elements.len().checked_add(other) {
            None => Err(Exhausted(())),
            Some(len) if len > N => Err(Exhausted(())),
            _ => Ok(()),
        }
    }

    /// Appends an element to the end of the section.
    ///
    /// Returns an error if the element doesn’t fit.
    pub fn push(&mut self, element: T) -> Result<(), Exhausted> {
        self.check_append_len(1)?;
        self.elements.push(element);
        Ok(())
    }

    /// Inserts an element at the given index.
    ///
    /// The existing elements with an index equal or greater are shifted to
    /// a position with an index incremented by one.
    ///
    /// Returns an error if no additional elements fit into the section.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds.
    pub fn insert(
        &mut self,
        index: usize,
        element: T,
    ) -> Result<(), Exhausted> {
        self.check_append_len(1)?;
        self.elements.insert(index, element);
        Ok(())
    }

    /// Moves all elements of `other` in `self`, leaving `other` empty.
    ///
    /// If adding all elements would exceed the size limit, returns an error
    /// and does nothing.
    pub fn append<const M: usize>(
        &mut self,
        other: &mut Section<T, M>,
    ) -> Result<(), Exhausted> {
        self.check_append_len(other.elements.len())?;
        self.elements.append(&mut other.elements);
        Ok(())
    }

    /// Clones and adds all elements in the given slice.
    ///
    /// Iterates over the slice, clones each element and appends it to the
    /// section.
    ///
    /// If adding all elements would exceed the size limit, returns an error
    /// and does nothing.
    pub fn extend_from_slice(&mut self, other: &[T]) -> Result<(), Exhausted>
    where
        T: Clone,
    {
        self.check_append_len(other.len())?;
        self.elements.extend_from_slice(other);
        Ok(())
    }
}

impl<T, const N: usize> Section<T, N> {
    /// Removes the last element from the section and returns it.
    ///
    /// Returns `None` if the section is empty.
    pub fn pop(&mut self) -> Option<T> {
        self.elements.pop()
    }

    /// Removes an element and returns it.
    ///
    /// All elements with larger indexes are shifted to a position with a
    /// index decremented by one.
    ///
    /// # Panics
    ///
    /// Panics if the index is out of bounds.
    pub fn remove(&mut self, index: usize) -> T {
        self.elements.remove(index)
    }

    /// Removes an element, returns it, and replaces it with the last one.
    ///
    /// This changes the order but can be done in _O_(1).
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    pub fn swap_remove(&mut self, index: usize) -> T {
        self.elements.swap_remove(index)
    }

    /// Shortens the section to at most the given length.
    ///
    /// Keeps the first `len` elements and drops the rest. If the section
    /// is already up to `len` elements long, does nothing.
    pub fn truncate(&mut self, len: usize) {
        self.elements.truncate(len)
    }

    /// Retains only the elements for which a predicate returns `true`.
    pub fn retain<F: FnMut(&T) -> bool>(&mut self, f: F) {
        self.elements.retain(f)
    }

    /// Retains only the elements for which a predicate returns `true`.
    ///
    /// This version allows manipulating the elements while examining them.
    pub fn retain_mut<F: FnMut(&mut T) -> bool>(&mut self, f: F) {
        self.elements.retain_mut(f)
    }

    /// Removes the given range and returns it as an iterator.
    ///
    /// The method removes the specified range of elements from the section
    /// and returns them as an iterator.
    ///
    /// # Panics
    ///
    /// Panics if the starting point is greater than the end point or if the
    /// end point is greater than the length of the vector.
    ///
    /// # Leaking
    ///
    /// If the returned iterator goes out of scope without being dropped (due
    /// to `mem::forget`, for example), the vector may have lost and leaked
    /// elements arbitrarily, including elements outside the range.
    pub fn drain<R: ops::RangeBounds<usize>>(
        &mut self,
        range: R,
    ) -> impl Iterator<Item = T> + '_ {
        self.elements.drain(range)
    }

    /// Removes all elements from the section.
    pub fn clear(&mut self) {
        self.elements.clear()
    }

    /// Splits the section at the given index.
    ///
    /// Returns a newly allocated section containing the elements starting
    /// with and including the one at the given index. The section will
    /// retain all other elements.
    ///
    /// # Panics
    ///
    /// Panics if `at` is out of bounds.
    pub fn split_off(&mut self, at: usize) -> Self {
        Self {
            elements: self.elements.split_off(at),
        }
    }

    /// Removes consecutive equal elements.
    pub fn dedup(&mut self)
    where
        T: PartialEq,
    {
        self.elements.dedup()
    }

    /// Removes all duplicate elements.
    ///
    /// Does so without changing the order of elements.
    pub fn dedup_all(&mut self)
    where
        T: PartialEq,
    {
        // XXX Surely there is a more efficient impl?
        for i in (1..self.len()).rev() {
            for j in 0..(i - 1) {
                if self.elements[i] == self.elements[j] {
                    self.elements.remove(i);
                }
            }
        }
    }
}

//--- Default

impl<T, const N: usize> Default for Section<T, N> {
    fn default() -> Self {
        Self {
            elements: Default::default(),
        }
    }
}

//--- From and TryFrom
//
// Because a section can become full, most of these are TryFrom impls where
// Vec<T> actually has From impls.

impl<T, const N: usize> TryFrom<Vec<T>> for Section<T, N> {
    type Error = Exhausted;

    fn try_from(src: Vec<T>) -> Result<Self, Self::Error> {
        if src.len() > N {
            Err(Exhausted(()))
        } else {
            Ok(Self::from_vec_unchecked(src))
        }
    }
}

impl<T: Clone, const N: usize> TryFrom<&[T]> for Section<T, N> {
    type Error = Exhausted;

    fn try_from(src: &[T]) -> Result<Self, Self::Error> {
        if src.len() > N {
            Err(Exhausted(()))
        } else {
            Ok(Self::from_vec_unchecked(src.into()))
        }
    }
}

/// Creates a section from an array.
///
/// # Panics
///
/// This will panic if `N` is larger than `u16::MAX`.
impl<T, const M: usize, const N: usize> From<[T; M]> for Section<T, N> {
    fn from(src: [T; M]) -> Self {
        assert!(M <= N);
        Self::from_vec_unchecked(src.into())
    }
}

impl<T, const M: usize, const N: usize> TryFrom<Section<T, N>> for [T; M] {
    type Error = Section<T, N>;

    fn try_from(src: Section<T, N>) -> Result<Self, Self::Error> {
        src.elements.try_into().map_err(Section::from_vec_unchecked)
    }
}

//--- Deref and DerefMut, AsRef and AsRefMut, Borrow and BorrowMut

impl<T, const N: usize> ops::Deref for Section<T, N> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T, const N: usize> ops::DerefMut for Section<T, N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.as_mut_slice()
    }
}

impl<T, const N: usize> AsRef<[T]> for Section<T, N> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T, const N: usize> AsMut<[T]> for Section<T, N> {
    fn as_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

impl<T, const N: usize> borrow::Borrow<[T]> for Section<T, N> {
    fn borrow(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T, const N: usize> borrow::BorrowMut<[T]> for Section<T, N> {
    fn borrow_mut(&mut self) -> &mut [T] {
        self.as_mut_slice()
    }
}

//--- Extend
//
// No extend because it never fails.

//--- Index and IndexMut

impl<T, const N: usize, I: slice::SliceIndex<[T]>> ops::Index<I>
    for Section<T, N>
{
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        self.elements.index(index)
    }
}

impl<T, const N: usize, I: slice::SliceIndex<[T]>> ops::IndexMut<I>
    for Section<T, N>
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        self.elements.index_mut(index)
    }
}

//--- IntoIterator

impl<T, const N: usize> IntoIterator for Section<T, N> {
    type Item = T;
    type IntoIter = vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.into_iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a Section<T, N> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut Section<T, N> {
    type Item = &'a mut T;
    type IntoIter = slice::IterMut<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.elements.iter_mut()
    }
}

//============ Helpers =======================================================

//------------ Constants -----------------------------------------------------

/// The maximum number of elements in a sections.
///
/// This is u16::MAX, but we need it as a usize. Because `From::from` isn’t
/// const, we need to use `as` here.
const MAX_SECTION_LEN: usize = u16::MAX as usize;

//============ Errors ========================================================

//------------ Exhausted -----------------------------------------------------

/// A section’s space is exhausted.
#[derive(Clone, Copy, Debug)]
pub struct Exhausted(());

impl fmt::Display for Exhausted {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("section space exhausted")
    }
}

impl error::Error for Exhausted {}
