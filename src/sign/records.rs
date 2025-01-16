//! Types for iterating over and storing zone records in canonical sort order.
use core::cmp::Ordering;
use core::convert::From;
use core::iter::Extend;
use core::marker::{PhantomData, Send};
use core::ops::Deref;
use core::slice::Iter;

use std::vec::Vec;
use std::{fmt, slice};

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{Class, Rtype};
use crate::base::name::ToName;
use crate::base::rdata::RecordData;
use crate::base::record::Record;
use crate::base::Ttl;

//------------ Sorter --------------------------------------------------------

/// A DNS resource record sorter.
///
/// Implement this trait to use a different sorting algorithm than that
/// implemented by [`DefaultSorter`], e.g. to use system resources in a
/// different way when sorting.
pub trait Sorter {
    /// Sort the given DNS resource records.
    ///
    /// The imposed order should be compatible with the ordering defined by
    /// RFC 8976 section 3.3.1, i.e. _"DNSSEC's canonical on-the-wire RR
    /// format (without name compression) and ordering as specified in
    /// Sections 6.1, 6.2, and 6.3 of [RFC4034] with the additional provision
    /// that RRsets having the same owner name MUST be numerically ordered, in
    /// ascending order, by their numeric RR TYPE"_.
    fn sort_by<N, D, F>(records: &mut Vec<Record<N, D>>, compare: F)
    where
        F: Fn(&Record<N, D>, &Record<N, D>) -> Ordering + Sync,
        Record<N, D>: CanonicalOrd + Send;
}

//------------ DefaultSorter -------------------------------------------------

/// The default [`Sorter`] implementation used by [`SortedRecords`].
///
/// The current implementation is the single threaded sort provided by Rust
/// [`std::vec::Vec::sort_by()`].
pub struct DefaultSorter;

impl Sorter for DefaultSorter {
    fn sort_by<N, D, F>(records: &mut Vec<Record<N, D>>, compare: F)
    where
        F: Fn(&Record<N, D>, &Record<N, D>) -> Ordering + Sync,
        Record<N, D>: CanonicalOrd + Send,
    {
        records.sort_by(compare);
    }
}

//------------ SortedRecords -------------------------------------------------

/// A collection of resource records sorted for signing.
///
/// The sort algorithm used defaults to [`DefaultSorter`] but can be
/// overridden by being generic over an alternate implementation of
/// [`Sorter`].
#[derive(Clone)]
pub struct SortedRecords<N, D, Sort = DefaultSorter>
where
    Record<N, D>: Send,
    Sort: Sorter,
{
    records: Vec<Record<N, D>>,

    _phantom: PhantomData<Sort>,
}

impl<N, D, Sort> SortedRecords<N, D, Sort>
where
    Record<N, D>: Send,
    Sort: Sorter,
{
    pub fn new() -> Self {
        SortedRecords {
            records: Vec::new(),
            _phantom: Default::default(),
        }
    }

    /// Insert a record in sorted order.
    ///
    /// If inserting a lot of records at once prefer [`extend()`] instead
    /// which will sort once after all insertions rather than once per
    /// insertion.
    pub fn insert(&mut self, record: Record<N, D>) -> Result<(), Record<N, D>>
    where
        N: ToName,
        D: RecordData + CanonicalOrd,
    {
        let idx = self
            .records
            .binary_search_by(|stored| stored.canonical_cmp(&record));
        match idx {
            Ok(_) => Err(record),
            Err(idx) => {
                self.records.insert(idx, record);
                Ok(())
            }
        }
    }

    /// Remove all records matching the owner name, class, and rtype.
    /// Class and Rtype can be None to match any.
    ///
    /// Returns:
    ///   - true: if one or more matching records were found (and removed)
    ///   - false: if no matching record was found
    pub fn remove_all_by_name_class_rtype(
        &mut self,
        name: N,
        class: Option<Class>,
        rtype: Option<Rtype>,
    ) -> bool
    where
        N: ToName + Clone,
        D: RecordData,
    {
        let mut found_one = false;
        loop {
            if self.remove_first_by_name_class_rtype(
                name.clone(),
                class,
                rtype,
            ) {
                found_one = true
            } else {
                break;
            }
        }

        found_one
    }

    /// Remove first records matching the owner name, class, and rtype.
    /// Class and Rtype can be None to match any.
    ///
    /// Returns:
    ///   - true: if a matching record was found (and removed)
    ///   - false: if no matching record was found
    pub fn remove_first_by_name_class_rtype(
        &mut self,
        name: N,
        class: Option<Class>,
        rtype: Option<Rtype>,
    ) -> bool
    where
        N: ToName,
        D: RecordData,
    {
        let idx = self.records.binary_search_by(|stored| {
            // Ordering based on base::Record::canonical_cmp excluding comparison of data

            if let Some(class) = class {
                match stored.class().cmp(&class) {
                    Ordering::Equal => {}
                    res => return res,
                }
            }

            match stored.owner().name_cmp(&name) {
                Ordering::Equal => {}
                res => return res,
            }

            if let Some(rtype) = rtype {
                stored.rtype().cmp(&rtype)
            } else {
                Ordering::Equal
            }
        });
        match idx {
            Ok(idx) => {
                self.records.remove(idx);
                true
            }
            Err(_) => false,
        }
    }

    pub fn owner_rrs(&self) -> RecordsIter<N, D> {
        RecordsIter::new(&self.records)
    }

    pub fn rrsets(&self) -> RrsetIter<N, D> {
        RrsetIter::new(&self.records)
    }

    pub fn find_soa(&self) -> Option<Rrset<N, D>>
    where
        N: ToName,
        D: RecordData,
    {
        self.rrsets().find(|rrset| rrset.rtype() == Rtype::SOA)
    }

    /// Update the data of an existing record.
    ///
    /// Allowing records to be mutated in-place would not be safe because it
    /// could invalidate the sort order so no general method to mutate the
    /// records is provided.
    ///
    /// This method offers a limited ability to mutate records in-place
    /// however because it only permits mutating of the resource record data
    /// of an existing record which doesn't impact the sort order because the
    /// data is not part of the sort key.
    pub fn update_data<F>(&mut self, matcher: F, new_data: D)
    where
        F: Fn(&Record<N, D>) -> bool,
    {
        if let Some(rr) = self.records.iter_mut().find(|rr| matcher(rr)) {
            *rr.data_mut() = new_data;
        }
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn iter(&self) -> Iter<'_, Record<N, D>> {
        self.records.iter()
    }

    pub(super) fn as_mut_slice(&mut self) -> &mut [Record<N, D>] {
        self.records.as_mut_slice()
    }

    pub fn into_inner(self) -> Vec<Record<N, D>> {
        self.records
    }
}

impl<N, D, Sort> Deref for SortedRecords<N, D, Sort>
where
    N: Send,
    D: Send,
    Sort: Sorter,
{
    type Target = [Record<N, D>];

    fn deref(&self) -> &Self::Target {
        &self.records
    }
}

impl<N, D, Sort> SortedRecords<N, D, Sort>
where
    N: ToName + Send,
    D: RecordData + CanonicalOrd + Send,
    Sort: Sorter,
    SortedRecords<N, D>: From<Vec<Record<N, D>>>,
{
    pub fn write<W>(&self, target: &mut W) -> Result<(), fmt::Error>
    where
        N: fmt::Display,
        D: RecordData + fmt::Display,
        W: fmt::Write,
    {
        for record in self.records.iter().filter(|r| r.rtype() == Rtype::SOA)
        {
            write!(target, "{record}")?;
        }

        for record in self.records.iter().filter(|r| r.rtype() != Rtype::SOA)
        {
            write!(target, "{record}")?;
        }

        Ok(())
    }

    pub fn write_with_comments<W, F>(
        &self,
        target: &mut W,
        comment_cb: F,
    ) -> Result<(), fmt::Error>
    where
        N: fmt::Display,
        D: RecordData + fmt::Display,
        W: fmt::Write,
        F: Fn(&Record<N, D>, &mut W) -> Result<(), fmt::Error>,
    {
        for record in self.records.iter().filter(|r| r.rtype() == Rtype::SOA)
        {
            write!(target, "{record}")?;
            comment_cb(record, target)?;
            writeln!(target)?;
        }

        for record in self.records.iter().filter(|r| r.rtype() != Rtype::SOA)
        {
            write!(target, "{record}")?;
            comment_cb(record, target)?;
            writeln!(target)?;
        }

        Ok(())
    }
}

impl<N: Send, D: Send + CanonicalOrd> Default
    for SortedRecords<N, D, DefaultSorter>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<N, D, Sort> From<Vec<Record<N, D>>> for SortedRecords<N, D, Sort>
where
    N: ToName + PartialEq + Send,
    D: RecordData + CanonicalOrd + PartialEq + Send,
    Sort: Sorter,
{
    fn from(mut src: Vec<Record<N, D>>) -> Self {
        Sort::sort_by(&mut src, CanonicalOrd::canonical_cmp);
        src.dedup();
        SortedRecords {
            records: src,
            _phantom: Default::default(),
        }
    }
}

impl<N, D, Sort> FromIterator<Record<N, D>> for SortedRecords<N, D, Sort>
where
    N: ToName,
    D: RecordData + CanonicalOrd,
    N: Send,
    D: Send,
    Sort: Sorter,
{
    fn from_iter<T: IntoIterator<Item = Record<N, D>>>(iter: T) -> Self {
        let mut res = Self::new();
        for item in iter {
            let _ = res.insert(item);
        }
        res
    }
}

impl<N, D, Sort> Extend<Record<N, D>> for SortedRecords<N, D, Sort>
where
    N: ToName + PartialEq,
    D: RecordData + CanonicalOrd + PartialEq,
    N: Send,
    D: Send,
    Sort: Sorter,
{
    fn extend<T: IntoIterator<Item = Record<N, D>>>(&mut self, iter: T) {
        for item in iter {
            self.records.push(item);
        }
        Sort::sort_by(&mut self.records, CanonicalOrd::canonical_cmp);
        self.records.dedup();
    }
}

//------------ OwnerRrs ------------------------------------------------------

/// A set of records with the same owner name.
#[derive(Clone)]
pub struct OwnerRrs<'a, N, D> {
    slice: &'a [Record<N, D>],
}

impl<'a, N, D> OwnerRrs<'a, N, D> {
    fn new(slice: &'a [Record<N, D>]) -> Self {
        OwnerRrs { slice }
    }

    pub fn owner(&self) -> &N {
        self.slice[0].owner()
    }

    pub fn class(&self) -> Class {
        self.slice[0].class()
    }

    pub fn rrsets(&self) -> OwnerRrsIter<'a, N, D> {
        OwnerRrsIter::new(self.slice)
    }

    pub fn records(&self) -> slice::Iter<'a, Record<N, D>> {
        self.slice.iter()
    }

    pub fn is_zone_cut(&self, apex: &N) -> bool
    where
        N: ToName + PartialEq,
        D: RecordData,
    {
        self.owner().ne(apex)
            && self.records().any(|record| record.rtype() == Rtype::NS)
    }

    pub fn is_in_zone(&self, apex: &N) -> bool
    where
        N: ToName,
    {
        self.owner().ends_with(&apex)
    }
}

//------------ Rrset ---------------------------------------------------------

/// A set of records with the same owner name, class, and record type.
pub struct Rrset<'a, N, D> {
    slice: &'a [Record<N, D>],
}

impl<'a, N, D> Rrset<'a, N, D> {
    pub fn new(slice: &'a [Record<N, D>]) -> Self {
        Rrset { slice }
    }

    pub fn owner(&self) -> &N {
        self.slice[0].owner()
    }

    pub fn class(&self) -> Class {
        self.slice[0].class()
    }

    pub fn rtype(&self) -> Rtype
    where
        D: RecordData,
    {
        self.slice[0].rtype()
    }

    pub fn ttl(&self) -> Ttl {
        self.slice[0].ttl()
    }

    pub fn first(&self) -> &Record<N, D> {
        &self.slice[0]
    }

    pub fn iter(&self) -> slice::Iter<'a, Record<N, D>> {
        self.slice.iter()
    }

    pub fn len(&self) -> usize {
        self.slice.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slice.is_empty()
    }

    pub fn as_slice(&self) -> &'a [Record<N, D>] {
        self.slice
    }

    pub fn into_inner(self) -> &'a [Record<N, D>] {
        self.slice
    }
}

//------------ RecordsIter ---------------------------------------------------

/// An iterator that produces groups of records belonging to the same owner
/// from sorted records.
pub struct RecordsIter<'a, N, D> {
    slice: &'a [Record<N, D>],
}

impl<'a, N, D> RecordsIter<'a, N, D> {
    pub fn new(slice: &'a [Record<N, D>]) -> Self {
        RecordsIter { slice }
    }

    pub fn first(&self) -> &'a Record<N, D> {
        &self.slice[0]
    }

    pub fn skip_before(&mut self, apex: &N)
    where
        N: ToName + PartialEq,
    {
        while let Some(first) = self.slice.first().map(|r| r.owner()) {
            if apex == first || first.ends_with(apex) {
                break;
            }
            self.slice = &self.slice[1..]
        }
    }
}

impl<'a, N, D> Iterator for RecordsIter<'a, N, D>
where
    N: ToName + 'a,
    D: RecordData + 'a,
{
    type Item = OwnerRrs<'a, N, D>;

    fn next(&mut self) -> Option<Self::Item> {
        let first = self.slice.first()?;
        let mut end = 1;
        while let Some(record) = self.slice.get(end) {
            if !record.owner().name_eq(first.owner()) {
                break;
            }
            end += 1;
        }
        let (res, slice) = self.slice.split_at(end);
        self.slice = slice;
        Some(OwnerRrs::new(res))
    }
}

//------------ RrsetIter -----------------------------------------------------

/// An iterator that produces RRsets from sorted records.
pub struct RrsetIter<'a, N, D> {
    slice: &'a [Record<N, D>],
}

impl<'a, N, D> RrsetIter<'a, N, D> {
    fn new(slice: &'a [Record<N, D>]) -> Self {
        RrsetIter { slice }
    }
}

impl<'a, N, D> Iterator for RrsetIter<'a, N, D>
where
    N: ToName + 'a,
    D: RecordData + 'a,
{
    type Item = Rrset<'a, N, D>;

    fn next(&mut self) -> Option<Self::Item> {
        let first = self.slice.first()?;
        let mut end = 1;
        while let Some(record) = self.slice.get(end) {
            if !record.owner().name_eq(first.owner())
                || record.rtype() != first.rtype()
            {
                break;
            }
            end += 1;
        }
        let (res, slice) = self.slice.split_at(end);
        self.slice = slice;
        Some(Rrset::new(res))
    }
}

//------------ OwnerRrsIter --------------------------------------------------

/// An iterator that produces RRsets from a set of records with the same owner
/// name.
pub struct OwnerRrsIter<'a, N, D> {
    slice: &'a [Record<N, D>],
}

impl<'a, N, D> OwnerRrsIter<'a, N, D> {
    fn new(slice: &'a [Record<N, D>]) -> Self {
        OwnerRrsIter { slice }
    }
}

impl<'a, N, D> Iterator for OwnerRrsIter<'a, N, D>
where
    N: ToName + 'a,
    D: RecordData + 'a,
{
    type Item = Rrset<'a, N, D>;

    fn next(&mut self) -> Option<Self::Item> {
        let first = self.slice.first()?;
        let mut end = 1;
        while let Some(record) = self.slice.get(end) {
            if record.rtype() != first.rtype() {
                break;
            }
            end += 1;
        }
        let (res, slice) = self.slice.split_at(end);
        self.slice = slice;
        Some(Rrset::new(res))
    }
}
