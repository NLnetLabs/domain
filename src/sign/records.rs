//! Actual signing.

use super::key::SigningKey;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{Class, Rtype};
use crate::base::name::ToName;
use crate::base::rdata::{ComposeRecordData, RecordData};
use crate::base::record::Record;
use crate::base::Ttl;
use crate::rdata::dnssec::{ProtoRrsig, RtypeBitmap, Timestamp};
use crate::rdata::{Dnskey, Ds, Nsec, Rrsig};
use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, Truncate};
use std::vec::Vec;
use std::{fmt, io, slice};

//------------ SortedRecords -------------------------------------------------

/// A collection of resource records sorted for signing.
#[derive(Clone)]
pub struct SortedRecords<N, D> {
    records: Vec<Record<N, D>>,
}

impl<N, D> SortedRecords<N, D> {
    pub fn new() -> Self {
        SortedRecords {
            records: Vec::new(),
        }
    }

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

    pub fn families(&self) -> RecordsIter<N, D> {
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

    #[allow(clippy::type_complexity)]
    pub fn sign<Octets, Key, ApexName>(
        &self,
        apex: &FamilyName<ApexName>,
        expiration: Timestamp,
        inception: Timestamp,
        key: Key,
    ) -> Result<Vec<Record<N, Rrsig<Octets, ApexName>>>, Key::Error>
    where
        N: ToName + Clone,
        D: RecordData + ComposeRecordData,
        Key: SigningKey,
        Octets: From<Key::Signature> + AsRef<[u8]>,
        ApexName: ToName + Clone,
    {
        let mut res = Vec::new();
        let mut buf = Vec::new();

        // The owner name of a zone cut if we currently are at or below one.
        let mut cut: Option<FamilyName<N>> = None;

        let mut families = self.families();

        // Since the records are ordered, the first family is the apex --
        // we can skip everything before that.
        families.skip_before(apex);

        for family in families {
            // If the owner is out of zone, we have moved out of our zone and
            // are done.
            if !family.is_in_zone(apex) {
                break;
            }

            // If the family is below a zone cut, we must ignore it.
            if let Some(ref cut) = cut {
                if family.owner().ends_with(cut.owner()) {
                    continue;
                }
            }

            // A copy of the family name. We’ll need it later.
            let name = family.family_name().cloned();

            // If this family is the parent side of a zone cut, we keep the
            // family name for later. This also means below that if
            // `cut.is_some()` we are at the parent side of a zone.
            cut = if family.is_zone_cut(apex) {
                Some(name.clone())
            } else {
                None
            };

            for rrset in family.rrsets() {
                if cut.is_some() {
                    // If we are at a zone cut, we only sign DS and NSEC
                    // records. NS records we must not sign and everything
                    // else shouldn’t be here, really.
                    if rrset.rtype() != Rtype::DS
                        && rrset.rtype() != Rtype::NSEC
                    {
                        continue;
                    }
                } else {
                    // Otherwise we only ignore RRSIGs.
                    if rrset.rtype() == Rtype::RRSIG {
                        continue;
                    }
                }

                // Create the signature.
                buf.clear();
                let rrsig = ProtoRrsig::new(
                    rrset.rtype(),
                    key.algorithm()?,
                    name.owner().rrsig_label_count(),
                    rrset.ttl(),
                    expiration,
                    inception,
                    key.key_tag()?,
                    apex.owner().clone(),
                );
                rrsig.compose_canonical(&mut buf).unwrap();
                for record in rrset.iter() {
                    record.compose_canonical(&mut buf).unwrap();
                }

                // Create and push the RRSIG record.
                res.push(Record::new(
                    name.owner().clone(),
                    name.class(),
                    rrset.ttl(),
                    rrsig
                        .into_rrsig(key.sign(&buf)?.into())
                        .expect("long signature"),
                ));
            }
        }
        Ok(res)
    }

    pub fn nsecs<Octets, ApexName>(
        &self,
        apex: &FamilyName<ApexName>,
        ttl: Ttl,
    ) -> Vec<Record<N, Nsec<Octets, N>>>
    where
        N: ToName + Clone,
        D: RecordData,
        Octets: FromBuilder,
        Octets::Builder: EmptyBuilder + Truncate + AsRef<[u8]> + AsMut<[u8]>,
        <Octets::Builder as OctetsBuilder>::AppendError: fmt::Debug,
        ApexName: ToName,
    {
        let mut res = Vec::new();

        // The owner name of a zone cut if we currently are at or below one.
        let mut cut: Option<FamilyName<N>> = None;

        let mut families = self.families();

        // Since the records are ordered, the first family is the apex --
        // we can skip everything before that.
        families.skip_before(apex);

        // Because of the next name thing, we need to keep the last NSEC
        // around.
        let mut prev: Option<(FamilyName<N>, RtypeBitmap<Octets>)> = None;

        // We also need the apex for the last NSEC.
        let apex_owner = families.first_owner().clone();

        for family in families {
            // If the owner is out of zone, we have moved out of our zone and
            // are done.
            if !family.is_in_zone(apex) {
                break;
            }

            // If the family is below a zone cut, we must ignore it.
            if let Some(ref cut) = cut {
                if family.owner().ends_with(cut.owner()) {
                    continue;
                }
            }

            // A copy of the family name. We’ll need it later.
            let name = family.family_name().cloned();

            // If this family is the parent side of a zone cut, we keep the
            // family name for later. This also means below that if
            // `cut.is_some()` we are at the parent side of a zone.
            cut = if family.is_zone_cut(apex) {
                Some(name.clone())
            } else {
                None
            };

            if let Some((prev_name, bitmap)) = prev.take() {
                res.push(prev_name.into_record(
                    ttl,
                    Nsec::new(name.owner().clone(), bitmap),
                ));
            }

            let mut bitmap = RtypeBitmap::<Octets>::builder();
            // RFC 4035 section 2.3:
            //  "The type bitmap of every NSEC resource record in a signed
            //   zone MUST indicate the presence of both the NSEC record
            //   itself and its corresponding RRSIG record."
            bitmap.add(Rtype::RRSIG).unwrap();
            bitmap.add(Rtype::NSEC).unwrap();
            for rrset in family.rrsets() {
                bitmap.add(rrset.rtype()).unwrap()
            }

            prev = Some((name, bitmap.finalize()));
        }
        if let Some((prev_name, bitmap)) = prev {
            res.push(
                prev_name.into_record(ttl, Nsec::new(apex_owner, bitmap)),
            );
        }
        res
    }

    pub fn write<W>(&self, target: &mut W) -> Result<(), io::Error>
    where
        N: fmt::Display,
        D: RecordData + fmt::Display,
        W: io::Write,
    {
        for record in &self.records {
            writeln!(target, "{}", record)?;
        }
        Ok(())
    }
}

impl<N, D> Default for SortedRecords<N, D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<N, D> From<Vec<Record<N, D>>> for SortedRecords<N, D>
where
    N: ToName,
    D: RecordData + CanonicalOrd,
{
    fn from(mut src: Vec<Record<N, D>>) -> Self {
        src.sort_by(CanonicalOrd::canonical_cmp);
        SortedRecords { records: src }
    }
}

impl<N, D> FromIterator<Record<N, D>> for SortedRecords<N, D>
where
    N: ToName,
    D: RecordData + CanonicalOrd,
{
    fn from_iter<T: IntoIterator<Item = Record<N, D>>>(iter: T) -> Self {
        let mut res = Self::new();
        for item in iter {
            let _ = res.insert(item);
        }
        res
    }
}

impl<N, D> Extend<Record<N, D>> for SortedRecords<N, D>
where
    N: ToName,
    D: RecordData + CanonicalOrd,
{
    fn extend<T: IntoIterator<Item = Record<N, D>>>(&mut self, iter: T) {
        for item in iter {
            let _ = self.insert(item);
        }
    }
}

//------------ Family --------------------------------------------------------

/// A set of records with the same owner name and class.
pub struct Family<'a, N, D> {
    slice: &'a [Record<N, D>],
}

impl<'a, N, D> Family<'a, N, D> {
    fn new(slice: &'a [Record<N, D>]) -> Self {
        Family { slice }
    }

    pub fn owner(&self) -> &N {
        self.slice[0].owner()
    }

    pub fn class(&self) -> Class {
        self.slice[0].class()
    }

    pub fn family_name(&self) -> FamilyName<&N> {
        FamilyName::new(self.owner(), self.class())
    }

    pub fn rrsets(&self) -> FamilyIter<'a, N, D> {
        FamilyIter::new(self.slice)
    }

    pub fn records(&self) -> slice::Iter<'a, Record<N, D>> {
        self.slice.iter()
    }

    pub fn is_zone_cut<NN>(&self, apex: &FamilyName<NN>) -> bool
    where
        N: ToName,
        NN: ToName,
        D: RecordData,
    {
        self.family_name().ne(apex)
            && self.records().any(|record| record.rtype() == Rtype::NS)
    }

    pub fn is_in_zone<NN: ToName>(&self, apex: &FamilyName<NN>) -> bool
    where
        N: ToName,
    {
        self.owner().ends_with(&apex.owner) && self.class() == apex.class
    }
}

//------------ FamilyName ----------------------------------------------------

/// The identifier for a family, i.e., a owner name and class.
#[derive(Clone)]
pub struct FamilyName<N> {
    owner: N,
    class: Class,
}

impl<N> FamilyName<N> {
    pub fn new(owner: N, class: Class) -> Self {
        FamilyName { owner, class }
    }

    pub fn owner(&self) -> &N {
        &self.owner
    }

    pub fn class(&self) -> Class {
        self.class
    }

    pub fn into_record<D>(self, ttl: Ttl, data: D) -> Record<N, D>
    where
        N: Clone,
    {
        Record::new(self.owner.clone(), self.class, ttl, data)
    }

    pub fn dnskey<K: SigningKey, Octets: From<K::Octets>>(
        &self,
        ttl: Ttl,
        key: K,
    ) -> Result<Record<N, Dnskey<Octets>>, K::Error>
    where
        N: Clone,
    {
        key.dnskey()
            .map(|dnskey| self.clone().into_record(ttl, dnskey.convert()))
    }

    pub fn ds<K: SigningKey>(
        &self,
        ttl: Ttl,
        key: K,
    ) -> Result<Record<N, Ds<K::Octets>>, K::Error>
    where
        N: ToName + Clone,
    {
        key.ds(&self.owner)
            .map(|ds| self.clone().into_record(ttl, ds))
    }
}

impl<'a, N: Clone> FamilyName<&'a N> {
    pub fn cloned(&self) -> FamilyName<N> {
        FamilyName {
            owner: (*self.owner).clone(),
            class: self.class,
        }
    }
}

impl<N: ToName, NN: ToName> PartialEq<FamilyName<NN>> for FamilyName<N> {
    fn eq(&self, other: &FamilyName<NN>) -> bool {
        self.owner.name_eq(&other.owner) && self.class == other.class
    }
}

impl<N: ToName, NN: ToName, D> PartialEq<Record<NN, D>> for FamilyName<N> {
    fn eq(&self, other: &Record<NN, D>) -> bool {
        self.owner.name_eq(other.owner()) && self.class == other.class()
    }
}

//------------ Rrset ---------------------------------------------------------

/// A set of records with the same owner name, class, and record type.
pub struct Rrset<'a, N, D> {
    slice: &'a [Record<N, D>],
}

impl<'a, N, D> Rrset<'a, N, D> {
    fn new(slice: &'a [Record<N, D>]) -> Self {
        Rrset { slice }
    }

    pub fn owner(&self) -> &N {
        self.slice[0].owner()
    }

    pub fn class(&self) -> Class {
        self.slice[0].class()
    }

    pub fn family_name(&self) -> FamilyName<&N> {
        FamilyName::new(self.owner(), self.class())
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
}

//------------ RecordsIter ---------------------------------------------------

/// An iterator that produces families from sorted records.
pub struct RecordsIter<'a, N, D> {
    slice: &'a [Record<N, D>],
}

impl<'a, N, D> RecordsIter<'a, N, D> {
    fn new(slice: &'a [Record<N, D>]) -> Self {
        RecordsIter { slice }
    }

    pub fn first_owner(&self) -> &'a N {
        self.slice[0].owner()
    }

    pub fn skip_before<NN: ToName>(&mut self, apex: &FamilyName<NN>)
    where
        N: ToName,
    {
        for rr in self.slice {
            if rr.class() == apex.class()
                && (apex == rr || rr.owner().ends_with(apex.owner()))
            {
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
    type Item = Family<'a, N, D>;

    fn next(&mut self) -> Option<Self::Item> {
        let first = match self.slice.first() {
            Some(first) => first,
            None => return None,
        };
        let mut end = 1;
        while let Some(record) = self.slice.get(end) {
            if !record.owner().name_eq(first.owner())
                || record.class() != first.class()
            {
                break;
            }
            end += 1;
        }
        let (res, slice) = self.slice.split_at(end);
        self.slice = slice;
        Some(Family::new(res))
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
        let first = match self.slice.first() {
            Some(first) => first,
            None => return None,
        };
        let mut end = 1;
        while let Some(record) = self.slice.get(end) {
            if !record.owner().name_eq(first.owner())
                || record.rtype() != first.rtype()
                || record.class() != first.class()
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

//------------ FamilyIter ----------------------------------------------------

/// An iterator that produces RRsets from a record family.
pub struct FamilyIter<'a, N, D> {
    slice: &'a [Record<N, D>],
}

impl<'a, N, D> FamilyIter<'a, N, D> {
    fn new(slice: &'a [Record<N, D>]) -> Self {
        FamilyIter { slice }
    }
}

impl<'a, N, D> Iterator for FamilyIter<'a, N, D>
where
    N: ToName + 'a,
    D: RecordData + 'a,
{
    type Item = Rrset<'a, N, D>;

    fn next(&mut self) -> Option<Self::Item> {
        let first = match self.slice.first() {
            Some(first) => first,
            None => return None,
        };
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
