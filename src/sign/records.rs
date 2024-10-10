//! Actual signing.

use super::key::SigningKey;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{Class, Nsec3HashAlg, Rtype};
use crate::base::name::{ToLabelIter, ToName};
use crate::base::rdata::{ComposeRecordData, RecordData};
use crate::base::record::Record;
use crate::base::{Name, NameBuilder, Ttl};
use crate::rdata::dnssec::{ProtoRrsig, RtypeBitmap, Timestamp};
use crate::rdata::nsec3::{Nsec3Salt, OwnerHash};
use crate::rdata::{Dnskey, Ds, Nsec, Nsec3, Rrsig, ZoneRecordData};
use crate::utils::base32;
use crate::validator::nsec3_hash;
use bytes::Bytes;
use core::convert::Infallible;
use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, Truncate};
use octseq::{FreezeBuilder, OctetsFrom};
use std::collections::HashMap;
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
        N: ToName + Clone + std::fmt::Debug,
        D: RecordData + ComposeRecordData + std::fmt::Debug,
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
        // NSECs in combination with RRSIGs allow a server to respond with
        // verified (secured) authority that either a domain does not exist or
        // that the domain exists but the requested RTYPE does not. Without
        // NSEC any such negative response would lack an accompanying DNSSEC
        // signature (RRSIG) so would not be verifiable. The NSEC record
        // cannot exist at the non-existing name without creating NSECS for
        // every possible name which is infeasible, so RRSIG records also
        // cannot exist for every possible non-existing name. An RRSIG record
        // needs to be associated with an actual existing record thus NSECs
        // have to exist but cannot exist for non-existent names, so where
        // should they exist? The answer is that they should exist on the
        // existing names and "cover" the gap between the existing names. The
        // signed statement that a gap exists (where the requested name or
        // RTYPE would be if existed) can then be returned by the server. This
        // topic is known as Authenticated Denial of Existence (see RFC 7129).
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
            // Assume there’s gonna be an RRSIG.
            bitmap.add(Rtype::RRSIG).unwrap();
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

    pub fn nsec3s<Octets, ApexName>(
        &self,
        apex: &FamilyName<ApexName>,
        ttl: Ttl,
        create_lookups: bool,
    ) -> (
        Vec<Record<N, Nsec3<Octets>>>,
        Option<(
            HashMap<N, OwnerHash<Octets>>,
            HashMap<OwnerHash<Octets>, Name<Vec<u8>>>,
        )>,
    )
    where
        N: ToName
            + Clone
            + From<Name<Octets>>
            + std::fmt::Display
            + Eq
            + std::hash::Hash,
        D: RecordData,
        Octets:
            FromBuilder + OctetsFrom<Vec<u8>> + From<&'static [u8]> + Clone,
        Octets::Builder: EmptyBuilder + Truncate + AsRef<[u8]> + AsMut<[u8]>,
        <Octets::Builder as OctetsBuilder>::AppendError: fmt::Debug,
        ApexName: ToName,
        Infallible: From<<Octets as OctetsFrom<Vec<u8>>>::Error>,
    {
        // Unlike NSEC, NSEC3 (a) doesn't leak the names that actually exist
        // in the zone, and (b) allows non-existence to be proven without
        // having special records (NSEC) at every authoritative name in the
        // zone (as creating such records and their corresonding DNSSEC RRSIG
        // signatures is expensive). Instead NSEC3 allows ranges of insecure
        // delegations to be be skipped (the names inside the range are said
        // to "opt-out" of NSEC3) when creating NSEC3 records unlike with NSEC
        // where insecure delegations (NS records without a DS record) are
        // still required to have an accompanying NSEC record. The NSEC3
        // record indicates whether it is Opt-Out or not because the proofs
        // that need to be created and verified are different for opt-out than
        // otherwise.
        //
        // TODO:
        //   - Handle name collisions? (see RFC 5155 7.1 Zone Signing)
        //   - Handle ENTs

        let mut nsec3s = SortedRecords::new();

        // The owner name of a zone cut if we currently are at or below one.
        let mut cut: Option<FamilyName<N>> = None;

        let mut families = self.families();

        // Since the records are ordered, the first family is the apex --
        // we can skip everything before that.
        families.skip_before(apex);

        // Because of the next name thing, we need to keep the last NSEC
        // around.
        let mut prev: Option<(OwnerHash<Octets>, RtypeBitmap<Octets>)> = None;

        // We also need the apex for the last NSEC.
        let apex_owner = families.first_owner().clone();
        let apex_label_count = apex_owner.iter_labels().count();

        // https://www.rfc-editor.org/rfc/rfc9276#section-3.1
        // - SHA-1, no extra iterations, empty salt.
        let alg = Nsec3HashAlg::SHA1;
        let flags = 0;
        let iterations = 2;
        let salt =
            Nsec3Salt::<Octets>::from_octets(Octets::from(&[0x4, 0xD2]))
                .unwrap();

        let mut non_empty_label_count = 0;

        let mut hashed_owner_hashes_to_owner_hashes =
            HashMap::<N, OwnerHash<Octets>>::new();
        let mut owner_hashes_to_names =
            HashMap::<OwnerHash<Octets>, Name<Vec<u8>>>::new();

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
            eprintln!("name={}", name.owner());

            // If this family is the parent side of a zone cut, we keep the
            // family name for later. This also means below that if
            // `cut.is_some()` we are at the parent side of a zone.
            cut = if family.is_zone_cut(apex) {
                Some(name.clone())
            } else {
                None
            };

            // RFC 5155 7.1 step 4.
            let num_labels_from_owner_to_root =
                name.owner().iter_labels().count();
            let num_labels_from_owner_to_apex =
                num_labels_from_owner_to_root - apex_label_count;
            eprintln!("non_empty_label_count={non_empty_label_count}, num_labels_from_owner_to_root={num_labels_from_owner_to_root}, apex_label_count={apex_label_count}, num_labels_from_owner_to_apex={num_labels_from_owner_to_apex}");
            if num_labels_from_owner_to_apex > 1 {
                // Are there any empty nodes between this node and the apex?
                // The zone file records are already sorted so if all of the
                // parent labels had records at them, i.e. they were non-empty
                // then non_empty_label_count would be equal to label_distance.
                // If it is less that means there are ENTs between us and the
                // last non-empty label in our ancestor path to the apex.

                // Walk from the owner name down the tree of labels from the
                // last known non-empty non-terminal label, extending the name
                // each time by one label until we get to the current name.

                // Given a.b.c.mail.example.com where:
                //   - example.com is the apex owner
                //   - mail.example.com was the last non-empty non-terminal
                // This loop will construct the names:
                //   - c.mail.example.com
                //   - b.c.mail.example.com
                // It will NOT construct the last name as that will be dealt
                // with in the next outer loop iteration.
                //   - a.b.c.mail.example.com
                for n in (1..num_labels_from_owner_to_apex - 1).rev() {
                    let rev_label_it = name.owner().iter_labels().skip(n);

                    let mut builder = NameBuilder::<Vec<u8>>::new();
                    for label in
                        rev_label_it.take(num_labels_from_owner_to_apex - n)
                    {
                        builder.append_label(label.as_slice()).unwrap();
                    }
                    let name = builder.append_origin(&apex_owner).unwrap();

                    let mut bitmap = RtypeBitmap::<Octets>::builder();
                    // Assume there’s gonna be an RRSIG.
                    bitmap.add(Rtype::RRSIG).unwrap();
                    for rrset in family.rrsets() {
                        bitmap.add(rrset.rtype()).unwrap()
                    }

                    let hash_octets: Vec<u8> =
                        nsec3_hash(name.clone(), alg, iterations, &salt)
                            .into_octets();
                    let hash_octets: Octets =
                        Octets::octets_from(hash_octets);
                    let next_owner: OwnerHash<Octets> =
                        OwnerHash::from_octets(hash_octets.clone()).unwrap();

                    if create_lookups {
                        owner_hashes_to_names
                            .insert(next_owner.clone(), name);
                    }

                    if let Some((prev_owner, bitmap)) = prev.take() {
                        let base32_label =
                            base32::encode_string_hex(prev_owner.as_slice())
                                .to_ascii_lowercase();
                        let mut builder =
                            NameBuilder::<Octets::Builder>::new();
                        builder
                            .append_label(base32_label.as_bytes())
                            .unwrap();
                        let owner_name =
                            builder.append_origin(&apex_owner).unwrap();
                        let owner_name: N = owner_name.into();

                        eprintln!("Adding ENT NSEC from {owner_name} -> {next_owner}");
                        let nsec3 = Nsec3::new(
                            alg,
                            flags,
                            iterations,
                            salt.clone(),
                            next_owner,
                            bitmap,
                        );
                        let rec =
                            Record::new(owner_name, Class::IN, ttl, nsec3);
                        let _ = nsec3s.insert(rec);
                    }

                    let bitmap = RtypeBitmap::<Octets>::builder();
                    // There are no RR types to record in the NSEC3 bitmap
                    // because this RRset was solely created to hold an NSEC3
                    // for an ENT, it's otherwise empty.

                    let next_owner: OwnerHash<Octets> =
                        OwnerHash::from_octets(hash_octets.clone()).unwrap();
                    prev = Some((next_owner, bitmap.finalize()));
                }
            }

            let hash_octets: Vec<u8> =
                nsec3_hash(name.owner().clone(), alg, iterations, &salt)
                    .into_octets();
            let hash_octets: Octets = Octets::octets_from(hash_octets);
            let next_owner: OwnerHash<Octets> =
                OwnerHash::from_octets(hash_octets.clone()).unwrap();

            if create_lookups {
                owner_hashes_to_names
                    .insert(next_owner.clone(), name.owner().to_name());
            }

            if let Some((prev_owner, bitmap)) = prev.take() {
                let base32_label =
                    base32::encode_string_hex(prev_owner.as_slice())
                        .to_ascii_lowercase();
                let mut builder = NameBuilder::<Octets::Builder>::new();
                builder.append_label(base32_label.as_bytes()).unwrap();
                let owner_name = builder.append_origin(&apex_owner).unwrap();
                let owner_name: N = owner_name.into();

                eprintln!("Adding NSEC from {owner_name} -> {next_owner}");
                let nsec3 = Nsec3::new(
                    alg,
                    flags,
                    iterations,
                    salt.clone(),
                    next_owner,
                    bitmap,
                );
                let rec = Record::new(owner_name, Class::IN, ttl, nsec3);
                let _ = nsec3s.insert(rec);
            }

            // This label is non-empty otherwise it wouldn't be a record in
            // the set. So however many labels deep we are from the apex we
            // know that at this depth the tree has a non-empty label, this
            // is not an empty-non terminal (ENT).
            non_empty_label_count = num_labels_from_owner_to_apex;

            // Finalize the bitmap to be added when this name becomes
            // prev_name and we have a known next_owner to use to construct
            // the NSEC3.
            let mut bitmap = RtypeBitmap::<Octets>::builder();
            // Assume there’s gonna be an RRSIG.
            bitmap.add(Rtype::RRSIG).unwrap();
            for rrset in family.rrsets() {
                bitmap.add(rrset.rtype()).unwrap()
            }

            let next_owner: OwnerHash<Octets> =
                OwnerHash::from_octets(hash_octets.clone()).unwrap();
            prev = Some((next_owner, bitmap.finalize()));
        }

        if let Some((prev_owner, bitmap)) = prev {
            // https://www.rfc-editor.org/rfc/rfc9276#section-3.1
            // - SHA-1, no extra iterations, empty salt.
            let base32_label =
                base32::encode_string_hex(prev_owner.as_slice())
                    .to_ascii_lowercase();
            let mut builder = NameBuilder::<Octets::Builder>::new();
            builder.append_label(base32_label.as_bytes()).unwrap();
            let owner_name = builder.append_origin(&apex_owner).unwrap();
            let owner_name: N = owner_name.into();

            let hash_octets: Vec<u8> =
                nsec3_hash(apex_owner.clone(), alg, iterations, &salt)
                    .into_octets();
            let hash_octets: Octets = Octets::octets_from(hash_octets);
            let next_owner: OwnerHash<Octets> =
                OwnerHash::from_octets(hash_octets).unwrap();

            if create_lookups {
                owner_hashes_to_names
                    .insert(next_owner.clone(), apex_owner.to_name());
            }

            eprintln!("Adding final NSEC from {owner_name} -> {next_owner}");
            let nsec3 = Nsec3::new(
                alg,
                flags,
                iterations,
                salt.clone(),
                next_owner,
                bitmap,
            );
            let rec = Record::new(owner_name, Class::IN, ttl, nsec3);
            let _ = nsec3s.insert(rec);
        }

        for i in 1..=nsec3s.records.len() {
            let next_i = if i == nsec3s.records.len() { 0 } else { i };
            let cur_owner = nsec3s.records[next_i].owner();
            let name: Name<Octets> = cur_owner.try_to_name().unwrap();
            let label = name.iter_labels().next().unwrap();
            let hash_octets: Octets =
                base32::decode_hex(&format!("{label}")).unwrap();
            let owner_hash =
                OwnerHash::<Octets>::from_octets(hash_octets).unwrap();
            let last_rec = &mut nsec3s.records[i - 1];
            let last_nsec3: &mut Nsec3<Octets> = last_rec.data_mut();
            last_nsec3.set_next_owner(owner_hash.clone());

            if create_lookups {
                hashed_owner_hashes_to_owner_hashes
                    .insert(name.into(), owner_hash);
            }
        }

        let lookups = if create_lookups {
            Some((hashed_owner_hashes_to_owner_hashes, owner_hashes_to_names))
        } else {
            None
        };

        (nsec3s.records, lookups)
    }

    pub fn write<'a, W, Octets>(
        &'a self,
        target: &mut W,
        lookups: Option<(
            HashMap<N, OwnerHash<Octets>>,
            HashMap<OwnerHash<Octets>, Name<Vec<u8>>>,
        )>,
    ) -> Result<(), io::Error>
    where
        N: fmt::Display + Eq + std::hash::Hash,
        D: RecordData + fmt::Display + Clone,
        Octets: AsRef<[u8]> + 'a,
        W: io::Write,
        ZoneRecordData<Octets, N>: TryFrom<D>,
    {
        for record in self.records.iter().filter(|r| r.rtype() == Rtype::SOA)
        {
            writeln!(target, "{record}")?;
        }
        if let Some((
            hashed_owner_hashes_to_owner_hashes,
            owner_hashes_to_names,
        )) = lookups
        {
            self.write_with_resolved_names(
                target,
                &hashed_owner_hashes_to_owner_hashes,
                &owner_hashes_to_names,
            )?;
        } else {
            for record in
                self.records.iter().filter(|r| r.rtype() != Rtype::SOA)
            {
                writeln!(target, "{record}")?;
            }
        }
        Ok(())
    }

    fn write_with_resolved_names<'a, W, Octets>(
        &'a self,
        target: &mut W,
        hashed_owner_hashes_to_owner_hashes: &HashMap<N, OwnerHash<Octets>>,
        owner_hashes_to_names: &HashMap<OwnerHash<Octets>, Name<Vec<u8>>>,
    ) -> Result<(), io::Error>
    where
        N: fmt::Display + Eq + std::hash::Hash,
        D: RecordData + fmt::Display + Clone,
        Octets: AsRef<[u8]> + 'a,
        W: io::Write,
        ZoneRecordData<Octets, N>: TryFrom<D>,
    {
        for record in self.records.iter().filter(|r| r.rtype() != Rtype::SOA)
        {
            if record.rtype() == Rtype::NSEC3 {
                let from = hashed_owner_hashes_to_owner_hashes
                    .get(record.owner())
                    .unwrap();
                let from = owner_hashes_to_names.get(from).unwrap();
                let Ok(ZoneRecordData::<Octets, N>::Nsec3(nsec3)) =
                    (*record.data()).clone().try_into()
                else {
                    unreachable!();
                };
                let to =
                    owner_hashes_to_names.get(nsec3.next_owner()).unwrap();
                writeln!(target, "{record} ; {from} -> {to}")?;
            } else {
                writeln!(target, "{record}")?;
            }
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
        while let Some(first) = self.slice.first() {
            if first.class() != apex.class() {
                continue;
            }
            if apex == first || first.owner().ends_with(apex.owner()) {
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
