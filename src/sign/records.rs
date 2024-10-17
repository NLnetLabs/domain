//! Actual signing.
use core::convert::From;
use core::fmt::Display;

use std::boxed::Box;
use std::fmt::Debug;
use std::string::String;
use std::vec::Vec;
use std::{fmt, io, slice};

use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, Truncate};
use octseq::{FreezeBuilder, OctetsFrom, OctetsInto};
use tracing::{debug, enabled, Level};

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{Class, Nsec3HashAlg, Rtype, SecAlg};
use crate::base::name::{ToLabelIter, ToName};
use crate::base::rdata::{ComposeRecordData, RecordData};
use crate::base::record::Record;
use crate::base::{Name, NameBuilder, Ttl};
use crate::rdata::dnssec::{
    ProtoRrsig, RtypeBitmap, RtypeBitmapBuilder, Timestamp,
};
use crate::rdata::nsec3::{Nsec3Salt, OwnerHash};
use crate::rdata::{Dnskey, Nsec, Nsec3, Nsec3param, ZoneRecordData};
use crate::utils::base32;
use crate::validate;

use super::ring::{nsec3_hash, Nsec3HashError};
use super::SignRaw;

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

    /// Sign a zone using the given keys.
    ///
    /// A DNSKEY RR will be output for each key.
    ///
    /// Keys with a supported algorithm with the ZONE flag set will be used as
    /// ZSKs.
    ///
    /// Keys with a supported algorithm with the ZONE flag AND the SEP flag
    /// set will be used as KSKs.
    ///
    /// If only one key has a supported algorithm and has the ZONE flag set
    /// AND has the SEP flag set, it will be used as a CSK (i.e. both KSK and
    /// ZSK).
    #[allow(clippy::type_complexity)]
    pub fn sign<Octets, SigningKey>(
        &self,
        apex: &FamilyName<N>,
        expiration: Timestamp,
        inception: Timestamp,
        keys: &[(SigningKey, validate::Key<Octets>)], // private, public key pair
    ) -> Result<Vec<Record<N, ZoneRecordData<Octets, N>>>, ()>
    where
        N: ToName + Clone,
        D: RecordData + ComposeRecordData + From<Dnskey<Octets>>,
        SigningKey: SignRaw,
        Octets: AsRef<[u8]>
            + Clone
            + From<Box<[u8]>>
            + octseq::OctetsFrom<std::vec::Vec<u8>>,
    {
        // Per RFC 8624 section 3.1 "DNSSEC Signing" column guidance.
        let unsupported_algorithms = [
            SecAlg::RSAMD5,
            SecAlg::DSA,
            SecAlg::DSA_NSEC3_SHA1,
            SecAlg::ECC_GOST,
        ];

        let mut ksks: Vec<&(SigningKey, validate::Key<Octets>)> = keys
            .iter()
            .filter(|(k, _)| !unsupported_algorithms.contains(&k.algorithm()))
            .filter(|(_, dk)| {
                dk.is_zone_signing_key() && dk.is_secure_entry_point()
            })
            .collect();

        let mut zsks: Vec<&(SigningKey, validate::Key<Octets>)> = keys
            .iter()
            .filter(|(k, _)| !unsupported_algorithms.contains(&k.algorithm()))
            .filter(|(_, dk)| {
                dk.is_zone_signing_key() && !dk.is_secure_entry_point()
            })
            .collect();

        // CSK?
        if !ksks.is_empty() && zsks.is_empty() {
            zsks = ksks.clone();
        } else if ksks.is_empty() && !zsks.is_empty() {
            ksks = zsks.clone();
        }

        if enabled!(Level::DEBUG) {
            for key in keys {
                debug!(
                    "Key   : {} [supported={}], owner={}, flags={} (SEP={}, ZSK={}))",
                    key.0.algorithm(),
                    !unsupported_algorithms.contains(&key.0.algorithm()),
                    key.1.owner(),
                    key.1.flags(),
                    key.1.is_secure_entry_point(),
                    key.1.is_zone_signing_key(),
                )
            }
            debug!("# KSKs: {}", ksks.len());
            debug!("# ZSKs: {}", zsks.len());
        }

        let mut res: Vec<Record<N, ZoneRecordData<Octets, N>>> = Vec::new();
        let mut buf = Vec::new();
        let mut cut: Option<FamilyName<N>> = None;
        let mut families = self.families();

        // Since the records are ordered, the first family is the apex --
        // we can skip everything before that.
        families.skip_before(apex);

        let mut families = families.peekable();

        let apex_ttl =
            families.peek().unwrap().records().next().unwrap().ttl();

        let mut dnskey_rrs: Vec<Record<N, D>> =
            Vec::with_capacity(keys.len());

        for public_key in keys.iter().map(|(_, public_key)| public_key) {
            let dnskey: Dnskey<Octets> =
                Dnskey::convert(public_key.to_dnskey());
            dnskey_rrs.push(Record::new(
                apex.owner().clone(),
                apex.class(),
                apex_ttl,
                dnskey.clone().into(),
            ));

            res.push(Record::new(
                apex.owner().clone(),
                apex.class(),
                apex_ttl,
                ZoneRecordData::Dnskey(dnskey),
            ));
        }

        let dnskeys_iter = RecordsIter::new(dnskey_rrs.as_slice());
        let families_iter = dnskeys_iter.chain(families);

        for family in families_iter {
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

                let keys = if rrset.rtype() == Rtype::DNSKEY {
                    &ksks
                } else {
                    &zsks
                };

                for (private_key, public_key) in keys {
                    let rrsig = ProtoRrsig::new(
                        rrset.rtype(),
                        private_key.algorithm(),
                        name.owner().rrsig_label_count(),
                        rrset.ttl(),
                        expiration,
                        inception,
                        public_key.key_tag(),
                        apex.owner().clone(),
                    );

                    buf.clear();
                    rrsig.compose_canonical(&mut buf).unwrap();
                    for record in rrset.iter() {
                        record.compose_canonical(&mut buf).unwrap();
                    }
                    let signature = private_key.sign_raw(&buf);
                    let signature = signature.as_ref().to_vec();
                    let Ok(signature) = signature.try_octets_into() else {
                        return Err(());
                    };

                    let rrsig =
                        rrsig.into_rrsig(signature).expect("long signature");
                    res.push(Record::new(
                        name.owner().clone(),
                        name.class(),
                        rrset.ttl(),
                        ZoneRecordData::Rrsig(rrsig),
                    ));
                }
            }
        }

        Ok(res)
    }

    pub fn nsecs<Octets>(
        &self,
        apex: &FamilyName<N>,
        ttl: Ttl,
    ) -> Vec<Record<N, Nsec<Octets, N>>>
    where
        N: ToName + Clone + PartialEq,
        D: RecordData,
        Octets: FromBuilder,
        Octets::Builder: EmptyBuilder + Truncate + AsRef<[u8]> + AsMut<[u8]>,
        <Octets::Builder as OctetsBuilder>::AppendError: Debug,
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
            // Assume there’s gonna be an RRSIG.
            bitmap.add(Rtype::RRSIG).unwrap();
            if family.owner() == &apex_owner {
                // Assume there's gonna be a DNSKEY.
                bitmap.add(Rtype::DNSKEY).unwrap();
            }
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

    /// Generate [RFC5155] NSEC3 and NSEC3PARAM records for this record set.
    ///
    /// This function does NOT enforce use of current best practice settings,
    /// as defined by [RFC 5155], [RFC 9077] and [RFC 9276] which state that:
    ///
    /// - The `ttl` should be the _"lesser of the MINIMUM field of the zone
    ///   SOA RR and the TTL of the zone SOA RR itself"_.
    ///
    /// - The `params` should be set to _"SHA-1, no extra iterations, empty
    ///   salt"_ and zero flags. See `Nsec3param::default()`.
    ///
    /// [RFC 5155]: https://www.rfc-editor.org/rfc/rfc5155.html
    /// [RFC 9077]: https://www.rfc-editor.org/rfc/rfc9077.html
    /// [RFC 9276]: https://www.rfc-editor.org/rfc/rfc9276.html
    pub fn nsec3s<Octets, OctetsMut>(
        &self,
        apex: &FamilyName<N>,
        ttl: Ttl,
        params: Nsec3param<Octets>,
        opt_out: bool,
    ) -> Result<Nsec3Records<N, Octets>, Nsec3HashError>
    where
        N: ToName + Clone + From<Name<Octets>> + Display,
        N: From<Name<<OctetsMut as FreezeBuilder>::Octets>>,
        D: RecordData,
        Octets: FromBuilder + OctetsFrom<Vec<u8>> + Clone + Default,
        Octets::Builder: EmptyBuilder + Truncate + AsRef<[u8]> + AsMut<[u8]>,
        <Octets::Builder as OctetsBuilder>::AppendError: Debug,
        OctetsMut: OctetsBuilder
            + AsRef<[u8]>
            + AsMut<[u8]>
            + EmptyBuilder
            + FreezeBuilder,
    {
        // TODO:
        //   - Handle name collisions? (see RFC 5155 7.1 Zone Signing)
        //   - RFC 5155 section 2 Backwards compatibility:
        //     Reject old algorithms? if not, map 3 to 6 and 5 to 7, or reject
        //     use of 3 and 5?

        // RFC 5155 7.1 step 5: _"Sort the set of NSEC3 RRs into hash order."
        // We store the NSEC3s as we create them in a self-sorting vec.
        let mut nsec3s = SortedRecords::new();

        // The owner name of a zone cut if we currently are at or below one.
        let mut cut: Option<FamilyName<N>> = None;

        let mut families = self.families();

        // Since the records are ordered, the first family is the apex --
        // we can skip everything before that.
        families.skip_before(apex);

        // We also need the apex for the last NSEC.
        let apex_owner = families.first_owner().clone();
        let apex_label_count = apex_owner.iter_labels().count();

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

            // RFC 5155 7.1 step 2:
            //   "If Opt-Out is being used, owner names of unsigned
            //    delegations MAY be excluded."
            let has_ds = family.records().any(|rec| rec.rtype() == Rtype::DS);
            if cut.is_some() && !has_ds && opt_out {
                continue;
            }

            // RFC 5155 7.1 step 4:
            //   "If the difference in number of labels between the apex and
            //    the original owner name is greater than 1, additional NSEC3
            //    RRs need to be added for every empty non-terminal between
            //    the apex and the original owner name."
            let distance_to_root = name.owner().iter_labels().count();
            let distance_to_apex = distance_to_root - apex_label_count;
            if distance_to_apex > 1 {
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
                for n in (1..distance_to_apex - 1).rev() {
                    let rev_label_it = name.owner().iter_labels().skip(n);

                    // Create next longest ENT name.
                    let mut builder = NameBuilder::<OctetsMut>::new();
                    for label in rev_label_it.take(distance_to_apex - n) {
                        builder.append_label(label.as_slice()).unwrap();
                    }
                    let name =
                        builder.append_origin(&apex_owner).unwrap().into();

                    // Create the type bitmap, empty for an ENT NSEC3.
                    let bitmap = RtypeBitmap::<Octets>::builder();

                    let rec = Self::mk_nsec3(
                        &name,
                        params.hash_algorithm(),
                        params.flags(),
                        params.iterations(),
                        params.salt(),
                        &apex_owner,
                        bitmap,
                        ttl,
                    )?;

                    // Store the record by order of its owner name.
                    let _ = nsec3s.insert(rec);
                }
            }

            // Create the type bitmap, assume there will be an RRSIG and an
            // NSEC3PARAM.
            let mut bitmap = RtypeBitmap::<Octets>::builder();

            // Authoritative RRsets will be signed.
            if cut.is_none() || has_ds {
                bitmap.add(Rtype::RRSIG).unwrap();
            }

            // RFC 5155 7.1 step 3:
            //   "For each RRSet at the original owner name, set the
            //    corresponding bit in the Type Bit Maps field."
            for rrset in family.rrsets() {
                bitmap.add(rrset.rtype()).unwrap();
            }

            if distance_to_apex == 0 {
                bitmap.add(Rtype::NSEC3PARAM).unwrap();
                bitmap.add(Rtype::DNSKEY).unwrap();
            }

            // RFC 5155 7.1 step 2:
            //   "If Opt-Out is being used, set the Opt-Out bit to one."
            let mut nsec3_flags = params.flags();
            if opt_out {
                // Set the Opt-Out flag.
                nsec3_flags |= 0b0000_0001;
            }

            let rec = Self::mk_nsec3(
                name.owner(),
                params.hash_algorithm(),
                nsec3_flags,
                params.iterations(),
                params.salt(),
                &apex_owner,
                bitmap,
                ttl,
            )?;

            let _ = nsec3s.insert(rec);
        }

        // RFC 5155 7.1 step 7:
        //   "In each NSEC3 RR, insert the next hashed owner name by using the
        //    value of the next NSEC3 RR in hash order.  The next hashed owner
        //    name of the last NSEC3 RR in the zone contains the value of the
        //    hashed owner name of the first NSEC3 RR in the hash order."
        for i in 1..=nsec3s.records.len() {
            let next_i = if i == nsec3s.records.len() { 0 } else { i };
            let cur_owner = nsec3s.records[next_i].owner();
            let name: Name<Octets> = cur_owner.try_to_name().unwrap();
            let label = name.iter_labels().next().unwrap();
            let owner_hash = if let Ok(hash_octets) =
                base32::decode_hex(&format!("{label}"))
            {
                OwnerHash::<Octets>::from_octets(hash_octets).unwrap()
            } else {
                OwnerHash::<Octets>::from_octets(name.as_octets().clone())
                    .unwrap()
            };
            let last_rec = &mut nsec3s.records[i - 1];
            let last_nsec3: &mut Nsec3<Octets> = last_rec.data_mut();
            last_nsec3.set_next_owner(owner_hash.clone());
        }

        // RFC 5155 7.1 step 8:
        //   "Finally, add an NSEC3PARAM RR with the same Hash Algorithm,
        //    Iterations, and Salt fields to the zone apex."
        let nsec3param_rec = Record::new(
            apex.owner().try_to_name::<Octets>().unwrap().into(),
            Class::IN,
            ttl,
            params,
        );

        // RFC 5155 7.1 after step 8:
        //   "If a hash collision is detected, then a new salt has to be
        //    chosen, and the signing process restarted."
        //
        // TODO

        Ok(Nsec3Records::new(nsec3s.records, nsec3param_rec))
    }

    pub fn write<W>(&self, target: &mut W) -> Result<(), io::Error>
    where
        N: fmt::Display + Eq,
        D: RecordData + fmt::Display + Clone,
        W: io::Write,
    {
        for record in self.records.iter().filter(|r| r.rtype() == Rtype::SOA)
        {
            writeln!(target, "{record}")?;
        }

        for record in self.records.iter().filter(|r| r.rtype() != Rtype::SOA)
        {
            writeln!(target, "{record}")?;
        }

        Ok(())
    }
}

/// Helper functions used to create NSEC3 records per RFC 5155.
impl<N, D> SortedRecords<N, D> {
    #[allow(clippy::too_many_arguments)]
    fn mk_nsec3<Octets>(
        name: &N,
        alg: Nsec3HashAlg,
        flags: u8,
        iterations: u16,
        salt: &Nsec3Salt<Octets>,
        apex_owner: &N,
        bitmap: RtypeBitmapBuilder<<Octets as FromBuilder>::Builder>,
        ttl: Ttl,
    ) -> Result<Record<N, Nsec3<Octets>>, Nsec3HashError>
    where
        N: ToName + From<Name<Octets>>,
        Octets: FromBuilder + Clone + Default,
        <Octets as FromBuilder>::Builder:
            EmptyBuilder + AsRef<[u8]> + AsMut<[u8]> + Truncate,
    {
        // Create the base32hex ENT NSEC owner name.
        let base32hex_label =
            Self::mk_base32hex_label_for_name(name, alg, iterations, salt)?;

        // Prepend it to the zone name to create the NSEC3 owner
        // name.
        let owner_name = Self::append_origin(base32hex_label, apex_owner);

        // RFC 5155 7.1. step 2:
        //   "The Next Hashed Owner Name field is left blank for the moment."
        // Create a placeholder next owner, we'll fix it later.
        let placeholder_next_owner =
            OwnerHash::<Octets>::from_octets(Octets::default()).unwrap();

        // Create an NSEC3 record.
        let nsec3 = Nsec3::new(
            alg,
            flags,
            iterations,
            salt.clone(),
            placeholder_next_owner,
            bitmap.finalize(),
        );

        Ok(Record::new(owner_name, Class::IN, ttl, nsec3))
    }

    fn append_origin<Octets>(base32hex_label: String, apex_owner: &N) -> N
    where
        N: ToName + From<Name<Octets>>,
        Octets: FromBuilder,
        <Octets as FromBuilder>::Builder:
            EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    {
        let mut builder = NameBuilder::<Octets::Builder>::new();
        builder.append_label(base32hex_label.as_bytes()).unwrap();
        let owner_name = builder.append_origin(apex_owner).unwrap();
        let owner_name: N = owner_name.into();
        owner_name
    }

    fn mk_base32hex_label_for_name<Octets>(
        name: &N,
        alg: Nsec3HashAlg,
        iterations: u16,
        salt: &Nsec3Salt<Octets>,
    ) -> Result<String, Nsec3HashError>
    where
        N: ToName,
        Octets: AsRef<[u8]>,
    {
        let hash_octets: Vec<u8> =
            nsec3_hash(name, alg, iterations, salt)?.into_octets();
        Ok(base32::encode_string_hex(&hash_octets).to_ascii_lowercase())
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

//------------ Nsec3Records ---------------------------------------------------

/// The set of records created by [`SortedRecords::nsec3s()`].
pub struct Nsec3Records<N, Octets> {
    /// The NSEC3 records.
    pub nsec3_recs: Vec<Record<N, Nsec3<Octets>>>,

    /// The NSEC3PARAM record.
    pub nsec3param_rec: Record<N, Nsec3param<Octets>>,
}

impl<N, Octets> Nsec3Records<N, Octets> {
    pub fn new(
        nsec3_recs: Vec<Record<N, Nsec3<Octets>>>,
        nsec3param_rec: Record<N, Nsec3param<Octets>>,
    ) -> Self {
        Self {
            nsec3_recs,
            nsec3param_rec,
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

    // pub fn dnskey<K: SigningKey, Octets: From<K::Octets>>(
    //     &self,
    //     ttl: Ttl,
    //     key: K,
    // ) -> Result<Record<N, Dnskey<Octets>>, K::Error>
    // where
    //     N: Clone,
    // {
    //     key.dnskey()
    //         .map(|dnskey| self.clone().into_record(ttl, dnskey.convert()))
    // }

    // pub fn ds<K: SigningKey>(
    //     &self,
    //     ttl: Ttl,
    //     key: K,
    // ) -> Result<Record<N, Ds<K::Octets>>, K::Error>
    // where
    //     N: ToName + Clone,
    // {
    //     key.ds(&self.owner)
    //         .map(|ds| self.clone().into_record(ttl, ds))
    // }
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
