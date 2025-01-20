use core::cmp::min;
use core::fmt::Debug;

use std::vec::Vec;

use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, Truncate};

use crate::base::iana::Rtype;
use crate::base::name::ToName;
use crate::base::record::Record;
use crate::rdata::dnssec::RtypeBitmap;
use crate::rdata::{Nsec, ZoneRecordData};
use crate::sign::error::SigningError;
use crate::sign::records::RecordsIter;

/// Generate DNSSEC NSEC records for an unsigned zone.
///
/// This function returns a collection of generated NSEC records for the given
/// zone, per [RFC 4034 section 4] _"The NSEC Resource Record"_, [RFC 4035
/// section 2.3] _"Including NSEC RRs in a Zone"_ and [RFC 9077] _"NSEC and
/// NSEC3: TTLs and Aggressive Use"_.
///
/// Assumes that the given records are in [`CanonicalOrd`] order and start
/// with a complete zone, i.e. including an apex SOA record. If the apex SOA
/// is not found or multiple SOA records are found at the apex error
/// SigningError::SoaRecordCouldNotBeDetermined will be returned.
///
/// Processing of records will stop at the end of the collection or at the
/// first record that lies outside the zone.
///
/// If the `assume_dnskeys_will_be_added` parameter is true the generated NSEC
/// at the apex RRset will include the `DNSKEY` record type in the NSEC type
/// bitmap.
///
/// [RFC 4034 section 4]: https://www.rfc-editor.org/rfc/rfc4034#section-4
/// [RFC 4035 section 2.3]: https://www.rfc-editor.org/rfc/rfc4035#section-2.3
/// [RFC 9077]: https://www.rfc-editor.org/rfc/rfc9077
// TODO: Add (mutable?) iterator based variant.
pub fn generate_nsecs<N, Octs>(
    records: RecordsIter<'_, N, ZoneRecordData<Octs, N>>,
    assume_dnskeys_will_be_added: bool,
) -> Result<Vec<Record<N, Nsec<Octs, N>>>, SigningError>
where
    N: ToName + Clone + PartialEq,
    Octs: FromBuilder,
    Octs::Builder: EmptyBuilder + Truncate + AsRef<[u8]> + AsMut<[u8]>,
    <Octs::Builder as OctetsBuilder>::AppendError: Debug,
{
    let mut res = Vec::new();

    // The owner name of a zone cut if we currently are at or below one.
    let mut cut: Option<N> = None;

    // Because of the next name thing, we need to keep the last NSEC around.
    let mut prev: Option<(N, RtypeBitmap<Octs>)> = None;

    // We also need the apex for the last NSEC.
    let first_rr = records.first();
    let apex_owner = first_rr.owner().clone();
    let zone_class = first_rr.class();
    let mut ttl = None;

    for owner_rrs in records {
        // If the owner is out of zone, we have moved out of our zone and are
        // done.
        if !owner_rrs.is_in_zone(&apex_owner) {
            break;
        }

        // If the owner is below a zone cut, we must ignore it.
        if let Some(ref cut) = cut {
            if owner_rrs.owner().ends_with(cut) {
                continue;
            }
        }

        // A copy of the owner name. We’ll need it later.
        let name = owner_rrs.owner().clone();

        // If this owner is the parent side of a zone cut, we keep the owner
        // name for later. This also means below that if `cut.is_some()` we
        // are at the parent side of a zone.
        cut = if owner_rrs.is_zone_cut(&apex_owner) {
            Some(name.clone())
        } else {
            None
        };

        if let Some((prev_name, bitmap)) = prev.take() {
            // SAFETY: ttl will be set below before prev is set to Some.
            res.push(Record::new(
                prev_name.clone(),
                zone_class,
                ttl.unwrap(),
                Nsec::new(name.clone(), bitmap),
            ));
        }

        let mut bitmap = RtypeBitmap::<Octs>::builder();

        // RFC 4035 section 2.3:
        //   "The type bitmap of every NSEC resource record in a signed zone
        //    MUST indicate the presence of both the NSEC record itself and
        //    its corresponding RRSIG record."
        bitmap.add(Rtype::RRSIG).unwrap();

        if assume_dnskeys_will_be_added && owner_rrs.owner() == &apex_owner {
            // Assume there's gonna be a DNSKEY.
            bitmap.add(Rtype::DNSKEY).unwrap();
        }

        bitmap.add(Rtype::NSEC).unwrap();

        for rrset in owner_rrs.rrsets() {
            // RFC 4034 section 4.1.2: (and also RFC 4035 section 2.3)
            //   "The bitmap for the NSEC RR at a delegation point requires
            //    special attention.  Bits corresponding to the delegation NS
            //    RRset and any RRsets for which the parent zone has
            //    authoritative data MUST be set; bits corresponding to any
            //    non-NS RRset for which the parent is not authoritative MUST
            //    be clear."
            if cut.is_none() || matches!(rrset.rtype(), Rtype::NS | Rtype::DS)
            {
                // RFC 4034 section 4.1.2:
                //   "Bits representing pseudo-types MUST be clear, as they do
                //    not appear in zone data."
                //
                // We don't need to do a check here as the ZoneRecordData type
                // that we require already excludes "pseudo" record types,
                // those are only included as member variants of the
                // AllRecordData type.
                bitmap.add(rrset.rtype()).unwrap()
            }

            if rrset.rtype() == Rtype::SOA {
                if rrset.len() > 1 {
                    return Err(SigningError::SoaRecordCouldNotBeDetermined);
                }

                let soa_rr = rrset.first();

                // Check that the RDATA for the SOA record can be parsed.
                let ZoneRecordData::Soa(ref soa_data) = soa_rr.data() else {
                    return Err(SigningError::SoaRecordCouldNotBeDetermined);
                };

                // RFC 9077 updated RFC 4034 (NSEC) and RFC 5155 (NSEC3) to
                // say that the "TTL of the NSEC(3) RR that is returned MUST
                // be the lesser of the MINIMUM field of the SOA record and
                // the TTL of the SOA itself".
                ttl = Some(min(soa_data.minimum(), soa_rr.ttl()));
            }
        }

        if ttl.is_none() {
            return Err(SigningError::SoaRecordCouldNotBeDetermined);
        }

        prev = Some((name, bitmap.finalize()));
    }

    if let Some((prev_name, bitmap)) = prev {
        res.push(Record::new(
            prev_name.clone(),
            zone_class,
            ttl.unwrap(),
            Nsec::new(apex_owner.clone(), bitmap),
        ));
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use std::io::Read;

    use bytes::Bytes;
    use pretty_assertions::assert_eq;

    use crate::base::Serial;
    use crate::base::{iana::Class, name::FlattenInto, Name, Ttl};
    use crate::rdata::{Ns, Soa, A};
    use crate::sign::records::SortedRecords;
    use crate::zonefile::inplace::{Entry, Zonefile};
    use crate::zonetree::{types::StoredRecordData, StoredName};

    use octseq::FreezeBuilder;

    use super::*;

    #[test]
    fn soa_is_required() {
        let mut records = SortedRecords::default();
        records.insert(mk_a("some_a.a.")).unwrap();
        let res = generate_nsecs(records.owner_rrs(), false);
        assert!(matches!(
            res,
            Err(SigningError::SoaRecordCouldNotBeDetermined)
        ));
    }

    #[test]
    fn multiple_soa_rrs_in_the_same_rrset_are_not_permitted() {
        let mut records = SortedRecords::default();
        records.insert(mk_soa("a.", "b.", "c.")).unwrap();
        records.insert(mk_soa("a.", "d.", "e.")).unwrap();
        let res = generate_nsecs(records.owner_rrs(), false);
        assert!(matches!(
            res,
            Err(SigningError::SoaRecordCouldNotBeDetermined)
        ));
    }

    #[test]
    fn records_outside_zone_are_ignored() {
        let mut records = SortedRecords::default();

        records.insert(mk_soa("b.", "d.", "e.")).unwrap();
        records.insert(mk_a("some_a.b.")).unwrap();
        records.insert(mk_soa("a.", "b.", "c.")).unwrap();
        records.insert(mk_a("some_a.a.")).unwrap();

        // First generate NSECs for the total record collection. As the
        // collection is sorted in canonical order the a zone preceeds the b
        // zone and NSECs should only be generated for the first zone in the
        // collection.
        let a_and_b_records = records.owner_rrs();
        let nsecs = generate_nsecs(a_and_b_records, false).unwrap();

        assert_eq!(
            nsecs,
            [
                mk_nsec("a.", Class::IN, 0, "some_a.a.", "SOA RRSIG NSEC"),
                mk_nsec("some_a.a.", Class::IN, 0, "a.", "A RRSIG NSEC"),
            ]
        );

        // Now skip the a zone in the collection and generate NSECs for the
        // remaining records which should only generate NSECs for the b zone.
        let mut b_records_only = records.owner_rrs();
        b_records_only.skip_before(&mk_name("b."));
        let nsecs = generate_nsecs(b_records_only, false).unwrap();

        assert_eq!(
            nsecs,
            [
                mk_nsec("b.", Class::IN, 0, "some_a.b.", "SOA RRSIG NSEC"),
                mk_nsec("some_a.b.", Class::IN, 0, "b.", "A RRSIG NSEC"),
            ]
        );
    }

    #[test]
    fn occluded_records_are_ignored() {
        let mut records = SortedRecords::default();

        records.insert(mk_soa("a.", "b.", "c.")).unwrap();
        records
            .insert(mk_ns("some_ns.a.", "some_a.other.b."))
            .unwrap();
        records.insert(mk_a("some_a.some_ns.a.")).unwrap();

        let nsecs = generate_nsecs(records.owner_rrs(), false).unwrap();

        // Implicit negative test.
        assert_eq!(
            nsecs,
            [
                mk_nsec(
                    "a.",
                    Class::IN,
                    12345,
                    "some_ns.a.",
                    "SOA RRSIG NSEC"
                ),
                mk_nsec(
                    "some_ns.a.",
                    Class::IN,
                    12345,
                    "a.",
                    "NS RRSIG NSEC"
                ),
            ]
        );

        // Explicit negative test.
        assert!(!contains_owner(&nsecs, "some_a.some_ns.a.example."));
    }

    #[test]
    fn expect_dnskeys_at_the_apex() {
        let mut records = SortedRecords::default();

        records.insert(mk_soa("a.", "b.", "c.")).unwrap();
        records.insert(mk_a("some_a.a.")).unwrap();

        let nsecs = generate_nsecs(records.owner_rrs(), true).unwrap();

        assert_eq!(
            nsecs,
            [
                mk_nsec(
                    "a.",
                    Class::IN,
                    0,
                    "some_a.a.",
                    "SOA DNSKEY RRSIG NSEC"
                ),
                mk_nsec("some_a.a.", Class::IN, 0, "a.", "A RRSIG NSEC"),
            ]
        );
    }

    #[test]
    fn rfc_4034_and_9077_compliant() {
        // See https://datatracker.ietf.org/doc/html/rfc4035#appendix-A
        let zonefile = include_bytes!(
            "../../../test-data/zonefiles/rfc4035-appendix-A.zone"
        );

        let records = bytes_to_records(&zonefile[..]);
        let nsecs = generate_nsecs(records.owner_rrs(), false).unwrap();

        assert_eq!(nsecs.len(), 10);

        assert_eq!(
            nsecs,
            [
                mk_nsec(
                    "example.",
                    Class::IN,
                    12345,
                    "a.example",
                    "NS SOA MX RRSIG NSEC DNSKEY"
                ),
                mk_nsec(
                    "a.example.",
                    Class::IN,
                    12345,
                    "ai.example",
                    "NS DS RRSIG NSEC"
                ),
                mk_nsec(
                    "ai.example.",
                    Class::IN,
                    12345,
                    "b.example",
                    "A HINFO AAAA RRSIG NSEC"
                ),
                mk_nsec(
                    "b.example.",
                    Class::IN,
                    12345,
                    "ns1.example",
                    "NS RRSIG NSEC"
                ),
                mk_nsec(
                    "ns1.example.",
                    Class::IN,
                    12345,
                    "ns2.example",
                    "A RRSIG NSEC"
                ),
                // The next record also validates that we comply with
                // https://datatracker.ietf.org/doc/html/rfc4034#section-6.2
                // 4.1.3. "Inclusion of Wildcard Names in NSEC RDATA" when
                // it says:
                //   "If a wildcard owner name appears in a zone, the wildcard
                //   label ("*") is treated as a literal symbol and is treated
                //   the same as any other owner name for the purposes of
                //   generating NSEC RRs. Wildcard owner names appear in the
                //   Next Domain Name field without any wildcard expansion.
                //   [RFC4035] describes the impact of wildcards on
                //   authenticated denial of existence."
                mk_nsec(
                    "ns2.example.",
                    Class::IN,
                    12345,
                    "*.w.example",
                    "A RRSIG NSEC"
                ),
                mk_nsec(
                    "*.w.example.",
                    Class::IN,
                    12345,
                    "x.w.example",
                    "MX RRSIG NSEC"
                ),
                mk_nsec(
                    "x.w.example.",
                    Class::IN,
                    12345,
                    "x.y.w.example",
                    "MX RRSIG NSEC"
                ),
                mk_nsec(
                    "x.y.w.example.",
                    Class::IN,
                    12345,
                    "xx.example",
                    "MX RRSIG NSEC"
                ),
                mk_nsec(
                    "xx.example.",
                    Class::IN,
                    12345,
                    "example",
                    "A HINFO AAAA RRSIG NSEC"
                )
            ],
        );

        // TTLs are not compared by the eq check above so check them
        // explicitly now.
        //
        // RFC 9077 updated RFC 4034 (NSEC) and RFC 5155 (NSEC3) to say that
        // the "TTL of the NSEC(3) RR that is returned MUST be the lesser of
        // the MINIMUM field of the SOA record and the TTL of the SOA itself".
        //
        // So in our case that is min(1800, 3600) = 1800.
        for nsec in &nsecs {
            assert_eq!(nsec.ttl(), Ttl::from_secs(1800));
        }

        // https://rfc-annotations.research.icann.org/rfc4035.html#section-2.3
        // 2.3.  Including NSEC RRs in a Zone
        //   ...
        //   "The type bitmap of every NSEC resource record in a signed zone
        //   MUST indicate the presence of both the NSEC record itself and its
        //   corresponding RRSIG record."
        for nsec in &nsecs {
            assert!(nsec.data().types().contains(Rtype::NSEC));
            assert!(nsec.data().types().contains(Rtype::RRSIG));
        }

        // https://rfc-annotations.research.icann.org/rfc4034.html#section-4.1.1
        // 4.1.2.  The Type Bit Maps Field
        //   "Bits representing pseudo-types MUST be clear, as they do not
        //    appear in zone data."
        //
        // There is nothing to test for this as it is excluded at the Rust
        // type system level by the generate_nsecs() function taking
        // ZoneRecordData (which excludes pseudo record types) as input rather
        // than AllRecordData (which includes pseudo record types).

        // https://rfc-annotations.research.icann.org/rfc4034.html#section-4.1.1
        // 4.1.2.  The Type Bit Maps Field
        //   ...
        //   "A zone MUST NOT include an NSEC RR for any domain name that only
        //    holds glue records."
        //
        // The "rfc4035-appendix-A.zone" file that we load contains glue A
        // records for ns1.example, ns1.a.example, ns1.b.example, ns2.example
        // and ns2.a.example all with no other record types at that name. We
        // can verify that an NSEC RR was NOT created for those that are not
        // within the example zone as we are not authoritative for thos.
        assert!(contains_owner(&nsecs, "ns1.example."));
        assert!(!contains_owner(&nsecs, "ns1.a.example."));
        assert!(!contains_owner(&nsecs, "ns1.b.example."));
        assert!(contains_owner(&nsecs, "ns2.example."));
        assert!(!contains_owner(&nsecs, "ns2.a.example."));

        // https://rfc-annotations.research.icann.org/rfc4035.html#section-2.3
        // 2.3.  Including NSEC RRs in a Zone
        //   ...
        //  "The bitmap for the NSEC RR at a delegation point requires special
        //  attention.  Bits corresponding to the delegation NS RRset and any
        //  RRsets for which the parent zone has authoritative data MUST be
        //  set; bits corresponding to any non-NS RRset for which the parent
        //  is not authoritative MUST be clear."
        //
        // The "rfc4035-appendix-A.zone" file that we load has been modified
        // compared to the original to include a glue A record at b.example.
        // We can verify that an NSEC RR was NOT created for that name.
        let name = mk_name::<Bytes>("b.example.");
        let nsec = nsecs.iter().find(|rr| rr.owner() == &name).unwrap();
        assert!(nsec.data().types().contains(Rtype::NSEC));
        assert!(nsec.data().types().contains(Rtype::RRSIG));
        assert!(!nsec.data().types().contains(Rtype::A));
    }

    //------------ Helper fns ------------------------------------------------

    fn bytes_to_records(
        mut zonefile: impl Read,
    ) -> SortedRecords<StoredName, StoredRecordData> {
        let reader = Zonefile::load(&mut zonefile).unwrap();
        let mut records = SortedRecords::default();
        for entry in reader {
            let entry = entry.unwrap();
            if let Entry::Record(record) = entry {
                records.insert(record.flatten_into()).unwrap()
            }
        }
        records
    }

    fn mk_nsec(
        owner: &str,
        class: Class,
        ttl_secs: u32,
        next_name: &str,
        types: &str,
    ) -> Record<StoredName, Nsec<Bytes, StoredName>> {
        let owner = Name::from_str(owner).unwrap();
        let ttl = Ttl::from_secs(ttl_secs);
        let next_name = Name::from_str(next_name).unwrap();
        let mut builder = RtypeBitmap::<Bytes>::builder();
        for rtype in types.split_whitespace() {
            builder.add(Rtype::from_str(rtype).unwrap()).unwrap();
        }
        let types = builder.finalize();
        Record::new(owner, class, ttl, Nsec::new(next_name, types))
    }

    fn mk_name<Octs>(name: &str) -> Name<Octs>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder
            + FreezeBuilder<Octets = Octs>
            + AsRef<[u8]>
            + AsMut<[u8]>,
    {
        Name::<Octs>::from_str(name).unwrap()
    }

    fn mk_soa(
        name: &str,
        mname: &str,
        rname: &str,
    ) -> Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>> {
        let zone_apex_name = mk_name::<Bytes>(name);
        let soa = ZoneRecordData::<Bytes, _>::Soa(Soa::new(
            mk_name::<Bytes>(mname),
            mk_name::<Bytes>(rname),
            Serial::now(),
            Ttl::ZERO,
            Ttl::ZERO,
            Ttl::ZERO,
            Ttl::ZERO,
        ));
        Record::new(zone_apex_name, Class::IN, Ttl::ZERO, soa)
    }

    fn mk_a(
        name: &str,
    ) -> Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>> {
        let a_name = mk_name::<Bytes>(name);
        let a =
            ZoneRecordData::<Bytes, _>::A(A::from_str("1.2.3.4").unwrap());
        Record::new(a_name, Class::IN, Ttl::ZERO, a)
    }

    fn mk_ns(
        name: &str,
        nsdname: &str,
    ) -> Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>> {
        let name = mk_name::<Bytes>(name);
        let nsdname = mk_name::<Bytes>(nsdname);
        let ns = ZoneRecordData::<Bytes, _>::Ns(Ns::new(nsdname));
        Record::new(name, Class::IN, Ttl::ZERO, ns)
    }

    fn contains_owner(
        nsecs: &[Record<Name<Bytes>, Nsec<Bytes, Name<Bytes>>>],
        name: &str,
    ) -> bool {
        let name = mk_name::<Bytes>(name);
        nsecs.iter().any(|rr| rr.owner() == &name)
    }
}
