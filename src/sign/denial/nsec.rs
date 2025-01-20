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
}
