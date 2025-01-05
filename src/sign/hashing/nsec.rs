use core::fmt::Debug;

use std::vec::Vec;

use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, Truncate};

use crate::base::iana::Rtype;
use crate::base::name::ToName;
use crate::base::record::Record;
use crate::base::Ttl;
use crate::rdata::dnssec::RtypeBitmap;
use crate::rdata::{Nsec, ZoneRecordData};
use crate::sign::records::{FamilyName, RecordsIter};

// TODO: Add (mutable?) iterator based variant.
pub fn generate_nsecs<N, Octs>(
    apex: &FamilyName<N>,
    ttl: Ttl,
    mut families: RecordsIter<'_, N, ZoneRecordData<Octs, N>>,
    assume_dnskeys_will_be_added: bool,
) -> Vec<Record<N, Nsec<Octs, N>>>
where
    N: ToName + Clone + PartialEq,
    Octs: FromBuilder,
    Octs::Builder: EmptyBuilder + Truncate + AsRef<[u8]> + AsMut<[u8]>,
    <Octs::Builder as OctetsBuilder>::AppendError: Debug,
{
    let mut res = Vec::new();

    // The owner name of a zone cut if we currently are at or below one.
    let mut cut: Option<FamilyName<N>> = None;

    // Since the records are ordered, the first family is the apex -- we can
    // skip everything before that.
    families.skip_before(apex);

    // Because of the next name thing, we need to keep the last NSEC around.
    let mut prev: Option<(FamilyName<N>, RtypeBitmap<Octs>)> = None;

    // We also need the apex for the last NSEC.
    let apex_owner = families.first_owner().clone();

    for family in families {
        // If the owner is out of zone, we have moved out of our zone and are
        // done.
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

        // If this family is the parent side of a zone cut, we keep the family
        // name for later. This also means below that if `cut.is_some()` we
        // are at the parent side of a zone.
        cut = if family.is_zone_cut(apex) {
            Some(name.clone())
        } else {
            None
        };

        if let Some((prev_name, bitmap)) = prev.take() {
            res.push(
                prev_name.into_record(
                    ttl,
                    Nsec::new(name.owner().clone(), bitmap),
                ),
            );
        }

        let mut bitmap = RtypeBitmap::<Octs>::builder();
        // RFC 4035 section 2.3:
        //   "The type bitmap of every NSEC resource record in a signed zone
        //    MUST indicate the presence of both the NSEC record itself and
        //    its corresponding RRSIG record."
        bitmap.add(Rtype::RRSIG).unwrap();
        if assume_dnskeys_will_be_added && family.owner() == &apex_owner {
            // Assume there's gonna be a DNSKEY.
            bitmap.add(Rtype::DNSKEY).unwrap();
        }
        bitmap.add(Rtype::NSEC).unwrap();
        for rrset in family.rrsets() {
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
                // TODO: Should this check be moved into RtypeBitmapBuilder
                // itself?
                if !rrset.rtype().is_pseudo() {
                    bitmap.add(rrset.rtype()).unwrap()
                }
            }
        }

        prev = Some((name, bitmap.finalize()));
    }
    if let Some((prev_name, bitmap)) = prev {
        res.push(prev_name.into_record(ttl, Nsec::new(apex_owner, bitmap)));
    }
    res
}
