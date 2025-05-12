use core::cmp::min;
use core::convert::From;
use core::fmt::{Debug, Display};
use core::marker::{PhantomData, Send};
use core::ops::Deref;

use std::hash::Hash;
use std::string::String;
use std::vec::Vec;

use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, Truncate};
use octseq::OctetsFrom;
use tracing::{debug, trace};

use crate::base::iana::{Class, Nsec3HashAlgorithm, Rtype};
use crate::base::name::{ToLabelIter, ToName};
use crate::base::{CanonicalOrd, Name, NameBuilder, Record, Ttl};
use crate::dnssec::common::{nsec3_hash, Nsec3HashError};
use crate::dnssec::sign::error::SigningError;
use crate::dnssec::sign::records::{DefaultSorter, RecordsIter, Sorter};
use crate::rdata::dnssec::{RtypeBitmap, RtypeBitmapBuilder};
use crate::rdata::nsec3::{Nsec3Salt, OwnerHash};
use crate::rdata::{Nsec3, Nsec3param, ZoneRecordData};
use crate::utils::base32;

//----------- GenerateNsec3Config --------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateNsec3Config<Octs, Sort>
where
    Octs: AsRef<[u8]> + From<&'static [u8]>,
{
    /// Whether to assume that the final zone will one or more DNSKEY RRs at
    /// the apex.
    ///
    /// If true, an NSEC3 RR created for the zone apex according to these
    /// config settings should have the DNSKEY bit _*SET*_ in the NSEC3 type
    /// bitmap.
    ///
    /// If false, an NSEC3 RR created for the zone apex according to these
    /// config settings should have the DNSKEY bit _*UNSET*_ in the NSEC3 type
    /// bitmap.
    pub assume_dnskeys_will_be_added: bool,

    /// NSEC3 and NSEC3PARAM settings.
    ///
    /// Hash algorithm, flags, iterations and salt.
    pub params: Nsec3param<Octs>,

    /// Whether to exclude owner names of unsigned delegations when Opt-Out
    /// is being used.
    ///
    /// Some zone signing tools (e.g. ldns-signzone) set the NSEC3 Opt-Out
    /// flag but still include insecure delegations in the NSEC3 chain.
    ///
    /// This is possible because RFC 5155 section 7.1 says:
    ///
    /// https://www.rfc-editor.org/rfc/rfc5155.html#section-7.1
    /// 7.1.  Zone Signing
    /// ...
    ///   "If Opt-Out is being used, owner names of unsigned delegations MAY
    ///    be excluded."
    ///
    /// I.e. owner names of unsigned delegations MAY also NOT be excluded.
    pub opt_out_exclude_owner_names_of_unsigned_delegations: bool,

    /// Which TTL value should be used for the NSEC3PARAM RR.
    pub nsec3param_ttl_mode: Nsec3ParamTtlMode,

    _phantom: PhantomData<Sort>,
}

impl<Octs, Sort> GenerateNsec3Config<Octs, Sort>
where
    Octs: AsRef<[u8]> + From<&'static [u8]>,
{
    pub fn new(params: Nsec3param<Octs>) -> Self {
        Self {
            assume_dnskeys_will_be_added: true,
            params,
            nsec3param_ttl_mode: Default::default(),
            opt_out_exclude_owner_names_of_unsigned_delegations: true,
            _phantom: Default::default(),
        }
    }

    pub fn with_ttl_mode(mut self, ttl_mode: Nsec3ParamTtlMode) -> Self {
        self.nsec3param_ttl_mode = ttl_mode;
        self
    }

    pub fn with_opt_out(mut self) -> Self {
        self.params.set_opt_out_flag();
        self
    }

    pub fn without_opt_out_excluding_owner_names_of_unsigned_delegations(
        mut self,
    ) -> Self {
        self.opt_out_exclude_owner_names_of_unsigned_delegations = false;
        self
    }

    pub fn without_assuming_dnskeys_will_be_added(mut self) -> Self {
        self.assume_dnskeys_will_be_added = false;
        self
    }
}

impl<Octs> Default for GenerateNsec3Config<Octs, DefaultSorter>
where
    Octs: AsRef<[u8]> + From<&'static [u8]> + Clone + FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
{
    fn default() -> Self {
        let params = Nsec3param::default();
        Self {
            assume_dnskeys_will_be_added: true,
            params,
            nsec3param_ttl_mode: Default::default(),
            opt_out_exclude_owner_names_of_unsigned_delegations: true,
            _phantom: Default::default(),
        }
    }
}

/// Generate RFC5155 NSEC3 and NSEC3PARAM records for this record set.
///
/// This function enforces [RFC 9077] when it says that the "TTL of the
/// NSEC(3) RR that is returned MUST be the lesser of the MINIMUM field of the
/// SOA record and the TTL of the SOA itself".
///
/// This function does NOT enforce the use of [RFC 9276] best practices which
/// state that:
///
/// - The `params` should be set to _"SHA-1, no extra iterations, empty salt"_
///   and zero flags. See [`Nsec3param::default()`].
///
/// # Panics
///
/// This function may panic if the input records are not sorted in DNSSEC
/// canonical order (see [`CanonicalOrd`]).
///
/// [RFC 9077]: https://www.rfc-editor.org/rfc/rfc9077.html
/// [RFC 9276]: https://www.rfc-editor.org/rfc/rfc9276.html
// TODO: Add mutable iterator based variant.
// TODO: Get rid of &mut for GenerateNsec3Config.
pub fn generate_nsec3s<N, Octs, Sort>(
    apex_owner: &N,
    mut records: RecordsIter<'_, N, ZoneRecordData<Octs, N>>,
    config: &GenerateNsec3Config<Octs, Sort>,
) -> Result<Nsec3Records<N, Octs>, SigningError>
where
    N: ToName + Clone + Display + Ord + Hash + Send + From<Name<Octs>>,
    Octs: FromBuilder
        + From<&'static [u8]>
        + OctetsFrom<Vec<u8>>
        + Default
        + Clone
        + Send,
    Octs::Builder: EmptyBuilder + Truncate + AsRef<[u8]> + AsMut<[u8]>,
    <Octs::Builder as OctetsBuilder>::AppendError: Debug,
    Sort: Sorter,
{
    // RFC 5155 7.1 step 2:
    //   "If Opt-Out is being used, set the Opt-Out bit to one."
    let exclude_owner_names_of_unsigned_delegations =
        config.params.opt_out_flag()
            && config.opt_out_exclude_owner_names_of_unsigned_delegations;

    // The generated collection of NSEC3 RRs that will be returned to the
    // caller.
    let mut nsec3s = Vec::<Record<N, Nsec3<Octs>>>::new();

    // A collection of empty non-terminal names (ENTs) discovered while
    // walking the zone. NSEC3 RRs will be generated for these RRs as well as
    // the RRs explicitly present in the zone.
    let mut ents = Vec::<N>::new();

    // The number of labels in the apex name. Used when discovering ENTs.
    let apex_label_count = apex_owner.iter_labels().count();

    // The stack of non-empty non-terminal labels currently being walked in the
    // zone. Used for implementing RFC 5155 7.1 step 4.
    let mut last_nent_stack: Vec<N> = vec![];

    // The owner name of a zone cut if we currently are at or below one.
    let mut cut: Option<N> = None;

    // The TTL to use for NSEC3 records. This will be determined per the rules
    // in RFC 9077 once the apex SOA RR is found.
    let mut nsec3_ttl = None;

    // The TTL value to be used for the NSEC3PARAM RR. Determined once
    // nsec3_ttl is known.
    let mut nsec3param_ttl = None;

    // Skip any glue records that sort earlier than the zone apex.
    records.skip_before(apex_owner);

    // RFC 5155 7.1 step 2
    // For each unique original owner name in the zone add an NSEC3 RR.
    for owner_rrs in records {
        trace!("Owner: {}", owner_rrs.owner());

        // If the owner is out of zone, we might have moved out of our zone
        // and are done.
        if !owner_rrs.is_in_zone(apex_owner) {
            debug!(
                "Stopping at owner {} as it is out of zone and assumed to trail the zone",
                owner_rrs.owner()
            );
            break;
        }

        // If the owner is below a zone cut, we must ignore it. As the RRs
        // are required to be sorted all RRs below a zone cut should be
        // encountered after the cut itself.
        if let Some(ref cut) = cut {
            if owner_rrs.owner().ends_with(cut) {
                debug!(
                    "Excluding owner {} as it is below a zone cut",
                    owner_rrs.owner()
                );
                continue;
            }
        }

        // A copy of the owner name. We’ll need it later.
        let name = owner_rrs.owner().clone();

        // If this owner is the parent side of a zone cut, we keep the owner
        // name for later. This also means below that if `cut.is_some()` we
        // are at the parent side of a zone.
        cut = if owner_rrs.is_zone_cut(apex_owner) {
            trace!("Zone cut detected at owner {}", owner_rrs.owner());
            Some(name.clone())
        } else {
            None
        };

        // RFC 5155 7.1 step 2:
        //   "If Opt-Out is being used, owner names of unsigned delegations
        //    MAY be excluded."
        // Note that:
        //   - A "delegation inherently happens at a zone cut" (RFC 9499).
        //   - An "unsigned delegation" aka an "insecure delegation" is a
        //     "signed name containing a delegation (NS RRset), but lacking a
        //     DS RRset, signifying a delegation to an unsigned subzone" (RFC
        //     9499).
        // So we need to check for whether Opt-Out is being used at a zone cut
        // that lacks a DS RR. We determine whether or not a DS RR is present
        // even when Opt-Out is not being used because we also need to know
        // there at a later step.
        let has_ds = owner_rrs.records().any(|rec| rec.rtype() == Rtype::DS);
        if exclude_owner_names_of_unsigned_delegations
            && cut.is_some()
            && !has_ds
        {
            debug!("Excluding owner {} as it is an insecure delegation (lacks a DS RR) and opt-out is enabled",owner_rrs.owner());
            continue;
        }

        // RFC 5155 7.1 step 4:
        //   "If the difference in number of labels between the apex and the
        //    original owner name is greater than 1, additional NSEC3 RRs need
        //    to be added for every empty non-terminal between the apex and
        //    the original owner name."
        let mut last_nent_distance_to_apex = 0;
        let mut last_nent = None;
        while let Some(this_last_nent) = last_nent_stack.pop() {
            if name.ends_with(&this_last_nent) {
                last_nent_distance_to_apex =
                    this_last_nent.iter_labels().count() - apex_label_count;
                last_nent = Some(this_last_nent);
                break;
            }
        }
        let distance_to_root = name.iter_labels().count();
        let distance_to_apex = distance_to_root - apex_label_count;
        if distance_to_apex > last_nent_distance_to_apex {
            trace!("Possible ENT detected at owner {}", owner_rrs.owner());

            // Are there any empty nodes between this node and the apex? The
            // zone file records are already sorted so if all of the parent
            // labels had records at them, i.e. they were non-empty then
            // non_empty_label_count would be equal to label_distance. If it
            // is less that means there are ENTs between us and the last
            // non-empty label in our ancestor path to the apex.

            // Walk from the owner name down the tree of labels from the last
            // known non-empty non-terminal label, extending the name each
            // time by one label until we get to the current name.

            // Given a.b.c.mail.example.com where:
            //   - example.com is the apex owner
            //   - mail.example.com was the last non-empty non-terminal
            // This loop will construct the names:
            //   - c.mail.example.com
            //   - b.c.mail.example.com
            // It will NOT construct the last name as that will be dealt with
            // in the next outer loop iteration.
            //   - a.b.c.mail.example.com
            let distance = distance_to_apex - last_nent_distance_to_apex;
            for n in (1..=distance - 1).rev() {
                let rev_label_it = name.iter_labels().skip(n);

                // Create next longest ENT name.
                let mut builder = NameBuilder::<Octs::Builder>::new();
                for label in rev_label_it.take(distance_to_apex - n) {
                    builder.append_label(label.as_slice()).unwrap();
                }
                let name = builder.append_origin(&apex_owner).unwrap().into();

                if let Err(pos) = ents.binary_search(&name) {
                    debug!("Found ENT at {name}");
                    ents.insert(pos, name);
                }
            }
        }

        // Create the type bitmap.
        let mut bitmap = RtypeBitmap::<Octs>::builder();

        // Authoritative RRsets will be signed by `sign()` so add the expected
        // future RRSIG type now to the NSEC3 Type Bitmap we are constructing.
        //
        // RFC 4033 section 2:
        // 2.  Definitions of Important DNSSEC Terms
        //    Authoritative RRset: Within the context of a particular zone, an
        //       RRset is "authoritative" if and only if the owner name of the
        //       RRset lies within the subset of the name space that is at or
        //       below the zone apex and at or above the cuts that separate
        //       the zone from its children, if any.  All RRsets at the zone
        //       apex are authoritative, except for certain RRsets at this
        //       domain name that, if present, belong to this zone's parent.
        //       These RRset could include a DS RRset, the NSEC RRset
        //       referencing this DS RRset (the "parental NSEC"), and RRSIG
        //       RRs associated with these RRsets, all of which are
        //       authoritative in the parent zone.  Similarly, if this zone
        //       contains any delegation points, only the parental NSEC RRset,
        //       DS RRsets, and any RRSIG RRs associated with these RRsets are
        //       authoritative for this zone.
        if cut.is_none() || has_ds {
            trace!("Adding RRSIG to the bitmap as the RRSET is authoritative (not at zone cut or has a DS RR)");
            bitmap.add(Rtype::RRSIG).unwrap();
        }

        // RFC 5155 7.1 step 3:
        //   "For each RRSet at the original owner name, set the corresponding
        //    bit in the Type Bit Maps field."
        //
        // Note: When generating NSEC RRs (not NSEC3 RRs) RFC 4035 makes it
        // clear that non-authoritative RRs should not be represented in the
        // Type Bitmap but for NSEC3 generation that's less clear.
        //
        // RFC 4035 section 2.3:
        // 2.3.  Including NSEC RRs in a Zone
        //   ...
        //   "bits corresponding to any non-NS RRset for which the parent is
        //   not authoritative MUST be clear."
        //
        // RFC 5155 section 7.1:
        // 7.1.  Zone Signing
        //   ...
        //   "o  The Type Bit Maps field of every NSEC3 RR in a signed zone
        //       MUST indicate the presence of all types present at the
        //       original owner name, except for the types solely contributed
        //       by an NSEC3 RR itself.  Note that this means that the NSEC3
        //       type itself will never be present in the Type Bit Maps."
        //
        // Thus the rules for the types to include in the Type Bitmap for NSEC
        // RRs appear to be different for NSEC3 RRs. However, in practice
        // common tooling implementations exclude types from the NSEC3 which
        // are non-authoritative (e.g. glue and occluded records). One could
        // argue that the following fragments of RFC 5155 support this:
        //
        // RFC 5155 section 7.1.
        // 7.1.  Zone Signing
        //   ...
        //   "Other non-authoritative RRs are not represented by NSEC3 RRs."
        //   ...
        //   "2.  For each unique original owner name in the zone add an NSEC3
        //   RR."
        //
        // (if one reads "in the zone" to exclude data occluded by a zone cut
        // or glue records that are only authoritative in the child zone and
        // not in the parent zone).
        //
        // RFC 4033 could also be interpreted as excluding non-authoritative
        // data from DNSSEC and thus NSEC3:
        //
        // RFC 4033 section 9:
        // 9.  Name Server Considerations
        //   ...
        //   "By itself, DNSSEC is not enough to protect the integrity of an
        //    entire zone during zone transfer operations, as even a signed
        //    zone contains some unsigned, nonauthoritative data if the zone
        //    has any children."
        //
        // As such we exclude non-authoritative RRs from the NSEC3 Type
        // Bitmap, with the EXCEPTION of the NS RR at a secure delegation as
        // insecure delegations are explicitly included by RFC 5155:
        //
        // RFC 5155 section 7.1:
        // 7.1.  Zone Signing
        //   ...
        //   "o  Each owner name within the zone that owns authoritative
        //       RRSets MUST have a corresponding NSEC3 RR.  Owner names that
        //       correspond to unsigned delegations MAY have a corresponding
        //       NSEC3 RR."
        for rrset in owner_rrs.rrsets() {
            if cut.is_none() || matches!(rrset.rtype(), Rtype::NS | Rtype::DS)
            {
                // RFC 5155 section 3.2:
                //   "Bits representing Meta-TYPEs or QTYPEs as specified in
                //    Section 3.1 of [RFC2929] or within the range reserved
                //    for assignment only to QTYPEs and Meta-TYPEs MUST be set
                //    to 0, since they do not appear in zone data".
                //
                // We don't need to do a check here as the ZoneRecordData type
                // that we require already excludes "pseudo" record types,
                // those are only included as member variants of the
                // AllRecordData type.
                trace!("Adding {} to the bitmap", rrset.rtype());
                bitmap.add(rrset.rtype()).unwrap();
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
                nsec3_ttl = Some(min(soa_data.minimum(), soa_rr.ttl()));

                nsec3param_ttl = match config.nsec3param_ttl_mode {
                    Nsec3ParamTtlMode::Fixed(ttl) => Some(ttl),
                    Nsec3ParamTtlMode::Soa => Some(soa_rr.ttl()),
                    Nsec3ParamTtlMode::SoaMinimum => Some(soa_data.minimum()),
                };
            }
        }

        if nsec3_ttl.is_none() {
            return Err(SigningError::SoaRecordCouldNotBeDetermined);
        }

        if distance_to_apex == 0 {
            trace!("Adding NSEC3PARAM to the bitmap as we are at the apex and RRSIG RRs are expected to be added");
            bitmap.add(Rtype::NSEC3PARAM).unwrap();
            if config.assume_dnskeys_will_be_added {
                trace!("Adding DNSKEY to the bitmap as we are at the apex and DNSKEY RRs are expected to be added");
                bitmap.add(Rtype::DNSKEY).unwrap();
            }
        }

        // SAFETY: ttl will be set above before we get here.
        let rec: Record<N, Nsec3<Octs>> = mk_nsec3(
            &name,
            config.params.hash_algorithm(),
            config.params.flags(),
            config.params.iterations(),
            config.params.salt(),
            apex_owner,
            bitmap,
            nsec3_ttl.unwrap(),
        )?;

        // Store the record by order of its owner name.
        nsec3s.push(rec);

        if let Some(last_nent) = last_nent {
            last_nent_stack.push(last_nent);
        }
        last_nent_stack.push(name.clone());
    }

    let Some(nsec3param_ttl) = nsec3param_ttl else {
        return Err(SigningError::SoaRecordCouldNotBeDetermined);
    };

    for name in ents {
        // Create the type bitmap, empty for an ENT NSEC3.
        let bitmap = RtypeBitmap::<Octs>::builder();

        debug!("Generating NSEC3 RR for ENT at {name}");
        // SAFETY: ttl will be set below before prev is set to Some.
        let rec = mk_nsec3(
            &name,
            config.params.hash_algorithm(),
            config.params.flags(),
            config.params.iterations(),
            config.params.salt(),
            apex_owner,
            bitmap,
            nsec3_ttl.unwrap(),
        )?;

        // Store the record by order of its owner name.
        nsec3s.push(rec);
    }

    // RFC 5155 7.1 step 5:
    //   "Sort the set of NSEC3 RRs into hash order."

    trace!("Sorting NSEC3 RRs");
    Sort::sort_by(&mut nsec3s, CanonicalOrd::canonical_cmp);
    nsec3s.dedup();

    // RFC 5155 7.2 step 6:
    //   "Combine NSEC3 RRs with identical hashed owner names by replacing
    //    them with a single NSEC3 RR with the Type Bit Maps field consisting
    //    of the union of the types represented by the set of NSEC3 RRs.  If
    //    the original owner name was tracked, then collisions may be detected
    //    when combining, as all of the matching NSEC3 RRs should have the
    //    same original owner name. Discard any possible temporary NSEC3 RRs."
    //
    // ^^^ Combining isn't necessary in our implementation as the input zone
    // is assumed to be sorted in DNSSEC canonical order and we created NSEC3
    // one owner name at a time already with all RTYPEs reflected in the type
    // bit map. We do track the original owner name in order to detect
    // collisions. We did not create temporary wildcard NSEC3s so have none to
    // discard.
    //
    // TODO: Create temporary wildcard NSEC3s. See RFC 5155 section 7.1 step
    // 4.
    //
    // Note: In mk_nsec3() the original owner name was stored as the
    // placeholder next owner name in the generated NSEC3 record in order to
    // detect hash collisions.

    // RFC 5155 7.1 step 7:
    //   "In each NSEC3 RR, insert the next hashed owner name by using the
    //    value of the next NSEC3 RR in hash order.  The next hashed owner
    //    name of the last NSEC3 RR in the zone contains the value of the
    //    hashed owner name of the first NSEC3 RR in the hash order."

    // We don't walk over windows of size two (as that would require nightly
    // Rust support) or keep a mutable reference to the previous NSEC3 (as
    // simultaneous mutable references would anger the borrow checker).
    // Instead we peek at the next and update the current, handling the final
    // last -> first case separately.

    let only_one_nsec3 = nsec3s.len() == 1;
    let first = nsec3s.first().unwrap().clone();
    let mut iter = nsec3s.iter_mut().peekable();

    while let Some(nsec3) = iter.next() {
        // If we are at the end of the NSEC3 chain the next NSEC3 is the first
        // NSEC3.
        let next_nsec3 = if let Some(next) = iter.peek() {
            next.deref()
        } else {
            &first
        };

        // Each NSEC3 should have a unique owner name, as we already combined
        // all RTYPEs into a single NSEC3 for a given owner name above. As the
        // NSEC3s are sorted, if another NSEC3 has the same owner name but
        // different RDATA it will be the next NSEC3 in the iterator. (a) this
        // shouldn't happen, and (b) if it does it should only be because the
        // original owner name of the two NSEC3s are different but hash to the
        // same hashed owner name, i.e. there was a hash collision. If the
        // next NSEC3 has a different hashed owner name it must have a
        // different original owner name, the same owner name can't hash to two
        // different values. If there is only one NSEC3 then it will point to
        // itself and clearly the current and next will be the same so exclude
        // that special case.
        if !only_one_nsec3 && nsec3.owner() == next_nsec3.owner() {
            if nsec3.data().next_owner() != next_nsec3.data().next_owner() {
                Err(Nsec3HashError::CollisionDetected)?;
            } else {
                // This shouldn't happen. Could it maybe happen if the input
                // data were unsorted?
                unreachable!("All RTYPEs for a single owner name should have been combined into a single NSEC3 RR. Was the input NSEC3 canonically ordered?");
            }
        }

        // Replace the Next Hashed Owner Name of the current NSEC3 RR with the
        // first label of the next NSEC3 RR owner name (which is itself an
        // NSEC3 hash).
        let next_owner_name: Name<Octs> = next_nsec3
            .owner()
            .try_to_name()
            .map_err(|_| Nsec3HashError::AppendError)?;

        // SAFETY: We created the owner name by appending the zone apex owner
        // name to an NSEC3 hash so by definition there must be two labels and
        // it is safe to unwrap the first.
        let first_label_of_next_owner_name =
            next_owner_name.iter_labels().next().unwrap();
        let next_hashed_owner_name = if let Ok(hash_octets) =
            base32::decode_hex(&format!("{first_label_of_next_owner_name}"))
        {
            OwnerHash::<Octs>::from_octets(hash_octets)
                .map_err(|_| Nsec3HashError::OwnerHashError)?
        } else {
            return Err(Nsec3HashError::OwnerHashError)?;
        };
        nsec3.data_mut().set_next_owner(next_hashed_owner_name);
    }

    // RFC 5155 7.1 step 8:
    //   "Finally, add an NSEC3PARAM RR with the same Hash Algorithm,
    //    Iterations, and Salt fields to the zone apex."
    // SAFETY: nsec3param_ttl will be set above before we get here.
    let nsec3param = Record::new(
        apex_owner
            .try_to_name::<Octs>()
            .map_err(|_| Nsec3HashError::AppendError)?
            .into(),
        Class::IN,
        nsec3param_ttl,
        config.params.clone(),
    );

    // RFC 5155 7.1 after step 8:
    //   "If a hash collision is detected, then a new salt has to be
    //    chosen, and the signing process restarted."
    //
    // Handled above.

    Ok(Nsec3Records::new(nsec3s, nsec3param))
}

// unhashed_owner_name_is_ent is used to signal that the unhashed owner name
// is an empty non-terminal, as ldns-signzone for example outputs a comment
// for NSEC3 hashes that are for unhashed empty non-terminal owner names, and
// it can be quite costly to determine later given only a collection of
// records if the unhashed owner name is an ENT or not, so we pass this flag
// to the hash provider and it can record it if wanted.
#[allow(clippy::too_many_arguments)]
fn mk_nsec3<N, Octs>(
    name: &N,
    alg: Nsec3HashAlgorithm,
    flags: u8,
    iterations: u16,
    salt: &Nsec3Salt<Octs>,
    apex_owner: &N,
    bitmap: RtypeBitmapBuilder<<Octs as FromBuilder>::Builder>,
    ttl: Ttl,
) -> Result<Record<N, Nsec3<Octs>>, Nsec3HashError>
where
    N: ToName + From<Name<Octs>>,
    Octs: FromBuilder + Clone + Default,
    <Octs as FromBuilder>::Builder:
        EmptyBuilder + AsRef<[u8]> + AsMut<[u8]> + Truncate,
{
    let owner_name =
        mk_hashed_nsec3_owner_name(name, alg, iterations, salt, apex_owner)?;

    // RFC 5155 7.1. step 2:
    //   "The Next Hashed Owner Name field is left blank for the moment."
    // Create a placeholder next owner, we'll fix it later. To enable
    // detection of collisions we use the original owner name as the
    // placeholder value.
    let placeholder_next_owner = OwnerHash::<Octs>::from_octets(
        name.try_to_name::<Octs>()
            .map_err(|_| Nsec3HashError::AppendError)?
            .as_octets()
            .clone(),
    )
    .map_err(|_| Nsec3HashError::OwnerHashError)?;

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

pub fn mk_hashed_nsec3_owner_name<N, Octs, SaltOcts>(
    name: &N,
    alg: Nsec3HashAlgorithm,
    iterations: u16,
    salt: &Nsec3Salt<SaltOcts>,
    apex_owner: &N,
) -> Result<N, Nsec3HashError>
where
    N: ToName + From<Name<Octs>>,
    Octs: FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    SaltOcts: AsRef<[u8]>,
{
    let base32hex_label =
        mk_base32hex_label_for_name(name, alg, iterations, salt)?;
    #[cfg(test)]
    if tests::NSEC3_TEST_MODE
        .with(|n| *n.borrow() == tests::Nsec3TestMode::NoHash)
    {
        let name = N::from(name.try_to_name().ok().unwrap());
        return Ok(name);
    }
    Ok(append_origin(base32hex_label, apex_owner))
}

fn append_origin<N, Octs>(base32hex_label: String, apex_owner: &N) -> N
where
    N: ToName + From<Name<Octs>>,
    Octs: FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
{
    let mut builder = NameBuilder::<Octs::Builder>::new();
    builder.append_label(base32hex_label.as_bytes()).unwrap();
    let owner_name = builder.append_origin(apex_owner).unwrap();
    let owner_name: N = owner_name.into();
    owner_name
}

fn mk_base32hex_label_for_name<N, SaltOcts>(
    name: &N,
    alg: Nsec3HashAlgorithm,
    iterations: u16,
    salt: &Nsec3Salt<SaltOcts>,
) -> Result<String, Nsec3HashError>
where
    N: ToName,
    SaltOcts: AsRef<[u8]>,
{
    let hash_octets: Vec<u8> =
        nsec3_hash(name, alg, iterations, salt)?.into_octets();
    #[cfg(test)]
    let hash_octets = if tests::NSEC3_TEST_MODE
        .with(|n| *n.borrow() == tests::Nsec3TestMode::Colliding)
    {
        vec![0; hash_octets.len()]
    } else {
        hash_octets
    };
    Ok(base32::encode_string_hex(&hash_octets).to_ascii_lowercase())
}

//----------- Nsec3ParamTtlMode ----------------------------------------------

/// The TTL to use for the NSEC3PARAM RR.
///
/// Per RFC 5155 section 7.3 "Secondary Servers": "Secondary servers (and
///   perhaps other entities) need to reliably determine which NSEC3
///    parameters (i.e., hash, salt, and iterations) are present at every
///    hashed owner name, in order to be able to choose an appropriate set of
///    NSEC3 RRs for negative responses.  This is indicated by an NSEC3PARAM
///    RR present at the zone apex."
///
/// RFC 5155 does not say anything about the TTL to use for the NSEC3PARAM RR.
///
/// RFC 1034 says when _"When a name server loads a zone, it forces the TTL of
/// all authoritative RRs to be at least the MINIMUM field of the SOA"_ so an
/// approach used by some zone signers (e.g. PowerDNS) is to use the SOA
/// MINIMUM as the TTL for the NSEC3PARAM.
///
/// An alternative approach used by some zone signers is to use a fixed TTL
/// for the NSEC3PARAM TTL, e.g. BIND, dnssec-signzone and OpenDNSSEC
/// reportedly use 0 while ldns-signzone uses 3600 (as does an example
/// in the BIND documentation).
///
/// The default approach used here is to use the TTL of the SOA RR, NOT the
/// SOA MINIMUM. This is consistent with how a TTL is chosen by tools such as
/// dnssec-signzone and ldns-signzone for other non-NSEC(3) records that are
/// added to a zone such as DNSKEY RRs. We do not use a fixed value as the
/// default as that seems strangely inconsistent with the rest of the zone,
/// and especially not zero as that seems to be considered a complex case for
/// resolvers to handle and may potentially lead to unwanted behaviour, and
/// additional load on both authoritatives and resolvers if a (abusive) client
/// should aggressively query the NSEC3PARAM RR. We also do not use the SOA
/// MINIMUM TTL as that concerns (quoting RFC 1034) "the length of time that
/// the negative result may be cached" and the NSEC3PARAM is not related to
/// negative caching. As at least one other implementation uses SOA MINIMUM
/// and this is not a hard-coded value that a caller can supply via the Fixed
/// enum variant, we also support using SOA MINIMUM via the SoaMinimum
/// variant.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Nsec3ParamTtlMode {
    /// Use a fixed TTL value.
    Fixed(Ttl),

    /// Use the TTL of the SOA record.
    #[default]
    Soa,

    /// Use the TTL of the SOA record MINIMUM data field.
    SoaMinimum,
}

impl Nsec3ParamTtlMode {
    pub fn fixed(ttl: Ttl) -> Self {
        Self::Fixed(ttl)
    }

    pub fn soa() -> Self {
        Self::Soa
    }

    pub fn soa_minimum() -> Self {
        Self::SoaMinimum
    }
}

//------------ Nsec3Records ---------------------------------------------------

pub struct Nsec3Records<N, Octets> {
    /// The NSEC3 records.
    pub nsec3s: Vec<Record<N, Nsec3<Octets>>>,

    /// The NSEC3PARAM record.
    pub nsec3param: Record<N, Nsec3param<Octets>>,
}

impl<N, Octets> Nsec3Records<N, Octets> {
    pub fn new(
        nsec3s: Vec<Record<N, Nsec3<Octets>>>,
        nsec3param: Record<N, Nsec3param<Octets>>,
    ) -> Self {
        Self { nsec3s, nsec3param }
    }
}

#[cfg(test)]
mod tests {
    // Note: These tests are similar to the nsec.rs unit tests but with two
    // key differences:
    //
    //   1. Unlike NSEC which set the bit for the NSEC RTYPE in the NSEC type
    //      bitmap, with NSEC3 the NSEC bit is never set and so NSEC in type
    //      bitmap tests is not replaced by NSEC3 in these tests but is
    //      instead removed from the expected type bitmap.
    //
    //   2. With NSEC the NSEC RRs are added at the same owner name as the
    //      covered records and so it is easy to write out by hand the
    //      expected RRs in DNSSEC canonical order. With NSEC3 however the
    //      NSEC3 RRs are added at an owner name that is based on a hash of
    //      the original owner name, and rather than include these long
    //      unreadable hashes in the expected RR names we instead decide that
    //      it is not the responsibility of these tests to verify that NSEC3
    //      hash generation is correct (that belongs with the code that
    //      generates NSEC3 hashes which is not done in this module at the
    //      time of writing), and so instead we generate the hashes during
    //      test execution and only refer to the unhashed names when defining
    //      the expected test records. As it is also not part of this module
    //      to correctly order NSEC3 recods by DNSSEC canonical order, we also
    //      assume that that ordering is applied correctly and so choose to
    //      define the correct order of expected NSEC3 records by letting
    //      SortedRecords sort them by hashed owner name in DNSSEC canonical
    //      order for us.
    use core::str::FromStr;

    use std::cell::RefCell;

    use pretty_assertions::assert_eq;

    use crate::dnssec::sign::records::SortedRecords;
    use crate::dnssec::sign::test_util::*;

    use super::*;

    #[derive(PartialEq)]
    pub(super) enum Nsec3TestMode {
        Normal,
        Colliding,
        NoHash,
    }

    thread_local! {
    pub(super) static NSEC3_TEST_MODE: RefCell<Nsec3TestMode> = const { RefCell::new(Nsec3TestMode::Normal) };
    }

    #[test]
    fn soa_is_required() {
        let cfg = GenerateNsec3Config::default()
            .without_assuming_dnskeys_will_be_added();
        let apex = Name::from_str("a.").unwrap();
        let records =
            SortedRecords::<_, _>::from_iter([mk_a_rr("some_a.a.")]);
        let res = generate_nsec3s(&apex, records.owner_rrs(), &cfg);
        assert!(matches!(
            res,
            Err(SigningError::SoaRecordCouldNotBeDetermined)
        ));
    }

    #[test]
    fn multiple_soa_rrs_in_the_same_rrset_are_not_permitted() {
        let cfg = GenerateNsec3Config::default()
            .without_assuming_dnskeys_will_be_added();
        let apex = Name::from_str("a.").unwrap();
        let records = SortedRecords::<_, _>::from_iter([
            mk_soa_rr("a.", "b.", "c."),
            mk_soa_rr("a.", "d.", "e."),
        ]);
        let res = generate_nsec3s(&apex, records.owner_rrs(), &cfg);
        assert!(matches!(
            res,
            Err(SigningError::SoaRecordCouldNotBeDetermined)
        ));
    }

    #[test]
    fn records_outside_zone_are_ignored() {
        let cfg = GenerateNsec3Config::default()
            .without_assuming_dnskeys_will_be_added();
        let a_apex = Name::from_str("a.").unwrap();
        let b_apex = Name::from_str("b.").unwrap();
        let records = SortedRecords::<_, _>::from_iter([
            mk_soa_rr("b.", "d.", "e."),
            mk_soa_rr("a.", "b.", "c."),
            mk_a_rr("some_a.a."),
            mk_a_rr("some_a.b."),
        ]);

        // Generate NSEC3s for the a. zone.
        let generated_records =
            generate_nsec3s(&a_apex, records.owner_rrs(), &cfg).unwrap();

        let expected_records = SortedRecords::<_, _>::from_iter([
            mk_nsec3_rr(
                "a.",
                "a.",
                "some_a.a.",
                "SOA RRSIG NSEC3PARAM",
                &cfg,
            ),
            mk_nsec3_rr("a.", "some_a.a.", "a.", "A RRSIG", &cfg),
        ]);

        assert_eq!(generated_records.nsec3s, expected_records.into_inner());

        // Generate NSEC3s for the b. zone.
        let generated_records =
            generate_nsec3s(&b_apex, records.owner_rrs(), &cfg).unwrap();

        let expected_records = SortedRecords::<_, _>::from_iter([
            mk_nsec3_rr(
                "b.",
                "b.",
                "some_a.b.",
                "SOA RRSIG NSEC3PARAM",
                &cfg,
            ),
            mk_nsec3_rr("b.", "some_a.b.", "b.", "A RRSIG", &cfg),
        ]);

        assert_eq!(generated_records.nsec3s, expected_records.into_inner());
        assert!(!generated_records.nsec3param.data().opt_out_flag());
    }

    #[test]
    fn glue_records_are_ignored() {
        let mut cfg = GenerateNsec3Config::default()
            .without_assuming_dnskeys_will_be_added();
        let apex = Name::from_str("example.").unwrap();
        let records = SortedRecords::<_, _>::from_iter([
            mk_soa_rr("example.", "mname.", "rname."),
            mk_ns_rr("example.", "early_sorting_glue."),
            mk_ns_rr("example.", "late_sorting_glue."),
            mk_a_rr("in_zone.example."),
            mk_a_rr("early_sorting_glue."),
            mk_a_rr("late_sorting_glue."),
        ]);

        // Generate NSEs for the a. zone.
        let generated_records =
            generate_nsec3s(&apex, records.owner_rrs(), &cfg).unwrap();

        let expected_records = SortedRecords::<_, _>::from_iter([
            mk_nsec3_rr(
                "example.",
                "example.",
                "in_zone.example.",
                "NS SOA RRSIG NSEC3PARAM",
                &cfg,
            ),
            mk_nsec3_rr(
                "example.",
                "in_zone.example.",
                "example.",
                "A RRSIG",
                &cfg,
            ),
        ]);

        assert_eq!(generated_records.nsec3s, expected_records.into_inner());
    }

    #[test]
    fn occluded_records_are_ignored() {
        let cfg = GenerateNsec3Config::default()
            .without_assuming_dnskeys_will_be_added();
        let apex = Name::from_str("a.").unwrap();
        let records = SortedRecords::<_, _>::from_iter([
            mk_soa_rr("a.", "b.", "c."),
            mk_ns_rr("some_ns.a.", "some_a.other.b."),
            mk_a_rr("some_a.some_ns.a."),
        ]);

        let generated_records =
            generate_nsec3s(&apex, records.owner_rrs(), &cfg).unwrap();

        let expected_records = SortedRecords::<_, _>::from_iter([
            mk_nsec3_rr(
                "a.",
                "a.",
                "some_ns.a.",
                "SOA RRSIG NSEC3PARAM",
                &cfg,
            ),
            // Unlike with NSEC the type bitmap for the NSEC3 for some_ns.a
            // does NOT include RRSIG. This is because with NSEC "Each owner
            // name in the zone that has authoritative data or a delegation
            // point NS RRset MUST have an NSEC resource record" (RFC 4035
            // section 2.3), and while the zone is not authoritative for the
            // NS record, "NSEC RRsets are authoritative data and are
            // therefore signed" (RFC 4035 section 2.3). With NSEC3 however
            // as the NSEC3 record for the unsigned delegation is generated
            // (because we are not using opt out) but not stored at some_ns.a
            // (but instead at <HASH>.a.) then the only record at some_ns.a
            // is the NS record itself which is not authoritative and so
            // doesn't get an RRSIG.
            mk_nsec3_rr("a.", "some_ns.a.", "a.", "NS", &cfg),
        ]);

        assert_eq!(generated_records.nsec3s, expected_records.into_inner());
        assert!(!generated_records.nsec3param.data().opt_out_flag());
    }

    #[test]
    fn expect_dnskeys_at_the_apex() {
        let cfg = GenerateNsec3Config::default();

        let apex = Name::from_str("a.").unwrap();
        let records = SortedRecords::<_, _>::from_iter([
            mk_soa_rr("a.", "b.", "c."),
            mk_a_rr("some_a.a."),
        ]);

        let generated_records =
            generate_nsec3s(&apex, records.owner_rrs(), &cfg).unwrap();

        let expected_records = SortedRecords::<_, _>::from_iter([
            mk_nsec3_rr(
                "a.",
                "a.",
                "some_a.a.",
                "SOA DNSKEY RRSIG NSEC3PARAM",
                &cfg,
            ),
            mk_nsec3_rr("a.", "some_a.a.", "a.", "A RRSIG", &cfg),
        ]);

        assert_eq!(generated_records.nsec3s, expected_records.into_inner());
        assert!(!generated_records.nsec3param.data().opt_out_flag());
    }

    #[test]
    fn rfc_5155_appendix_a_and_rfc_9077_compliant_plus_ents() {
        // These NSEC3 settings match those of the NSEC3PARAM record shown in
        // https://datatracker.ietf.org/doc/html/rfc5155#appendix-A.
        let nsec3params = Nsec3param::new(
            Nsec3HashAlgorithm::SHA1,
            1, // opt-out
            12,
            Nsec3Salt::from_str("aabbccdd").unwrap(),
        );
        let cfg =
            GenerateNsec3Config::<_, DefaultSorter>::new(nsec3params.clone())
                .without_assuming_dnskeys_will_be_added();

        // See https://datatracker.ietf.org/doc/html/rfc5155#appendix-A
        let zonefile = include_bytes!(
            "../../../../test-data/zonefiles/rfc5155-appendix-A.zone"
        );

        let apex = Name::from_str("example.").unwrap();
        let records = bytes_to_records(&zonefile[..]);
        let generated_records =
            generate_nsec3s(&apex, records.owner_rrs(), &cfg).unwrap();

        // Generate the expected NSEC3 RRs. The hashes used match those listed
        // in https://datatracker.ietf.org/doc/html/rfc5155#appendix-A and can
        // be replicated by e.g. using a command such as:
        //   ldns-nsec3-hash -t 12 -s 'aabbccdd' xx.example.
        // The records are listed in hash chain order, e.g.
        //    0p9.. -> 2t7..
        //    2t7.. -> 2vp..
        //    2vp.. -> 35m..
        //
        // https://datatracker.ietf.org/doc/html/rfc5155#section-7.1
        // 7.1.  Zone Signing
        // ..
        //   "The owner name of the NSEC3 RR is the hash of the original owner
        //    name, prepended as a single label to the zone name."
        //
        // E.g. the hash of example. computed with:
        //   ldns-nsec3-hash -t 12 -s 'aabbccdd' example.
        // is:
        //   0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.
        //
        // So the owner name of the NSEC3 RR for original owner example. is
        // the hash value we just calculated "pre-pended as a single label to
        // the zone name" with the zone name in this case being "example.",
        // i.e.:
        //   0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.
        //
        // Next we calculate the "next hashed owner name" like so:
        //
        // https://datatracker.ietf.org/doc/html/rfc5155#section-7.1
        // 7.1.  Zone Signing
        // ..
        //   "7.  In each NSEC3 RR, insert the next hashed owner name by using
        //    the value of the next NSEC3 RR in hash order.  The next hashed
        //    owner name of the last NSEC3 RR in the zone contains the value
        //    of the hashed owner name of the first NSEC3 RR in the hash
        //    order."
        //
        // The generated NSEC3s should be in hash order because we have to sort
        // them that way anyway for the RFC 5155 algorithm:
        //
        // https://datatracker.ietf.org/doc/html/rfc5155#section-7.1
        // 7.1.  Zone Signing
        // ..
        //   "   5.  Sort the set of NSEC3 RRs into hash order."
        let expected_records = SortedRecords::<_, _>::from_iter([
            mk_precalculated_nsec3_rr(
                // from: example. to: ns1.example.
                "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom.example.",
                "2t7b4g4vsa5smi47k61mv5bv1a22bojr",
                "NS SOA MX RRSIG NSEC3PARAM",
                &cfg,
            ),
            mk_precalculated_nsec3_rr(
                // from: ns1.example. to: x.y.w.example.
                "2t7b4g4vsa5smi47k61mv5bv1a22bojr.example.",
                "2vptu5timamqttgl4luu9kg21e0aor3s",
                "A RRSIG",
                &cfg,
            ),
            mk_precalculated_nsec3_rr(
                // from: x.y.w.example. to: a.example.
                "2vptu5timamqttgl4luu9kg21e0aor3s.example.",
                "35mthgpgcu1qg68fab165klnsnk3dpvl",
                "MX RRSIG",
                &cfg,
            ),
            mk_precalculated_nsec3_rr(
                // from: a.example to: x.w.example.
                "35mthgpgcu1qg68fab165klnsnk3dpvl.example.",
                "b4um86eghhds6nea196smvmlo4ors995",
                "NS DS RRSIG",
                &cfg,
            ),
            mk_precalculated_nsec3_rr(
                // from: x.w.example. to: ai.example.
                "b4um86eghhds6nea196smvmlo4ors995.example.",
                "gjeqe526plbf1g8mklp59enfd789njgi",
                "MX RRSIG",
                &cfg,
            ),
            mk_precalculated_nsec3_rr(
                // from: ai.example. to: y.w.example.
                "gjeqe526plbf1g8mklp59enfd789njgi.example.",
                "ji6neoaepv8b5o6k4ev33abha8ht9fgc",
                "A HINFO AAAA RRSIG",
                &cfg,
            ),
            // Unlike NSEC, with NSEC3 empty non-terminals must also have
            // NSEC3 RRs:
            //
            // https://www.rfc-editor.org/rfc/rfc5155#section-7.1
            // 7.1.  Zone Signing
            // ..
            //   "Each empty non-terminal MUST have a corresponding NSEC3 RR,
            //    unless the empty non-terminal is only derived from an
            //    insecure delegation covered by an Opt-Out NSEC3 RR."
            //
            // ENT NSEC3 RRs have an empty Type Bit Map.
            mk_precalculated_nsec3_rr(
                // from: y.w.example. to: w.example.
                "ji6neoaepv8b5o6k4ev33abha8ht9fgc.example.",
                "k8udemvp1j2f7eg6jebps17vp3n8i58h",
                "",
                &cfg,
            ),
            mk_precalculated_nsec3_rr(
                // from: w.example. to: ns2.example.
                "k8udemvp1j2f7eg6jebps17vp3n8i58h.example.",
                "q04jkcevqvmu85r014c7dkba38o0ji5r",
                "",
                &cfg,
            ),
            mk_precalculated_nsec3_rr(
                // from: ns2.example. to: *.w.example.
                "q04jkcevqvmu85r014c7dkba38o0ji5r.example.",
                "r53bq7cc2uvmubfu5ocmm6pers9tk9en",
                "A RRSIG",
                &cfg,
            ),
            mk_precalculated_nsec3_rr(
                // from: *.w.example. to: xx.example.
                "r53bq7cc2uvmubfu5ocmm6pers9tk9en.example.",
                "t644ebqk9bibcna874givr6joj62mlhv",
                "MX RRSIG",
                &cfg,
            ),
            mk_precalculated_nsec3_rr(
                // from: xx.example. to: example.
                "t644ebqk9bibcna874givr6joj62mlhv.example.",
                "0p9mhaveqvm6t7vbl5lop2u3t2rp3tom",
                "A HINFO AAAA RRSIG",
                &cfg,
            ),
        ]);

        assert_eq!(generated_records.nsec3s, expected_records.into_inner());

        // https://www.rfc-editor.org/rfc/rfc5155#section-7.1
        // 7.1.  Zone Signing
        // ..
        //   "8.  Finally, add an NSEC3PARAM RR with the same Hash Algorithm,
        //    Iterations, and Salt fields to the zone apex."
        //
        // We don't actually add the NSEC3PARAM RR to the zone, instead we
        // generate it so that the caller can do that.
        let expected_nsec3param = mk_nsec3param_rr("example.", &cfg);
        assert_eq!(generated_records.nsec3param, expected_nsec3param);
        assert!(generated_records.nsec3param.data().opt_out_flag());

        // TTLs are not compared by the eq check above so check them
        // explicitly now.
        //
        // RFC 9077 updated RFC 4034 (NSEC) and RFC 5155 (NSEC3) to say that
        // the "TTL of the NSEC(3) RR that is returned MUST be the lesser of
        // the MINIMUM field of the SOA record and the TTL of the SOA itself".
        //
        // So in our case that is min(1800, 3600) = 1800.
        for nsec3 in &generated_records.nsec3s {
            assert_eq!(nsec3.ttl(), Ttl::from_secs(1800));
        }
    }

    #[test]
    fn opt_out_with_exclusion() {
        // https://www.rfc-editor.org/rfc/rfc5155.html#section-7.1
        // 7.1.  Zone Signing
        // ..
        //   "Owner names that correspond to unsigned delegations MAY have a
        //    corresponding NSEC3 RR. However, if there is not a corresponding
        //    NSEC3 RR, there MUST be an Opt-Out NSEC3 RR that covers the
        //    "next closer" name to the delegation."
        //
        // This test tests opt-out with exclusion, i.e. opt-out that excludes
        // an unsigned delegation and thus there "MUST be an Opt-Out NSEC3
        // RR...".
        let cfg = GenerateNsec3Config::default()
            .with_opt_out()
            .without_assuming_dnskeys_will_be_added();

        let apex = Name::from_str("a.").unwrap();
        let records = SortedRecords::<_, _>::from_iter([
            mk_soa_rr("a.", "b.", "c."),
            mk_ns_rr("unsigned_delegation.a.", "some.other.zone."),
        ]);

        let generated_records =
            generate_nsec3s(&apex, records.owner_rrs(), &cfg).unwrap();

        let expected_records =
            SortedRecords::<_, _>::from_iter([mk_nsec3_rr(
                "a.",
                "a.",
                "a.",
                "SOA RRSIG NSEC3PARAM",
                &cfg,
            )]);

        assert_eq!(generated_records.nsec3s, expected_records.into_inner());
        assert!(generated_records.nsec3param.data().opt_out_flag());
    }

    #[test]
    fn opt_out_without_exclusion() {
        // https://www.rfc-editor.org/rfc/rfc5155.html#section-7.1
        // 7.1.  Zone Signing
        // ..
        //   "Owner names that correspond to unsigned delegations MAY have a
        //    corresponding NSEC3 RR. However, if there is not a corresponding
        //    NSEC3 RR, there MUST be an Opt-Out NSEC3 RR that covers the
        //    "next closer" name to the delegation."
        //
        // This test tests opt-out with_out_ exclusion, i.e. opt-out that
        // creates an NSEC RR for an unsigned delegation.
        let cfg = GenerateNsec3Config::default()
            .with_opt_out()
            .without_opt_out_excluding_owner_names_of_unsigned_delegations()
            .without_assuming_dnskeys_will_be_added();

        // This also tests the case of handling a single NSEC3 as only the SOA
        // RR gets an NSEC3, the NS RR does not.
        let apex = Name::from_str("a.").unwrap();
        let records = SortedRecords::<_, _>::from_iter([
            mk_soa_rr("a.", "b.", "c."),
            mk_ns_rr("unsigned_delegation.a.", "some.other.zone."),
        ]);

        let generated_records =
            generate_nsec3s(&apex, records.owner_rrs(), &cfg).unwrap();

        let expected_records = SortedRecords::<_, _>::from_iter([
            mk_nsec3_rr(
                "a.",
                "a.",
                "unsigned_delegation.a.",
                "SOA RRSIG NSEC3PARAM",
                &cfg,
            ),
            mk_nsec3_rr("a.", "unsigned_delegation.a.", "a.", "NS", &cfg),
        ]);

        assert_eq!(generated_records.nsec3s, expected_records.into_inner());
        assert!(generated_records.nsec3param.data().opt_out_flag());
    }

    #[test]
    #[should_panic(
        expected = "All RTYPEs for a single owner name should have been combined into a single NSEC3 RR. Was the input NSEC3 canonically ordered?"
    )]
    fn generating_nsec3s_for_unordered_input_should_panic() {
        let cfg = GenerateNsec3Config::default()
            .without_assuming_dnskeys_will_be_added();

        let apex = Name::from_str("a.").unwrap();
        let records = vec![
            mk_soa_rr("a.", "b.", "c."),
            mk_a_rr("some_a.a."),
            mk_a_rr("some_b.a."),
            mk_aaaa_rr("some_a.a."),
        ];

        let _res = generate_nsec3s(&apex, RecordsIter::new(&records), &cfg);
    }

    #[test]
    fn test_nsec3_hash_collision_handling() {
        let cfg = GenerateNsec3Config::<_, DefaultSorter>::new(
            Nsec3param::default(),
        );
        NSEC3_TEST_MODE.replace(Nsec3TestMode::Colliding);

        let apex = Name::from_str("a.").unwrap();
        let records = SortedRecords::<_, _>::from_iter([
            mk_soa_rr("a.", "b.", "c."),
            mk_a_rr("some_a.a."),
        ]);

        assert!(matches!(
            generate_nsec3s(&apex, records.owner_rrs(), &cfg),
            Err(SigningError::Nsec3HashingError(
                Nsec3HashError::CollisionDetected
            ))
        ));
    }

    #[test]
    fn test_nsec3_hashing_failure() {
        let cfg = GenerateNsec3Config::<_, DefaultSorter>::new(
            Nsec3param::default(),
        );
        NSEC3_TEST_MODE.replace(Nsec3TestMode::NoHash);

        let apex = Name::from_str("a.").unwrap();
        let records = SortedRecords::<_, _>::from_iter([
            mk_soa_rr("a.", "b.", "c."),
            mk_a_rr("some_a.a."),
        ]);

        assert!(matches!(
            generate_nsec3s(&apex, records.owner_rrs(), &cfg),
            Err(SigningError::Nsec3HashingError(
                Nsec3HashError::OwnerHashError
            ))
        ));
    }
}
