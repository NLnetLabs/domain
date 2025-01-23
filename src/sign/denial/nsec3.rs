use core::cmp::min;
use core::convert::From;
use core::fmt::{Debug, Display};
use core::marker::{PhantomData, Send};

use std::hash::Hash;
use std::string::String;
use std::vec::Vec;

use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, Truncate};
use octseq::OctetsFrom;
use tracing::{debug, trace};

use crate::base::iana::{Class, Nsec3HashAlg, Rtype};
use crate::base::name::{ToLabelIter, ToName};
use crate::base::{Name, NameBuilder, Record, Ttl};
use crate::rdata::dnssec::{RtypeBitmap, RtypeBitmapBuilder};
use crate::rdata::nsec3::{Nsec3Salt, OwnerHash};
use crate::rdata::{Nsec3, Nsec3param, ZoneRecordData};
use crate::sign::error::SigningError;
use crate::sign::records::{
    DefaultSorter, RecordsIter, SortedRecords, Sorter,
};
use crate::utils::base32;
use crate::validate::{nsec3_hash, Nsec3HashError};

//----------- GenerateNsec3Config --------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GenerateNsec3Config<N, Octs, HashProvider, Sort>
where
    HashProvider: Nsec3HashProvider<N, Octs>,
    Octs: AsRef<[u8]> + From<&'static [u8]>,
{
    pub assume_dnskeys_will_be_added: bool,
    pub params: Nsec3param<Octs>,
    pub opt_out: Nsec3OptOut,
    pub nsec3param_ttl_mode: Nsec3ParamTtlMode,
    pub hash_provider: HashProvider,
    _phantom: PhantomData<(N, Sort)>,
}

impl<N, Octs, HashProvider, Sort>
    GenerateNsec3Config<N, Octs, HashProvider, Sort>
where
    HashProvider: Nsec3HashProvider<N, Octs>,
    Octs: AsRef<[u8]> + From<&'static [u8]>,
{
    pub fn new(
        params: Nsec3param<Octs>,
        opt_out: Nsec3OptOut,
        hash_provider: HashProvider,
    ) -> Self {
        Self {
            assume_dnskeys_will_be_added: true,
            params,
            opt_out,
            hash_provider,
            nsec3param_ttl_mode: Default::default(),
            _phantom: Default::default(),
        }
    }

    pub fn with_ttl_mode(mut self, ttl_mode: Nsec3ParamTtlMode) -> Self {
        self.nsec3param_ttl_mode = ttl_mode;
        self
    }

    pub fn without_assuming_dnskeys_will_be_added(mut self) -> Self {
        self.assume_dnskeys_will_be_added = false;
        self
    }
}

impl<N, Octs> Default
    for GenerateNsec3Config<
        N,
        Octs,
        OnDemandNsec3HashProvider<Octs>,
        DefaultSorter,
    >
where
    N: ToName + From<Name<Octs>>,
    Octs: AsRef<[u8]> + From<&'static [u8]> + Clone + FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
{
    fn default() -> Self {
        let params = Nsec3param::default();
        let hash_provider = OnDemandNsec3HashProvider::new(
            params.hash_algorithm(),
            params.iterations(),
            params.salt().clone(),
        );
        Self {
            assume_dnskeys_will_be_added: true,
            params,
            opt_out: Default::default(),
            nsec3param_ttl_mode: Default::default(),
            hash_provider,
            _phantom: Default::default(),
        }
    }
}

/// Generate [RFC5155] NSEC3 and NSEC3PARAM records for this record set.
///
/// This function does NOT enforce use of current best practice settings, as
/// defined by [RFC 5155], [RFC 9077] and [RFC 9276] which state that:
///
/// - The `ttl` should be the _"lesser of the MINIMUM field of the zone SOA RR
///   and the TTL of the zone SOA RR itself"_.
///
/// - The `params` should be set to _"SHA-1, no extra iterations, empty salt"_
///   and zero flags. See [`Nsec3param::default()`].
///
/// [RFC 5155]: https://www.rfc-editor.org/rfc/rfc5155.html
/// [RFC 9077]: https://www.rfc-editor.org/rfc/rfc9077.html
/// [RFC 9276]: https://www.rfc-editor.org/rfc/rfc9276.html
// TODO: Add mutable iterator based variant.
// TODO: Get rid of &mut for GenerateNsec3Config.
pub fn generate_nsec3s<N, Octs, HashProvider, Sort>(
    records: RecordsIter<'_, N, ZoneRecordData<Octs, N>>,
    config: &mut GenerateNsec3Config<N, Octs, HashProvider, Sort>,
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
    HashProvider: Nsec3HashProvider<N, Octs>,
    Sort: Sorter,
{
    // TODO:
    //   - Handle name collisions? (see RFC 5155 7.1 Zone Signing)
    //   - RFC 5155 section 2 Backwards compatibility: Reject old algorithms?
    //     if not, map 3 to 6 and 5 to 7, or reject use of 3 and 5?

    // RFC 5155 7.1 step 2:
    //   "If Opt-Out is being used, set the Opt-Out bit to one."
    let mut nsec3_flags = config.params.flags();
    if matches!(
        config.opt_out,
        Nsec3OptOut::OptOut | Nsec3OptOut::OptOutFlagsOnly
    ) {
        // Set the Opt-Out flag.
        nsec3_flags |= 0b0000_0001;
    }

    // RFC 5155 7.1 step 5:
    //   "Sort the set of NSEC3 RRs into hash order." We store the NSEC3s as
    //    we create them and sort them afterwards.
    let mut nsec3s = Vec::<Record<N, Nsec3<Octs>>>::new();

    let mut ents = Vec::<N>::new();

    // The owner name of a zone cut if we currently are at or below one.
    let mut cut: Option<N> = None;

    // We also need the apex for the last NSEC3.
    let first_rr = records.first();
    let apex_owner = first_rr.owner().clone();
    let apex_label_count = apex_owner.iter_labels().count();

    let mut last_nent_stack: Vec<N> = vec![];
    let mut ttl = None;
    let mut nsec3param_ttl = None;

    for owner_rrs in records {
        trace!("Owner: {}", owner_rrs.owner());

        // If the owner is out of zone, we have moved out of our zone and are
        // done.
        if !owner_rrs.is_in_zone(&apex_owner) {
            debug!(
                "Stopping NSEC3 generation at out-of-zone owner {}",
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
        cut = if owner_rrs.is_zone_cut(&apex_owner) {
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
        if config.opt_out == Nsec3OptOut::OptOut && cut.is_some() && !has_ds {
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
                ttl = Some(min(soa_data.minimum(), soa_rr.ttl()));

                nsec3param_ttl = match config.nsec3param_ttl_mode {
                    Nsec3ParamTtlMode::Fixed(ttl) => Some(ttl),
                    Nsec3ParamTtlMode::Soa => Some(soa_rr.ttl()),
                    Nsec3ParamTtlMode::SoaMinimum => Some(soa_data.minimum()),
                };
            }
        }

        if ttl.is_none() {
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
            &mut config.hash_provider,
            config.params.hash_algorithm(),
            nsec3_flags,
            config.params.iterations(),
            config.params.salt(),
            &apex_owner,
            bitmap,
            ttl.unwrap(),
            false,
        )?;

        // Store the record by order of its owner name.
        nsec3s.push(rec);

        if let Some(last_nent) = last_nent {
            last_nent_stack.push(last_nent);
        }
        last_nent_stack.push(name.clone());
    }

    for name in ents {
        // Create the type bitmap, empty for an ENT NSEC3.
        let bitmap = RtypeBitmap::<Octs>::builder();

        debug!("Generating NSEC3 RR for ENT at {name}");
        // SAFETY: ttl will be set below before prev is set to Some.
        let rec = mk_nsec3(
            &name,
            &mut config.hash_provider,
            config.params.hash_algorithm(),
            nsec3_flags,
            config.params.iterations(),
            config.params.salt(),
            &apex_owner,
            bitmap,
            ttl.unwrap(),
            true,
        )?;

        // Store the record by order of its owner name.
        nsec3s.push(rec);
    }

    // RFC 5155 7.1 step 7:
    //   "In each NSEC3 RR, insert the next hashed owner name by using the
    //    value of the next NSEC3 RR in hash order.  The next hashed owner
    //    name of the last NSEC3 RR in the zone contains the value of the
    //    hashed owner name of the first NSEC3 RR in the hash order."
    trace!("Sorting NSEC3 RRs");
    let mut nsec3s = SortedRecords::<N, Nsec3<Octs>, Sort>::from(nsec3s);
    let num_nsec3s = nsec3s.len();
    for i in 1..=num_nsec3s {
        // TODO: Detect duplicate hashes.
        let next_i = if i == num_nsec3s { 0 } else { i };
        let cur_owner = nsec3s.as_ref()[next_i].owner();
        let name: Name<Octs> = cur_owner.try_to_name().unwrap();
        let label = name.iter_labels().next().unwrap();
        let owner_hash = if let Ok(hash_octets) =
            base32::decode_hex(&format!("{label}"))
        {
            OwnerHash::<Octs>::from_octets(hash_octets).unwrap()
        } else {
            OwnerHash::<Octs>::from_octets(name.as_octets().clone()).unwrap()
        };
        let last_rec = &mut nsec3s.as_mut_slice()[i - 1];
        let last_nsec3: &mut Nsec3<Octs> = last_rec.data_mut();
        last_nsec3.set_next_owner(owner_hash.clone());
    }

    let Some(nsec3param_ttl) = nsec3param_ttl else {
        return Err(SigningError::SoaRecordCouldNotBeDetermined);
    };

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

    Ok(Nsec3Records::new(nsec3s.into_inner(), nsec3param))
}

// unhashed_owner_name_is_ent is used to signal that the unhashed owner name
// is an empty non-terminal, as ldns-signzone for example outputs a comment
// for NSEC3 hashes that are for unhashed empty non-terminal owner names, and
// it can be quite costly to determine later given only a collection of
// records if the unhashed owner name is an ENT or not, so we pass this flag
// to the hash provider and it can record it if wanted.
#[allow(clippy::too_many_arguments)]
fn mk_nsec3<N, Octs, HashProvider>(
    name: &N,
    hash_provider: &mut HashProvider,
    alg: Nsec3HashAlg,
    flags: u8,
    iterations: u16,
    salt: &Nsec3Salt<Octs>,
    apex_owner: &N,
    bitmap: RtypeBitmapBuilder<<Octs as FromBuilder>::Builder>,
    ttl: Ttl,
    unhashed_owner_name_is_ent: bool,
) -> Result<Record<N, Nsec3<Octs>>, Nsec3HashError>
where
    N: ToName + From<Name<Octs>>,
    Octs: FromBuilder + Clone + Default,
    <Octs as FromBuilder>::Builder:
        EmptyBuilder + AsRef<[u8]> + AsMut<[u8]> + Truncate,
    HashProvider: Nsec3HashProvider<N, Octs>,
{
    let owner_name = hash_provider.get_or_create(
        apex_owner,
        name,
        unhashed_owner_name_is_ent,
    )?;

    // RFC 5155 7.1. step 2:
    //   "The Next Hashed Owner Name field is left blank for the moment."
    // Create a placeholder next owner, we'll fix it later.
    let placeholder_next_owner =
        OwnerHash::<Octs>::from_octets(Octs::default()).unwrap();

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
    alg: Nsec3HashAlg,
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
    alg: Nsec3HashAlg,
    iterations: u16,
    salt: &Nsec3Salt<SaltOcts>,
) -> Result<String, Nsec3HashError>
where
    N: ToName,
    SaltOcts: AsRef<[u8]>,
{
    let hash_octets: Vec<u8> =
        nsec3_hash(name, alg, iterations, salt)?.into_octets();
    Ok(base32::encode_string_hex(&hash_octets).to_ascii_lowercase())
}

//------------ Nsec3OptOut ---------------------------------------------------

/// The different types of NSEC3 opt-out.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum Nsec3OptOut {
    /// No opt-out. The opt-out flag of NSEC3 RRs will NOT be set and insecure
    /// delegations will be included in the NSEC3 chain.
    #[default]
    NoOptOut,

    /// Opt-out. The opt-out flag of NSEC3 RRs will be set and insecure
    /// delegations will NOT be included in the NSEC3 chain.
    OptOut,

    /// Opt-out (flags only). The opt-out flag of NSEC3 RRs will be set and
    /// insecure delegations will be included in the NSEC3 chain.
    OptOutFlagsOnly,
}

//------------ Nsec3HashProvider ---------------------------------------------

pub trait Nsec3HashProvider<N, Octs> {
    fn get_or_create(
        &mut self,
        apex_owner: &N,
        unhashed_owner_name: &N,
        unhashed_owner_name_is_ent: bool,
    ) -> Result<N, Nsec3HashError>;
}

pub struct OnDemandNsec3HashProvider<SaltOcts> {
    alg: Nsec3HashAlg,
    iterations: u16,
    salt: Nsec3Salt<SaltOcts>,
}

impl<SaltOcts> OnDemandNsec3HashProvider<SaltOcts> {
    pub fn new(
        alg: Nsec3HashAlg,
        iterations: u16,
        salt: Nsec3Salt<SaltOcts>,
    ) -> Self {
        Self {
            alg,
            iterations,
            salt,
        }
    }

    pub fn algorithm(&self) -> Nsec3HashAlg {
        self.alg
    }

    pub fn iterations(&self) -> u16 {
        self.iterations
    }

    pub fn salt(&self) -> &Nsec3Salt<SaltOcts> {
        &self.salt
    }
}

impl<N, Octs, SaltOcts> Nsec3HashProvider<N, Octs>
    for OnDemandNsec3HashProvider<SaltOcts>
where
    N: ToName + From<Name<Octs>>,
    Octs: FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    SaltOcts: AsRef<[u8]> + From<&'static [u8]>,
{
    fn get_or_create(
        &mut self,
        apex_owner: &N,
        unhashed_owner_name: &N,
        _unhashed_owner_name_is_ent: bool,
    ) -> Result<N, Nsec3HashError> {
        mk_hashed_nsec3_owner_name(
            unhashed_owner_name,
            self.alg,
            self.iterations,
            &self.salt,
            apex_owner,
        )
    }
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
/// approach used by some zone signers (e.g. PowerDNS [1]) is to use the SOA
/// MINIMUM as the TTL for the NSEC3PARAM.
///
/// An alternative approach used by some zone signers is to use a fixed TTL
/// for the NSEC3PARAM TTL, e.g. BIND, dnssec-signzone and OpenDNSSEC
/// reportedly use 0 [1] while ldns-signzone uses 3600 [2] (as does an example
/// in the BIND documentation [3]).
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
    use pretty_assertions::assert_eq;

    use crate::sign::records::SortedRecords;
    use crate::sign::test_util::*;
    use crate::zonetree::types::StoredRecordData;
    use crate::zonetree::StoredName;

    use super::*;

    #[test]
    fn soa_is_required() {
        let mut cfg = GenerateNsec3Config::default()
            .without_assuming_dnskeys_will_be_added();
        let mut records =
            SortedRecords::<StoredName, StoredRecordData>::default();
        records.insert(mk_a_rr("some_a.a.")).unwrap();
        let res = generate_nsec3s(records.owner_rrs(), &mut cfg);
        assert!(matches!(
            res,
            Err(SigningError::SoaRecordCouldNotBeDetermined)
        ));
    }

    #[test]
    fn multiple_soa_rrs_in_the_same_rrset_are_not_permitted() {
        let mut cfg = GenerateNsec3Config::default()
            .without_assuming_dnskeys_will_be_added();
        let mut records =
            SortedRecords::<StoredName, StoredRecordData>::default();
        records.insert(mk_soa_rr("a.", "b.", "c.")).unwrap();
        records.insert(mk_soa_rr("a.", "d.", "e.")).unwrap();
        let res = generate_nsec3s(records.owner_rrs(), &mut cfg);
        assert!(matches!(
            res,
            Err(SigningError::SoaRecordCouldNotBeDetermined)
        ));
    }

    #[test]
    fn records_outside_zone_are_ignored() {
        let mut cfg = GenerateNsec3Config::default()
            .without_assuming_dnskeys_will_be_added();
        let mut records =
            SortedRecords::<StoredName, StoredRecordData>::default();

        records.insert(mk_soa_rr("b.", "d.", "e.")).unwrap();
        records.insert(mk_a_rr("some_a.b.")).unwrap();
        records.insert(mk_soa_rr("a.", "b.", "c.")).unwrap();
        records.insert(mk_a_rr("some_a.a.")).unwrap();

        // First generate NSECs for the total record collection. As the
        // collection is sorted in canonical order the a zone preceeds the b
        // zone and NSECs should only be generated for the first zone in the
        // collection.
        let a_and_b_records = records.owner_rrs();

        let generated_records =
            generate_nsec3s(a_and_b_records, &mut cfg).unwrap();

        let mut expected_records = SortedRecords::default();
        expected_records.extend([
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

        // Now skip the a zone in the collection and generate NSECs for the
        // remaining records which should only generate NSECs for the b zone.
        let mut b_records_only = records.owner_rrs();
        b_records_only.skip_before(&mk_name("b."));

        let generated_records =
            generate_nsec3s(b_records_only, &mut cfg).unwrap();

        let mut expected_records = SortedRecords::default();
        expected_records.extend([
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
    }

    // #[test]
    // fn occluded_records_are_ignored() {
    //     let mut cfg = GenerateNsec3Config::default()
    //         .without_assuming_dnskeys_will_be_added();
    //     let mut records = SortedRecords::default();

    //     records.insert(mk_soa_rr("a.", "b.", "c.")).unwrap();
    //     records
    //         .insert(mk_ns_rr("some_ns.a.", "some_a.other.b."))
    //         .unwrap();
    //     records.insert(mk_a_rr("some_a.some_ns.a.")).unwrap();

    //     let generated_records =
    //         generate_nsec3s(records.owner_rrs(), &mut cfg).unwrap();

    //     // Implicit negative test.
    //     assert_eq!(
    //         generated_records.nsec3s,
    //         [
    //             mk_nsec3_rr(
    //                 "a.",
    //                 "a.",
    //                 "some_ns.a.",
    //                 "SOA RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             mk_nsec3_rr(
    //                 "a.",
    //                 "some_ns.a.",
    //                 "a.",
    //                 "NS RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //         ]
    //     );

    //     // Explicit negative test.
    //     assert!(!contains_owner(
    //         &generated_records.nsec3s,
    //         "some_a.some_ns.a.example."
    //     ));
    // }

    // #[test]
    // fn expect_dnskeys_at_the_apex() {
    //     let mut cfg = GenerateNsec3Config::default();

    //     let mut records =
    //         SortedRecords::<StoredName, StoredRecordData>::default();

    //     records.insert(mk_soa_rr("a.", "b.", "c.")).unwrap();
    //     records.insert(mk_a_rr("some_a.a.")).unwrap();

    //     let generated_records =
    //         generate_nsec3s(records.owner_rrs(), &mut cfg).unwrap();

    //     assert_eq!(
    //         generated_records.nsec3s,
    //         [
    //             mk_nsec3_rr(
    //                 "a.",
    //                 "a.",
    //                 "some_a.a.",
    //                 "SOA DNSKEY RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             mk_nsec3_rr(
    //                 "a.",
    //                 "some_a.a.",
    //                 "a.",
    //                 "A RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //         ]
    //     );
    // }

    // #[test]
    // fn rfc_4034_and_9077_compliant() {
    //     let mut cfg = GenerateNsec3Config::default()
    //         .without_assuming_dnskeys_will_be_added();

    //     // See https://datatracker.ietf.org/doc/html/rfc4035#appendix-A
    //     let zonefile = include_bytes!(
    //         "../../../test-data/zonefiles/rfc4035-appendix-A.zone"
    //     );

    //     let records = bytes_to_records(&zonefile[..]);
    //     let generated_records =
    //         generate_nsec3s(records.owner_rrs(), &mut cfg).unwrap();

    //     assert_eq!(generated_records.nsec3s.len(), 10);

    //     assert_eq!(
    //         generated_records.nsec3s,
    //         [
    //             mk_nsec3_rr(
    //                 "example.",
    //                 "example.",
    //                 "a.example",
    //                 "NS SOA MX RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             mk_nsec3_rr(
    //                 "example.",
    //                 "a.example.",
    //                 "ai.example",
    //                 "NS DS RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             mk_nsec3_rr(
    //                 "example.",
    //                 "ai.example.",
    //                 "b.example",
    //                 "A HINFO AAAA RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             mk_nsec3_rr(
    //                 "example.",
    //                 "b.example.",
    //                 "ns1.example",
    //                 "NS RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             mk_nsec3_rr(
    //                 "example.",
    //                 "ns1.example.",
    //                 "ns2.example",
    //                 "A RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             // The next record also validates that we comply with
    //             // https://datatracker.ietf.org/doc/html/rfc4034#section-6.2
    //             // 4.1.3. "Inclusion of Wildcard Names in NSEC RDATA" when
    //             // it says:
    //             //   "If a wildcard owner name appears in a zone, the wildcard
    //             //   label ("*") is treated as a literal symbol and is treated
    //             //   the same as any other owner name for the purposes of
    //             //   generating NSEC RRs. Wildcard owner names appear in the
    //             //   Next Domain Name field without any wildcard expansion.
    //             //   [RFC4035] describes the impact of wildcards on
    //             //   authenticated denial of existence."
    //             mk_nsec3_rr(
    //                 "example.",
    //                 "ns2.example.",
    //                 "*.w.example",
    //                 "A RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             mk_nsec3_rr(
    //                 "example.",
    //                 "*.w.example.",
    //                 "x.w.example",
    //                 "MX RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             mk_nsec3_rr(
    //                 "example.",
    //                 "x.w.example.",
    //                 "x.y.w.example",
    //                 "MX RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             mk_nsec3_rr(
    //                 "example.",
    //                 "x.y.w.example.",
    //                 "xx.example",
    //                 "MX RRSIG NSEC",
    //                 &mut cfg
    //             ),
    //             mk_nsec3_rr(
    //                 "example.",
    //                 "xx.example.",
    //                 "example",
    //                 "A HINFO AAAA RRSIG NSEC",
    //                 &mut cfg
    //             )
    //         ],
    //     );

    //     // TTLs are not compared by the eq check above so check them
    //     // explicitly now.
    //     //
    //     // RFC 9077 updated RFC 4034 (NSEC) and RFC 5155 (NSEC3) to say that
    //     // the "TTL of the NSEC(3) RR that is returned MUST be the lesser of
    //     // the MINIMUM field of the SOA record and the TTL of the SOA itself".
    //     //
    //     // So in our case that is min(1800, 3600) = 1800.
    //     for nsec3 in &generated_records.nsec3s {
    //         assert_eq!(nsec3.ttl(), Ttl::from_secs(1800));
    //     }

    //     // https://rfc-annotations.research.icann.org/rfc4035.html#section-2.3
    //     // 2.3.  Including NSEC RRs in a Zone
    //     //   ...
    //     //   "The type bitmap of every NSEC resource record in a signed zone
    //     //   MUST indicate the presence of both the NSEC record itself and its
    //     //   corresponding RRSIG record."
    //     for nsec3 in &generated_records.nsec3s {
    //         assert!(nsec3.data().types().contains(Rtype::NSEC));
    //         assert!(nsec3.data().types().contains(Rtype::RRSIG));
    //     }

    //     // https://rfc-annotations.research.icann.org/rfc4034.html#section-4.1.1
    //     // 4.1.2.  The Type Bit Maps Field
    //     //   "Bits representing pseudo-types MUST be clear, as they do not
    //     //    appear in zone data."
    //     //
    //     // There is nothing to test for this as it is excluded at the Rust
    //     // type system level by the generate_nsecs() function taking
    //     // ZoneRecordData (which excludes pseudo record types) as input rather
    //     // than AllRecordData (which includes pseudo record types).

    //     // https://rfc-annotations.research.icann.org/rfc4034.html#section-4.1.1
    //     // 4.1.2.  The Type Bit Maps Field
    //     //   ...
    //     //   "A zone MUST NOT include an NSEC RR for any domain name that only
    //     //    holds glue records."
    //     //
    //     // The "rfc4035-appendix-A.zone" file that we load contains glue A
    //     // records for ns1.example, ns1.a.example, ns1.b.example, ns2.example
    //     // and ns2.a.example all with no other record types at that name. We
    //     // can verify that an NSEC RR was NOT created for those that are not
    //     // within the example zone as we are not authoritative for thos.
    //     assert!(contains_owner(&generated_records.nsec3s, "ns1.example."));
    //     assert!(!contains_owner(&generated_records.nsec3s, "ns1.a.example."));
    //     assert!(!contains_owner(&generated_records.nsec3s, "ns1.b.example."));
    //     assert!(contains_owner(&generated_records.nsec3s, "ns2.example."));
    //     assert!(!contains_owner(&generated_records.nsec3s, "ns2.a.example."));

    //     // https://rfc-annotations.research.icann.org/rfc4035.html#section-2.3
    //     // 2.3.  Including NSEC RRs in a Zone
    //     //   ...
    //     //  "The bitmap for the NSEC RR at a delegation point requires special
    //     //  attention.  Bits corresponding to the delegation NS RRset and any
    //     //  RRsets for which the parent zone has authoritative data MUST be
    //     //  set; bits corresponding to any non-NS RRset for which the parent
    //     //  is not authoritative MUST be clear."
    //     //
    //     // The "rfc4035-appendix-A.zone" file that we load has been modified
    //     // compared to the original to include a glue A record at b.example.
    //     // We can verify that an NSEC RR was NOT created for that name.
    //     let name = mk_name("b.example.");
    //     let nsec3 = generated_records
    //         .nsec3s
    //         .iter()
    //         .find(|rr| rr.owner() == &name)
    //         .unwrap();
    //     assert!(nsec3.data().types().contains(Rtype::NSEC));
    //     assert!(nsec3.data().types().contains(Rtype::RRSIG));
    //     assert!(!nsec3.data().types().contains(Rtype::A));
    // }
}
