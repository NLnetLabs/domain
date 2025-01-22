//! DNSSEC RRSIG generation.
use core::convert::{AsRef, From};
use core::fmt::Display;
use core::marker::{PhantomData, Send};

use std::boxed::Box;
use std::string::ToString;
use std::vec::Vec;

use log::Level;
use octseq::builder::FromBuilder;
use octseq::{OctetsFrom, OctetsInto};
use tracing::{debug, trace};

use super::strategy::DefaultSigningKeyUsageStrategy;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::ToName;
use crate::base::rdata::{ComposeRecordData, RecordData};
use crate::base::record::Record;
use crate::base::Name;
use crate::rdata::dnssec::ProtoRrsig;
use crate::rdata::{Dnskey, ZoneRecordData};
use crate::sign::error::SigningError;
use crate::sign::keys::keymeta::DesignatedSigningKey;
use crate::sign::keys::signingkey::SigningKey;
use crate::sign::records::{
    DefaultSorter, RecordsIter, Rrset, SortedRecords, Sorter,
};
use crate::sign::signatures::strategy::SigningKeyUsageStrategy;
use crate::sign::traits::SignRaw;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GenerateRrsigConfig<'a, N, KeyStrat, Sort> {
    pub add_used_dnskeys: bool,

    pub zone_apex: Option<&'a N>,

    _phantom: PhantomData<(KeyStrat, Sort)>,
}

impl<'a, N, KeyStrat, Sort> GenerateRrsigConfig<'a, N, KeyStrat, Sort> {
    /// Like [`Self::default()`] but gives control over the SigningKeyStrategy
    /// and Sorter used.
    pub fn new() -> Self {
        Self {
            add_used_dnskeys: true,
            zone_apex: None,
            _phantom: Default::default(),
        }
    }

    pub fn without_adding_used_dns_keys(mut self) -> Self {
        self.add_used_dnskeys = false;
        self
    }

    pub fn with_zone_apex(mut self, zone_apex: &'a N) -> Self {
        self.zone_apex = Some(zone_apex);
        self
    }
}

impl<N> Default
    for GenerateRrsigConfig<
        '_,
        N,
        DefaultSigningKeyUsageStrategy,
        DefaultSorter,
    >
{
    fn default() -> Self {
        Self {
            add_used_dnskeys: true,
            zone_apex: None,
            _phantom: Default::default(),
        }
    }
}

/// Generate RRSIG RRs for a collection of zone records.
///
/// Returns the collection of RRSIG and (optionally) DNSKEY RRs that must be
/// added to the given records as part of DNSSEC zone signing.
///
/// The given records MUST be sorted according to [`CanonicalOrd`].
///
/// Any existing RRSIG records will be ignored.
// TODO: Add mutable iterator based variant.
#[allow(clippy::type_complexity)]
pub fn generate_rrsigs<N, Octs, DSK, Inner, KeyStrat, Sort>(
    records: RecordsIter<'_, N, ZoneRecordData<Octs, N>>,
    keys: &[DSK],
    config: &GenerateRrsigConfig<'_, N, KeyStrat, Sort>,
) -> Result<Vec<Record<N, ZoneRecordData<Octs, N>>>, SigningError>
where
    DSK: DesignatedSigningKey<Octs, Inner>,
    Inner: SignRaw,
    KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
    N: ToName
        + PartialEq
        + Clone
        + Display
        + Send
        + CanonicalOrd
        + From<Name<Octs>>,
    Octs: AsRef<[u8]>
        + From<Box<[u8]>>
        + Send
        + OctetsFrom<Vec<u8>>
        + Clone
        + FromBuilder
        + From<&'static [u8]>,
    Sort: Sorter,
{
    debug!(
        "Signer settings: add_used_dnskeys={}, strategy: {}",
        config.add_used_dnskeys,
        KeyStrat::NAME
    );

    // Peek at the records because we need to process the first owner records
    // differently if they represent the apex of a zone (i.e. contain the SOA
    // record), otherwise we process the first owner records in the same loop
    // as the rest of the records beneath the apex.
    let mut records = records.peekable();

    let first_rrs = records.peek();

    let Some(first_rrs) = first_rrs else {
        // No records were provided. As we are able to generate RRSIGs for
        // partial zones this is a special case of a partial zone, an empty
        // input, for which there is nothing to do.
        return Ok(vec![]);
    };

    let first_owner = first_rrs.owner().clone();

    // If no apex was supplied, assume that because the input should be
    // canonically ordered that the first record is part of the apex RRSET.
    // Otherwise, check if the first record matches the given apex, if not
    // that means that the input starts beneath the apex.
    let (zone_apex, at_apex) = match config.zone_apex {
        Some(zone_apex) => (zone_apex, first_rrs.owner() == zone_apex),
        None => (&first_owner, true),
    };

    // https://www.rfc-editor.org/rfc/rfc1034#section-6.1
    // 6.1. C.ISI.EDU name server
    //   ...
    //   "Since the class of all RRs in a zone must be the same..."
    //
    // We can therefore assume that the class to use for new DNSKEY records
    // when we add them will be the same as the class of the first resource
    // record in the zone.
    let zone_class = first_rrs.class();

    // Determine which keys to use for what. Work with indices because
    // SigningKey doesn't impl PartialEq so we cannot use a HashSet to make a
    // unique set of them.

    if keys.is_empty() {
        return Err(SigningError::NoKeysProvided);
    }

    let mut dnskey_signing_key_idxs =
        KeyStrat::select_signing_keys_for_rtype(keys, Some(Rtype::DNSKEY));
    if dnskey_signing_key_idxs.is_empty() {
        return Err(SigningError::NoSuitableKeysFound);
    }
    dnskey_signing_key_idxs.sort();
    dnskey_signing_key_idxs.dedup();

    let mut non_dnskey_signing_key_idxs =
        KeyStrat::select_signing_keys_for_rtype(keys, None);
    if non_dnskey_signing_key_idxs.is_empty() {
        return Err(SigningError::NoSuitableKeysFound);
    }
    non_dnskey_signing_key_idxs.sort();
    non_dnskey_signing_key_idxs.dedup();

    let mut keys_in_use_idxs: Vec<_> = non_dnskey_signing_key_idxs
        .iter()
        .chain(dnskey_signing_key_idxs.iter())
        .collect();
    keys_in_use_idxs.sort();
    keys_in_use_idxs.dedup();

    if log::log_enabled!(Level::Debug) {
        log_keys_in_use(
            keys,
            &dnskey_signing_key_idxs,
            &non_dnskey_signing_key_idxs,
            &keys_in_use_idxs,
        );
    }

    let mut res: Vec<Record<N, ZoneRecordData<Octs, N>>> = Vec::new();
    let mut reusable_scratch = Vec::new();
    let mut cut: Option<N> = None;

    if at_apex {
        // Sign the apex, if it contains a SOA record, otherwise it's just the
        // first in a collection of sorted records but not the apex of a zone.
        generate_apex_rrsigs(
            keys,
            config,
            &mut records,
            zone_apex,
            zone_class,
            &dnskey_signing_key_idxs,
            &non_dnskey_signing_key_idxs,
            &keys_in_use_idxs,
            &mut res,
            &mut reusable_scratch,
        )?;
    }

    // For all records
    for owner_rrs in records {
        // If the owner is out of zone, we have moved out of our zone and are
        // done.
        if !owner_rrs.is_in_zone(zone_apex) {
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
        cut = if owner_rrs.is_zone_cut(zone_apex) {
            Some(name.clone())
        } else {
            None
        };

        for rrset in owner_rrs.rrsets() {
            if cut.is_some() {
                // If we are at a zone cut, we only sign DS and NSEC records.
                // NS records we must not sign and everything else shouldn’t
                // be here, really.
                if rrset.rtype() != Rtype::DS && rrset.rtype() != Rtype::NSEC
                {
                    continue;
                }
            } else {
                // Otherwise we only ignore RRSIGs.
                if rrset.rtype() == Rtype::RRSIG {
                    continue;
                }
            }

            for key in
                non_dnskey_signing_key_idxs.iter().map(|&idx| &keys[idx])
            {
                let rrsig_rr = sign_rrset_in(
                    key,
                    &rrset,
                    zone_apex,
                    &mut reusable_scratch,
                )?;
                res.push(rrsig_rr);
                debug!(
                    "Signed {} RRSET at {} with keytag {}",
                    rrset.rtype(),
                    rrset.owner(),
                    key.public_key().key_tag()
                );
            }
        }
    }

    debug!("Returning {} records from signature generation", res.len());

    Ok(res)
}

fn log_keys_in_use<Octs, DSK, Inner>(
    keys: &[DSK],
    dnskey_signing_key_idxs: &[usize],
    non_dnskey_signing_key_idxs: &[usize],
    keys_in_use_idxs: &[&usize],
) where
    DSK: DesignatedSigningKey<Octs, Inner>,
    Inner: SignRaw,
    Octs: AsRef<[u8]>,
{
    fn debug_key<Octs: AsRef<[u8]>, Inner: SignRaw>(
        prefix: &str,
        key: &SigningKey<Octs, Inner>,
    ) {
        debug!(
            "{prefix} with algorithm {}, owner={}, flags={} (SEP={}, ZSK={}) and key tag={}",
            key.algorithm()
                .to_mnemonic_str()
                .map(|alg| format!("{alg} ({})", key.algorithm()))
                .unwrap_or_else(|| key.algorithm().to_string()),
            key.owner(),
            key.flags(),
            key.is_secure_entry_point(),
            key.is_zone_signing_key(),
            key.public_key().key_tag(),
        )
    }

    let num_keys = keys_in_use_idxs.len();
    debug!(
        "Signing with {} {}:",
        num_keys,
        if num_keys == 1 { "key" } else { "keys" }
    );

    for idx in keys_in_use_idxs {
        let key = &keys[**idx];
        let is_dnskey_signing_key = dnskey_signing_key_idxs.contains(idx);
        let is_non_dnskey_signing_key =
            non_dnskey_signing_key_idxs.contains(idx);
        let usage = if is_dnskey_signing_key && is_non_dnskey_signing_key {
            "CSK"
        } else if is_dnskey_signing_key {
            "KSK"
        } else if is_non_dnskey_signing_key {
            "ZSK"
        } else {
            "Unused"
        };
        debug_key(&format!("Key[{idx}]: {usage}"), key);
    }
}

#[allow(clippy::too_many_arguments)]
fn generate_apex_rrsigs<N, Octs, DSK, Inner, KeyStrat, Sort>(
    keys: &[DSK],
    config: &GenerateRrsigConfig<'_, N, KeyStrat, Sort>,
    records: &mut core::iter::Peekable<
        RecordsIter<'_, N, ZoneRecordData<Octs, N>>,
    >,
    zone_apex: &N,
    zone_class: crate::base::iana::Class,
    dnskey_signing_key_idxs: &[usize],
    non_dnskey_signing_key_idxs: &[usize],
    keys_in_use_idxs: &[&usize],
    generated_rrs: &mut Vec<Record<N, ZoneRecordData<Octs, N>>>,
    reusable_scratch: &mut Vec<u8>,
) -> Result<(), SigningError>
where
    DSK: DesignatedSigningKey<Octs, Inner>,
    Inner: SignRaw,
    KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
    N: ToName
        + PartialEq
        + Clone
        + Display
        + Send
        + CanonicalOrd
        + From<Name<Octs>>,
    Octs: AsRef<[u8]>
        + From<Box<[u8]>>
        + Send
        + OctetsFrom<Vec<u8>>
        + Clone
        + FromBuilder
        + From<&'static [u8]>,
    Sort: Sorter,
{
    let Some(apex_owner_rrs) = records.peek() else {
        // Nothing to do.
        return Ok(());
    };

    let apex_rrsets = apex_owner_rrs
        .rrsets()
        .filter(|rrset| rrset.rtype() != Rtype::RRSIG);

    let soa_rrs = apex_owner_rrs
        .rrsets()
        .find(|rrset| rrset.rtype() == Rtype::SOA);

    let Some(soa_rrs) = soa_rrs else {
        // Nothing to do, no SOA RR found.
        return Ok(());
    };

    if soa_rrs.len() > 1 {
        // Too many SOA RRs found.
        return Err(SigningError::SoaRecordCouldNotBeDetermined);
    }

    // Get the SOA RR.
    let soa_rr = soa_rrs.first();

    // Find any existing DNSKEY RRs.
    let apex_dnskey_rrset = apex_owner_rrs
        .rrsets()
        .find(|rrset| rrset.rtype() == Rtype::DNSKEY);

    // Determine the TTL of any existing DNSKEY RRSET and use that as the TTL
    // for DNSKEY RRs that we add. If none, then fall back to the SOA TTL.
    //
    // https://datatracker.ietf.org/doc/html/rfc2181#section-5.2
    // 5.2. TTLs of RRs in an RRSet
    //   "Consequently the use of differing TTLs in an RRSet is hereby
    //    deprecated, the TTLs of all RRs in an RRSet must be the same."
    //
    // Note that while RFC 1033 says:
    // RESOURCE RECORDS
    //   "If you leave the TTL field blank it will default to the minimum time
    //    specified in the SOA record (described later)."
    //
    // That RFC pre-dates RFC 1034, and neither dnssec-signzone nor
    // ldns-signzone use the SOA MINIMUM as a default TTL, rather they use the
    // TTL of the SOA RR as the default and so we will do the same.
    let dnskey_rrset_ttl = if let Some(rrset) = &apex_dnskey_rrset {
        rrset.ttl()
    } else {
        soa_rr.ttl()
    };

    // Generate or extend the DNSKEY RRSET with the keys that we will sign
    // apex DNSKEY RRs and zone RRs with.
    let mut augmented_apex_dnskey_rrs = if let Some(rrset) = apex_dnskey_rrset
    {
        SortedRecords::<_, _, Sort>::from_iter(rrset.iter().cloned())
    } else {
        SortedRecords::<_, _, Sort>::new()
    };

    // https://datatracker.ietf.org/doc/html/rfc4035#section-2.1 2.1.
    // Including DNSKEY RRs in a Zone. .. "For each private key used to create
    //   RRSIG RRs in a zone, the zone SHOULD include a zone DNSKEY RR
    //   containing the corresponding public key"
    //
    // We iterate over the DNSKEY RRs at the apex in the zone converting them
    // into the correct output octets form, and if any keys we are going to
    // sign the zone with do not exist we add them.

    for public_key in
        keys_in_use_idxs.iter().map(|&&idx| keys[idx].public_key())
    {
        let dnskey = public_key.to_dnskey();

        let signing_key_dnskey_rr = Record::new(
            zone_apex.clone(),
            zone_class,
            dnskey_rrset_ttl,
            Dnskey::convert(dnskey.clone()).into(),
        );

        // Add the DNSKEY RR to the set of DNSKEY RRs to create RRSIGs for.
        let is_new_dnskey = augmented_apex_dnskey_rrs
            .insert(signing_key_dnskey_rr)
            .is_ok();

        if config.add_used_dnskeys && is_new_dnskey {
            // Add the DNSKEY RR to the set of new RRs to output for the zone.
            generated_rrs.push(Record::new(
                zone_apex.clone(),
                zone_class,
                dnskey_rrset_ttl,
                Dnskey::convert(dnskey).into(),
            ));
        }
    }

    let augmented_apex_dnskey_rrset = Rrset::new(&augmented_apex_dnskey_rrs);

    // Sign the apex RRSETs in canonical order.
    for rrset in apex_rrsets
        .filter(|rrset| rrset.rtype() != Rtype::DNSKEY)
        .chain(std::iter::once(augmented_apex_dnskey_rrset))
    {
        // For the DNSKEY RRSET, use signing keys chosen for that purpose and
        // sign the augmented set of DNSKEY RRs that we have generated rather
        // than the original set in the zonefile.
        let signing_key_idxs = if rrset.rtype() == Rtype::DNSKEY {
            dnskey_signing_key_idxs
        } else {
            non_dnskey_signing_key_idxs
        };

        for key in signing_key_idxs.iter().map(|&idx| &keys[idx]) {
            let rrsig_rr =
                sign_rrset_in(key, &rrset, zone_apex, reusable_scratch)?;
            generated_rrs.push(rrsig_rr);
            trace!(
                "Signed {} RRs in RRSET {} at the zone apex with keytag {}",
                rrset.iter().len(),
                rrset.rtype(),
                key.public_key().key_tag()
            );
        }
    }

    // Move the iterator past the processed apex owner RRs.
    let _ = records.next();

    Ok(())
}

/// Generate `RRSIG` records for a given RRset.
///
/// See [`sign_rrset_in()`].
///
/// If signing multiple RRsets, calling [`sign_rrset_in()`] directly will be
/// more efficient as you can allocate the scratch buffer once and re-use it
/// across multiple calls.
pub fn sign_rrset<N, D, Octs, Inner>(
    key: &SigningKey<Octs, Inner>,
    rrset: &Rrset<'_, N, D>,
    apex_owner: &N,
) -> Result<Record<N, ZoneRecordData<Octs, N>>, SigningError>
where
    N: ToName + Clone + Send,
    D: RecordData
        + ComposeRecordData
        + From<Dnskey<Octs>>
        + CanonicalOrd
        + Send,
    Inner: SignRaw,
    Octs: AsRef<[u8]> + OctetsFrom<Vec<u8>>,
{
    sign_rrset_in(key, rrset, apex_owner, &mut vec![])
}

/// Generate `RRSIG` records for a given RRset.
///
/// This function generates an `RRSIG` record for the given RRset based on the
/// given signing key, according to the rules defined in [RFC 4034 section 3]
/// _"The RRSIG Resource Record"_, [RFC 4035 section 2.2] _"Including RRSIG
/// RRs in a Zone"_ and [RFC 6840 section 5.11] _"Mandatory Algorithm Rules"_.
///
/// No checks are done on the given signing key, any key with any algorithm,
/// apex owner and flags may be used to sign the given RRset.
///
/// When signing multiple RRsets by calling this function multiple times, the
/// `scratch` buffer parameter can be allocated once and re-used for each call
/// to avoid needing to allocate the buffer for each call.
///
/// [RFC 4034 section 3]:
///     https://www.rfc-editor.org/rfc/rfc4034.html#section-3
/// [RFC 4035 section 2.2]:
///     https://www.rfc-editor.org/rfc/rfc4035.html#section-2.2
/// [RFC 6840 section 5.11]:
///     https://www.rfc-editor.org/rfc/rfc6840.html#section-5.11
pub fn sign_rrset_in<N, D, Octs, Inner>(
    key: &SigningKey<Octs, Inner>,
    rrset: &Rrset<'_, N, D>,
    apex_owner: &N,
    scratch: &mut Vec<u8>,
) -> Result<Record<N, ZoneRecordData<Octs, N>>, SigningError>
where
    N: ToName + Clone + Send,
    D: RecordData
        + ComposeRecordData
        + From<Dnskey<Octs>>
        + CanonicalOrd
        + Send,
    Inner: SignRaw,
    Octs: AsRef<[u8]> + OctetsFrom<Vec<u8>>,
{
    // RFC 4035
    // 2.2.  Including RRSIG RRs in a Zone
    //   ...
    //   "An RRSIG RR itself MUST NOT be signed"
    if rrset.rtype() == Rtype::RRSIG {
        return Err(SigningError::RrsigRrsMustNotBeSigned);
    }

    let (inception, expiration) = key
        .signature_validity_period()
        .ok_or(SigningError::NoSignatureValidityPeriodProvided)?
        .into_inner();

    if expiration < inception {
        return Err(SigningError::InvalidSignatureValidityPeriod(
            inception, expiration,
        ));
    }

    // RFC 4034
    // 3.  The RRSIG Resource Record
    //   "The TTL value of an RRSIG RR MUST match the TTL value of the RRset
    //    it covers.  This is an exception to the [RFC2181] rules for TTL
    //    values of individual RRs within a RRset: individual RRSIG RRs with
    //    the same owner name will have different TTL values if the RRsets
    //    they cover have different TTL values."
    let rrsig = ProtoRrsig::new(
        rrset.rtype(),
        key.algorithm(),
        rrset.owner().rrsig_label_count(),
        rrset.ttl(),
        expiration,
        inception,
        key.public_key().key_tag(),
        // The fns provided by `ToName` state in their RustDoc that they
        // "Converts the name into a single, uncompressed name" which matches
        // the RFC 4034 section 3.1.7 requirement that "A sender MUST NOT use
        // DNS name compression on the Signer's Name field when transmitting a
        // RRSIG RR.".
        //
        // TODO: However, is this inefficient? The RFC requires it to be
        // SENT uncompressed, but doesn't ban storing it in compressed from?
        //
        // We don't need to make sure here that the signer name is in
        // canonical form as required by RFC 4034 as the call to
        // `compose_canonical()` below will take care of that.
        apex_owner.clone(),
    );

    scratch.clear();

    rrsig.compose_canonical(scratch).unwrap();
    for record in rrset.iter() {
        record.compose_canonical(scratch).unwrap();
    }
    let signature = key.raw_secret_key().sign_raw(&*scratch)?;
    let signature = signature.as_ref().to_vec();
    let Ok(signature) = signature.try_octets_into() else {
        return Err(SigningError::OutOfMemory);
    };

    let rrsig = rrsig.into_rrsig(signature).expect("long signature");

    // RFC 4034
    // 3.1.3.  The Labels Field
    //   ...
    //   "The value of the Labels field MUST be less than or equal to the
    //    number of labels in the RRSIG owner name."
    debug_assert!(
        (rrsig.labels() as usize) < rrset.owner().iter_labels().count()
    );

    Ok(Record::new(
        rrset.owner().clone(),
        rrset.class(),
        rrset.ttl(),
        ZoneRecordData::Rrsig(rrsig),
    ))
}

#[cfg(test)]
mod tests {
    use core::ops::RangeInclusive;

    use bytes::Bytes;
    use pretty_assertions::assert_eq;

    use crate::base::iana::{Class, SecAlg};
    use crate::base::Serial;
    use crate::rdata::dnssec::Timestamp;
    use crate::sign::crypto::common::KeyPair;
    use crate::sign::error::SignError;
    use crate::sign::keys::keymeta::IntendedKeyPurpose;
    use crate::sign::keys::DnssecSigningKey;
    use crate::sign::test_util::*;
    use crate::sign::{test_util, PublicKeyBytes, Signature};
    use crate::zonetree::types::StoredRecordData;
    use crate::zonetree::{StoredName, StoredRecord};

    use super::*;

    const TEST_INCEPTION: u32 = 0;
    const TEST_EXPIRATION: u32 = 100;

    #[test]
    fn sign_rrset_adheres_to_rules_in_rfc_4034_and_rfc_4035() {
        let apex_owner = Name::root();
        let key = SigningKey::new(apex_owner.clone(), 0, TestKey);
        let key = key.with_validity(Timestamp::from(0), Timestamp::from(0));

        // RFC 4034
        // 3.1.3.  The Labels Field
        //   ...
        //   "For example, "www.example.com." has a Labels field value of 3"
        // We can use any class as RRSIGs are class independent.
        let records = [mk_a_rr("www.example.com.")];
        let rrset = Rrset::new(&records);

        let rrsig_rr = sign_rrset(&key, &rrset, &apex_owner).unwrap();

        let ZoneRecordData::Rrsig(rrsig) = rrsig_rr.data() else {
            unreachable!();
        };

        // RFC 4035
        // 2.2.  Including RRSIG RRs in a Zone
        //   "For each authoritative RRset in a signed zone, there MUST be at
        //    least one RRSIG record that meets the following requirements:
        //
        //    o  The RRSIG owner name is equal to the RRset owner name.
        assert_eq!(rrsig_rr.owner(), rrset.owner());
        //
        //    o  The RRSIG class is equal to the RRset class.
        assert_eq!(rrsig_rr.class(), rrset.class());
        //
        //    o  The RRSIG Type Covered field is equal to the RRset type.
        //
        assert_eq!(rrsig.type_covered(), rrset.rtype());
        //    o  The RRSIG Original TTL field is equal to the TTL of the
        //       RRset.
        //
        assert_eq!(rrsig.original_ttl(), rrset.ttl());
        //    o  The RRSIG RR's TTL is equal to the TTL of the RRset.
        //
        assert_eq!(rrsig_rr.ttl(), rrset.ttl());
        //    o  The RRSIG Labels field is equal to the number of labels in
        //       the RRset owner name, not counting the null root label and
        //       not counting the leftmost label if it is a wildcard.
        assert_eq!(rrsig.labels(), 3);
        //    o  The RRSIG Signer's Name field is equal to the name of the
        //       zone containing the RRset.
        //
        assert_eq!(rrsig.signer_name(), &apex_owner);
        //    o  The RRSIG Algorithm, Signer's Name, and Key Tag fields
        //       identify a zone key DNSKEY record at the zone apex."
        // ^^^ This is outside the control of the rrset_sign() function.

        // RFC 4034
        // 3.1.3.  The Labels Field
        //   ...
        //   "The value of the Labels field MUST be less than or equal to the
        //    number of labels in the RRSIG owner name."
        assert!((rrsig.labels() as usize) < rrset.owner().label_count());
    }

    #[test]
    fn sign_rrset_with_wildcard() {
        let apex_owner = Name::root();
        let key = SigningKey::new(apex_owner.clone(), 0, TestKey);
        let key = key.with_validity(Timestamp::from(0), Timestamp::from(0));

        // RFC 4034
        // 3.1.3.  The Labels Field
        //   ...
        //   ""*.example.com." has a Labels field value of 2"
        let records = [mk_a_rr("*.example.com.")];
        let rrset = Rrset::new(&records);

        let rrsig_rr = sign_rrset(&key, &rrset, &apex_owner).unwrap();

        let ZoneRecordData::Rrsig(rrsig) = rrsig_rr.data() else {
            unreachable!();
        };

        assert_eq!(rrsig.labels(), 2);
    }

    #[test]
    fn sign_rrset_must_not_sign_rrsigs() {
        // RFC 4035
        // 2.2.  Including RRSIG RRs in a Zone
        //   ...
        //   "An RRSIG RR itself MUST NOT be signed"

        let apex_owner = Name::root();
        let key = SigningKey::new(apex_owner.clone(), 0, TestKey);
        let key = key.with_validity(Timestamp::from(0), Timestamp::from(0));
        let dnskey = key.public_key().to_dnskey().convert();

        let records = [mk_rrsig_rr("any.", Rtype::A, 1, ".", &dnskey)];
        let rrset = Rrset::new(&records);

        let res = sign_rrset(&key, &rrset, &apex_owner);
        assert!(matches!(res, Err(SigningError::RrsigRrsMustNotBeSigned)));
    }

    #[test]
    fn sign_rrset_check_validity_period_handling() {
        // RFC 4034
        // 3.1.5.  Signature Expiration and Inception Fields
        //   ...
        //   "The Signature Expiration and Inception field values specify a
        //    date and time in the form of a 32-bit unsigned number of seconds
        //    elapsed since 1 January 1970 00:00:00 UTC, ignoring leap
        //    seconds, in network byte order.  The longest interval that can
        //    be expressed by this format without wrapping is approximately
        //    136 years.  An RRSIG RR can have an Expiration field value that
        //    is numerically smaller than the Inception field value if the
        //    expiration field value is near the 32-bit wrap-around point or
        //    if the signature is long lived.  Because of this, all
        //    comparisons involving these fields MUST use "Serial number
        //    arithmetic", as defined in [RFC1982].  As a direct consequence,
        //    the values contained in these fields cannot refer to dates more
        //    than 68 years in either the past or the future."

        let apex_owner = Name::root();
        let key = SigningKey::new(apex_owner.clone(), 0, TestKey);

        let records = [mk_a_rr("any.")];
        let rrset = Rrset::new(&records);

        fn calc_timestamps(
            start: u32,
            duration: u32,
        ) -> (Timestamp, Timestamp) {
            let start_serial = Serial::from(start);
            let end = start_serial.add(duration).into_int();
            (Timestamp::from(start), Timestamp::from(end))
        }

        // Good: Expiration > Inception.
        let (inception, expiration) = calc_timestamps(5, 5);
        let key = key.with_validity(inception, expiration);
        sign_rrset(&key, &rrset, &apex_owner).unwrap();

        // Good: Expiration == Inception.
        let (inception, expiration) = calc_timestamps(10, 0);
        let key = key.with_validity(inception, expiration);
        sign_rrset(&key, &rrset, &apex_owner).unwrap();

        // Bad: Expiration < Inception.
        let (expiration, inception) = calc_timestamps(5, 10);
        let key = key.with_validity(inception, expiration);
        let res = sign_rrset(&key, &rrset, &apex_owner);
        assert!(matches!(
            res,
            Err(SigningError::InvalidSignatureValidityPeriod(_, _))
        ));

        // Good: Expiration > Inception with Expiration near wrap around
        // point.
        let (inception, expiration) = calc_timestamps(u32::MAX - 10, 10);
        let key = key.with_validity(inception, expiration);
        sign_rrset(&key, &rrset, &apex_owner).unwrap();

        // Good: Expiration > Inception with Inception near wrap around point.
        let (inception, expiration) = calc_timestamps(0, 10);
        let key = key.with_validity(inception, expiration);
        sign_rrset(&key, &rrset, &apex_owner).unwrap();

        // Good: Expiration > Inception with Exception crossing the wrap
        // around point.
        let (inception, expiration) = calc_timestamps(u32::MAX - 10, 20);
        let key = key.with_validity(inception, expiration);
        sign_rrset(&key, &rrset, &apex_owner).unwrap();

        // Good: Expiration - Inception == 68 years.
        let sixty_eight_years_in_secs = 68 * 365 * 24 * 60 * 60;
        let (inception, expiration) =
            calc_timestamps(0, sixty_eight_years_in_secs);
        let key = key.with_validity(inception, expiration);
        sign_rrset(&key, &rrset, &apex_owner).unwrap();

        // Bad: Expiration - Inception > 68 years.
        //
        // I add a rather large amount (A year) because it's unclear where the
        // boundary is from the approximate text in the quoted RFC. I think
        // it's at 2^31 - 1 so from that you can see how much we need to add
        // to cross the boundary:
        //
        // ```
        //   68 years = 68 * 365 * 24 * 60 * 60 = 2144448000
        //   2^31 - 1 =                           2147483647
        //   69 years = 69 * 365 * 24 * 60 * 60 = 2175984000
        // ```
        //
        // But as the RFC refers to "dates more than 68 years" a value of 69
        // years is fine to test with.
        let sixty_eight_years_in_secs = 68 * 365 * 24 * 60 * 60;
        let one_year_in_secs = 365 * 24 * 60 * 60;

        // We can't use calc_timestamps() here because the underlying call to
        // Serial::add() panics if the value to add is > 2^31 - 1.
        //
        //   calc_timestamps(0, sixty_eight_years_in_secs + one_year_in_secs);
        //
        // But Timestamp doesn't care, we can construct those just fine.
        // However when sign_rrset() compares the Timestamp inception and
        // expiration values it will fail because the PartialOrd impl is
        // implemented in terms of Serial which detects the wrap around.
        //
        // I think this is all good because RFC 4034 doesn't prevent creation
        // and storage of an arbitrary 32-bit unsigned number of seconds as
        // the inception or expiration value, it only mandates that "all
        // comparisons involving these fields MUST use "Serial number
        // arithmetic", as defined in [RFC1982]"
        let (inception, expiration) = (
            Timestamp::from(0),
            Timestamp::from(sixty_eight_years_in_secs + one_year_in_secs),
        );
        let key = key.with_validity(inception, expiration);
        let res = sign_rrset(&key, &rrset, &apex_owner);
        assert!(matches!(
            res,
            Err(SigningError::InvalidSignatureValidityPeriod(_, _))
        ));
    }

    #[test]
    fn generate_rrsigs_without_keys_should_succeed_for_empty_zone() {
        let records: [Record<StoredName, StoredRecordData>; 0] = [];
        let no_keys: [DnssecSigningKey<Bytes, KeyPair>; 0] = [];

        generate_rrsigs(
            RecordsIter::new(&records),
            &no_keys,
            &GenerateRrsigConfig::default(),
        )
        .unwrap();
    }

    #[test]
    fn generate_rrsigs_without_keys_should_fail_for_non_empty_zone() {
        let records = [mk_a_rr("example.")];
        let no_keys: [DnssecSigningKey<Bytes, KeyPair>; 0] = [];

        let res = generate_rrsigs(
            RecordsIter::new(&records),
            &no_keys,
            &GenerateRrsigConfig::default(),
        );

        assert!(matches!(res, Err(SigningError::NoKeysProvided)));
    }

    #[test]
    fn generate_rrsigs_for_partial_zone() {
        let zone_apex = "example.";

        // This is an example of generating RRSIGs for something other than a
        // full zone, in this case just for NSECs, as is done by sign_zone().
        let records = [Record::from_record(mk_nsec_rr(
            zone_apex,
            "next.example.",
            "A NSEC RRSIG",
        ))];

        // Prepare a zone signing key and a key signing key.
        let keys = [mk_dnssec_signing_key(IntendedKeyPurpose::CSK)];

        // Generate RRSIGs. Use the default signing config and thus also the
        // DefaultSigningKeyUsageStrategy which will honour the purpose of the
        // key when selecting a key to use for signing DNSKEY RRs or other
        // zone RRs. We supply the zone apex because we are not supplying an
        // entire zone complete with SOA.
        let rrsigs = generate_rrsigs(
            RecordsIter::new(&records),
            &keys,
            &GenerateRrsigConfig::default()
                .with_zone_apex(&mk_name(zone_apex)),
        )
        .unwrap();

        // Check the generated RRSIG record
        assert_eq!(rrsigs.len(), 1);
        assert_eq!(rrsigs[0].owner(), &mk_name("example."));
        assert_eq!(rrsigs[0].class(), Class::IN);
        assert_eq!(rrsigs[0].rtype(), Rtype::RRSIG);

        // Check the contained RRSIG RDATA
        let ZoneRecordData::Rrsig(rrsig) = rrsigs[0].data() else {
            panic!("RDATA is not RRSIG");
        };
        assert_eq!(rrsig.type_covered(), Rtype::NSEC);
        assert_eq!(rrsig.algorithm(), keys[0].algorithm());
        assert_eq!(rrsig.original_ttl(), TEST_TTL);
        assert_eq!(rrsig.signer_name(), &mk_name(zone_apex));
        assert_eq!(rrsig.key_tag(), keys[0].public_key().key_tag());
        assert_eq!(
            RangeInclusive::new(rrsig.inception(), rrsig.expiration()),
            keys[0].signature_validity_period().unwrap()
        );
    }

    #[test]
    fn generate_rrsigs_for_complete_zone_with_ksk_and_zsk() {
        let keys = [
            mk_dnssec_signing_key(IntendedKeyPurpose::KSK),
            mk_dnssec_signing_key(IntendedKeyPurpose::ZSK),
        ];
        let cfg = GenerateRrsigConfig::default();
        generate_rrsigs_for_complete_zone(&keys, 0, 1, &cfg).unwrap();
    }

    #[test]
    fn generate_rrsigs_for_complete_zone_with_csk() {
        let keys = [mk_dnssec_signing_key(IntendedKeyPurpose::CSK)];
        let cfg = GenerateRrsigConfig::default();
        generate_rrsigs_for_complete_zone(&keys, 0, 0, &cfg).unwrap();
    }

    #[test]
    fn generate_rrsigs_for_complete_zone_with_csk_without_adding_dnskeys() {
        let keys = [mk_dnssec_signing_key(IntendedKeyPurpose::CSK)];
        let cfg =
            GenerateRrsigConfig::default().without_adding_used_dns_keys();
        generate_rrsigs_for_complete_zone(&keys, 0, 0, &cfg).unwrap();
    }

    #[test]
    fn generate_rrsigs_for_complete_zone_with_only_zsk_should_fail_by_default(
    ) {
        let keys = [mk_dnssec_signing_key(IntendedKeyPurpose::ZSK)];
        let cfg = GenerateRrsigConfig::default();

        // This should fail as the DefaultSigningKeyUsageStrategy requires
        // both ZSK and KSK, or a CSK.
        let res = generate_rrsigs_for_complete_zone(&keys, 0, 0, &cfg);
        assert!(matches!(res, Err(SigningError::NoSuitableKeysFound)));
    }

    #[test]
    fn generate_rrsigs_for_complete_zone_with_only_zsk_and_fallback_strategy()
    {
        let keys = [mk_dnssec_signing_key(IntendedKeyPurpose::ZSK)];

        // Implement a strategy that falls back to the ZSK for signing zone
        // keys if no KSK is available. (ala ldns-sign -A)
        struct FallbackStrat;
        impl SigningKeyUsageStrategy<Bytes, TestKey> for FallbackStrat {
            const NAME: &'static str =
                "Fallback to ZSK usage strategy for testing";

            fn select_signing_keys_for_rtype<
                DSK: DesignatedSigningKey<Bytes, TestKey>,
            >(
                candidate_keys: &[DSK],
                rtype: Option<Rtype>,
            ) -> smallvec::SmallVec<[usize; 4]> {
                if core::matches!(rtype, Some(Rtype::DNSKEY)) {
                    Self::filter_keys(candidate_keys, |_| true)
                } else {
                    Self::filter_keys(candidate_keys, |k| k.signs_zone_data())
                }
            }
        }

        let fallback_cfg = GenerateRrsigConfig::<_, FallbackStrat, _>::new();
        generate_rrsigs_for_complete_zone(&keys, 0, 0, &fallback_cfg)
            .unwrap();
    }

    fn generate_rrsigs_for_complete_zone<KeyStrat>(
        keys: &[DnssecSigningKey<Bytes, TestKey>],
        ksk_idx: usize,
        zsk_idx: usize,
        cfg: &GenerateRrsigConfig<StoredName, KeyStrat, DefaultSorter>,
    ) -> Result<(), SigningError>
    where
        KeyStrat: SigningKeyUsageStrategy<Bytes, TestKey>,
    {
        // See https://datatracker.ietf.org/doc/html/rfc4035#appendix-A
        let zonefile = include_bytes!(
            "../../../test-data/zonefiles/rfc4035-appendix-A.zone"
        );

        // Load the zone to generate RRSIGs for.
        let records = bytes_to_records(&zonefile[..]);

        // Generate DNSKEYs and RRSIGs.
        let generated_records =
            generate_rrsigs(RecordsIter::new(&records), keys, cfg)?;

        let dnskeys = keys
            .iter()
            .map(|k| k.public_key().to_dnskey().convert())
            .collect::<Vec<_>>();

        let ksk = &dnskeys[ksk_idx];
        let zsk = &dnskeys[zsk_idx];

        // Check the generated records.
        let mut iter = generated_records.iter();

        // The records should be in a fixed canonical order because the input
        // records must be in canonical order, with the exception of the added
        // DNSKEY RRs which will be ordered in the order in the supplied
        // collection of keys to sign with.
        //
        // We check each record explicitly by index because assert_eq() on an
        // array of objects that includes Rrsig produces hard to read output
        // due to the large RRSIG signature bytes being printed one byte per
        // line.

        // NOTE: As we only invoked generate_rrsigs() and not generate_nsecs()
        // there will not be any RRSIGs covering NSEC records.

        // -- example.

        if cfg.add_used_dnskeys {
            // DNSKEY records should have been generated for the apex for both
            // of the keys that we used to sign the zone.
            assert_eq!(*iter.next().unwrap(), mk_dnskey_rr("example.", ksk));
            if ksk_idx != zsk_idx {
                assert_eq!(
                    *iter.next().unwrap(),
                    mk_dnskey_rr("example.", zsk)
                );
            }
        }

        // RRSIG records should have been generated for the zone apex records,
        // one RRSIG per ZSK used (we used one ZSK so only one RRSIG per
        // record).
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("example.", Rtype::NS, 1, "example.", zsk)
        );
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("example.", Rtype::SOA, 1, "example.", zsk)
        );
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("example.", Rtype::MX, 1, "example.", zsk)
        );
        // https://datatracker.ietf.org/doc/html/rfc4035#section-2.2 2.2.
        // Including RRSIG RRs in a Zone. .. "There MUST be an RRSIG for each
        //   RRset using at least one DNSKEY of each algorithm in the zone
        //   apex DNSKEY RRset.  The apex DNSKEY RRset itself MUST be signed
        //    by each algorithm appearing in the DS RRset located at the
        //    delegating parent (if any)."
        //
        // In the real world a DNSSEC signed zone is only valid when part of a
        // hierarchy such that the signatures can be trusted because there
        // exists a valid chain of trust up to a root, and each parent zone
        // specifies via one or more DS records which DNSKEY RRs the child
        // zone should be signed with.
        //
        // In our contrived test example we don't have a hierarchy or a parent
        // zone so there are no DS RRs to consider. The keys that the zone
        // should be signed with are determined by the keys passed to
        // generate_rrsigs(). In our case that means that the DNSKEY RR RRSIG
        // should have been generated using the KSK because the
        // DefaultSigningKeyUsageStrategy selects keys to sign DNSKEY RRs
        // based on whether they return true or not from
        // `DesignatedSigningKey::signs_keys()` and we are using the
        // `DnssecSigningKey` impl of `DesignatedSigningKey` which selects
        // keys based on their `IntendedKeyPurpose` which we assigned above
        // when creating the keys.
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("example.", Rtype::DNSKEY, 1, "example.", ksk)
        );

        // -- a.example.

        // NOTE: Per RFC 4035 there is NOT an RRSIG for a.example NS because:
        //
        // https://datatracker.ietf.org/doc/html/rfc4035#section-2.2
        // 2.2.  Including RRSIG RRs in a Zone
        //   ...
        //   "The NS RRset that appears at the zone apex name MUST be signed,
        //    but the NS RRsets that appear at delegation points (that is, the
        //    NS RRsets in the parent zone that delegate the name to the child
        //    zone's name servers) MUST NOT be signed."

        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("a.example.", Rtype::DS, 2, "example.", zsk)
        );

        // -- ns1.a.example.
        //    ns2.a.example.

        // NOTE: Per RFC 4035 there is NOT an RRSIG for ns1.a.example A
        // or ns2.a.example because:
        //
        // https://datatracker.ietf.org/doc/html/rfc4035#section-2.2 2.2.
        // Including RRSIG RRs in a Zone "For each authoritative RRset in a
        //   signed zone, there MUST be at least one RRSIG record..." ... AND
        //   ... "Glue address RRsets associated with delegations MUST NOT be
        //   signed."
        //
        // ns1.a.example is part of the a.example zone which was delegated
        // above and so we are not authoritative for it.
        //
        // Further, ns1.a.example A is a glue record because a.example NS
        // refers to it by name but in order for a recursive resolver to
        // follow the delegation to the child zones' nameservers it has to
        // know their IP address, and in this case the nameserver name falls
        // inside the child zone so strictly speaking only the child zone is
        // authoritative for it, yet the resolver can't ask the child zone
        // nameserver unless it knows its IP address, hence the need for glue
        // in the parent zone.

        // -- ai.example.

        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("ai.example.", Rtype::A, 2, "example.", zsk)
        );
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("ai.example.", Rtype::HINFO, 2, "example.", zsk)
        );
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("ai.example.", Rtype::AAAA, 2, "example.", zsk)
        );

        // -- b.example.

        // NOTE: There is no RRSIG for b.example NS for the same reason that
        // there is no RRSIG for a.example.
        //
        // Also, there is no RRSIG for b.example A because b.example is
        // delegated and thus we are not authoritative for records in that
        // zone.

        // -- ns1.b.example.
        //    ns2.b.example.

        // NOTE: There is no RRSIG for ns1.b.example or ns2.b.example for
        // the same reason that there are no RRSIGs ofr ns1.a.example or
        // ns2.a.example, as described above.

        // -- ns1.example.

        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("ns1.example.", Rtype::A, 2, "example.", zsk)
        );

        // -- ns2.example.

        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("ns2.example.", Rtype::A, 2, "example.", zsk)
        );

        // -- *.w.example.

        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("*.w.example.", Rtype::MX, 2, "example.", zsk)
        );

        // -- x.w.example.

        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("x.w.example.", Rtype::MX, 3, "example.", zsk)
        );

        // -- x.y.w.example.

        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("x.y.w.example.", Rtype::MX, 4, "example.", zsk)
        );

        // -- xx.example.

        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("xx.example.", Rtype::A, 2, "example.", zsk)
        );
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("xx.example.", Rtype::HINFO, 2, "example.", zsk)
        );
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("xx.example.", Rtype::AAAA, 2, "example.", zsk)
        );

        // No other records should have been generated.

        assert!(iter.next().is_none());

        Ok(())
    }

    //------------ Helper fns ------------------------------------------------

    fn mk_dnssec_signing_key(
        purpose: IntendedKeyPurpose,
    ) -> DnssecSigningKey<Bytes, TestKey> {
        // Note: The flags value has no impact on the role the key will play
        // in signing, that is instead determined by its designated purpose
        // AND the SigningKeyUsageStrategy in use.
        let flags = match purpose {
            IntendedKeyPurpose::KSK => 257,
            IntendedKeyPurpose::ZSK => 256,
            IntendedKeyPurpose::CSK => 257,
            IntendedKeyPurpose::Inactive => 0,
        };

        let key = SigningKey::new(StoredName::root_bytes(), flags, TestKey);

        let key = key.with_validity(
            Timestamp::from(TEST_INCEPTION),
            Timestamp::from(TEST_EXPIRATION),
        );

        DnssecSigningKey::new(key, purpose)
    }

    fn mk_dnskey_rr(name: &str, dnskey: &Dnskey<Bytes>) -> StoredRecord {
        test_util::mk_dnskey_rr(
            name,
            dnskey.flags(),
            dnskey.algorithm(),
            dnskey.public_key(),
        )
    }

    fn mk_rrsig_rr(
        name: &str,
        covered_rtype: Rtype,
        labels: u8,
        signer_name: &str,
        dnskey: &Dnskey<Bytes>,
    ) -> StoredRecord {
        test_util::mk_rrsig_rr(
            name,
            covered_rtype,
            &dnskey.algorithm(),
            labels,
            TEST_EXPIRATION,
            TEST_INCEPTION,
            dnskey.key_tag(),
            signer_name,
            TEST_SIGNATURE,
        )
    }

    //------------ TestKey ---------------------------------------------------

    const TEST_SIGNATURE_RAW: [u8; 64] = [0u8; 64];
    const TEST_SIGNATURE: Bytes = Bytes::from_static(&TEST_SIGNATURE_RAW);

    struct TestKey;

    impl SignRaw for TestKey {
        fn algorithm(&self) -> SecAlg {
            SecAlg::ED25519
        }

        fn raw_public_key(&self) -> PublicKeyBytes {
            PublicKeyBytes::Ed25519([0_u8; 32].into())
        }

        fn sign_raw(&self, _data: &[u8]) -> Result<Signature, SignError> {
            Ok(Signature::Ed25519(TEST_SIGNATURE_RAW.into()))
        }
    }
}
