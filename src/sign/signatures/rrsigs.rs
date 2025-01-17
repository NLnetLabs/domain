//! DNSSEC RRSIG generation.
use core::convert::From;
use core::fmt::Display;
use core::marker::Send;

use std::boxed::Box;
use std::collections::HashSet;
use std::string::ToString;
use std::vec::Vec;

use octseq::builder::{EmptyBuilder, FromBuilder};
use octseq::{OctetsFrom, OctetsInto};
use tracing::{debug, enabled, trace, Level};

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{Class, Rtype};
use crate::base::name::ToName;
use crate::base::rdata::{ComposeRecordData, RecordData};
use crate::base::record::Record;
use crate::base::Name;
use crate::rdata::dnssec::ProtoRrsig;
use crate::rdata::{Dnskey, ZoneRecordData};
use crate::sign::error::SigningError;
use crate::sign::keys::keymeta::DesignatedSigningKey;
use crate::sign::keys::signingkey::SigningKey;
use crate::sign::records::{RecordsIter, Rrset, SortedRecords, Sorter};
use crate::sign::signatures::strategy::SigningKeyUsageStrategy;
use crate::sign::traits::{SignRaw, SortedExtend};

/// Generate RRSIG RRs for a collection of unsigned zone records.
///
/// Returns the collection of RRSIG and (optionally) DNSKEY RRs that must be
/// added to the given records as part of DNSSEC zone signing.
///
/// The given records MUST be sorted according to [`CanonicalOrd`].
// TODO: Add mutable iterator based variant.
#[allow(clippy::type_complexity)]
pub fn generate_rrsigs<N, Octs, DSK, Inner, KeyStrat, Sort>(
    expected_apex: &N,
    records: RecordsIter<'_, N, ZoneRecordData<Octs, N>>,
    keys: &[DSK],
    add_used_dnskeys: bool,
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
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
{
    debug!(
        "Signer settings: add_used_dnskeys={add_used_dnskeys}, strategy: {}",
        KeyStrat::NAME
    );

    if keys.is_empty() {
        return Err(SigningError::NoKeysProvided);
    }

    // Work with indices because SigningKey doesn't impl PartialEq so we
    // cannot use a HashSet to make a unique set of them.

    let dnskey_signing_key_idxs =
        KeyStrat::select_signing_keys_for_rtype(keys, Some(Rtype::DNSKEY));

    let non_dnskey_signing_key_idxs =
        KeyStrat::select_signing_keys_for_rtype(keys, None);

    let keys_in_use_idxs: HashSet<_> = non_dnskey_signing_key_idxs
        .iter()
        .chain(dnskey_signing_key_idxs.iter())
        .collect();

    if keys_in_use_idxs.is_empty() {
        return Err(SigningError::NoSuitableKeysFound);
    }

    // TODO: use log::log_enabled instead.
    // See: https://github.com/NLnetLabs/domain/pull/465
    if enabled!(Level::DEBUG) {
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

        for idx in &keys_in_use_idxs {
            let key = &keys[**idx];
            let is_dnskey_signing_key = dnskey_signing_key_idxs.contains(idx);
            let is_non_dnskey_signing_key =
                non_dnskey_signing_key_idxs.contains(idx);
            let usage = if is_dnskey_signing_key && is_non_dnskey_signing_key
            {
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

    let mut res: Vec<Record<N, ZoneRecordData<Octs, N>>> = Vec::new();
    let mut reusable_scratch = Vec::new();
    let mut cut: Option<N> = None;
    let mut records = records.peekable();

    // Are we signing the entire tree from the apex down or just some child
    // records? Use the first found SOA RR as the apex. If no SOA RR can be
    // found assume that we are only signing records below the apex.
    let (soa_ttl, zone_class) = if let Some(rr) =
        records.peek().and_then(|first_owner_rrs| {
            first_owner_rrs.records().find(|rr| {
                rr.owner() == expected_apex && rr.rtype() == Rtype::SOA
            })
        }) {
        (Some(rr.ttl()), rr.class())
    } else {
        (None, Class::IN)
    };

    if let Some(soa_ttl) = soa_ttl {
        // Sign the apex
        // SAFETY: We just checked above if the apex records existed.
        let apex_owner_rrs = records.next().unwrap();

        let apex_rrsets = apex_owner_rrs
            .rrsets()
            .filter(|rrset| rrset.rtype() != Rtype::RRSIG);

        // Generate or extend the DNSKEY RRSET with the keys that we will sign
        // apex DNSKEY RRs and zone RRs with.
        let apex_dnskey_rrset = apex_owner_rrs
            .rrsets()
            .find(|rrset| rrset.rtype() == Rtype::DNSKEY);

        let mut augmented_apex_dnskey_rrs =
            SortedRecords::<_, _, Sort>::new();

        // Determine the TTL of any existing DNSKEY RRSET and use that as the
        // TTL for DNSKEY RRs that we add. If none, then fall back to the SOA
        // TTL.
        //
        // https://datatracker.ietf.org/doc/html/rfc2181#section-5.2 5.2. TTLs
        // of RRs in an RRSet "Consequently the use of differing TTLs in an
        //   RRSet is hereby deprecated, the TTLs of all RRs in an RRSet must
        //    be the same."
        //
        // Note that while RFC 1033 says: RESOURCE RECORDS "If you leave the
        //   TTL field blank it will default to the minimum time specified in
        //     the SOA record (described later)."
        //
        // That RFC pre-dates RFC 1034, and neither dnssec-signzone nor
        // ldns-signzone use the SOA MINIMUM as a default TTL, rather they use
        // the TTL of the SOA RR as the default and so we will do the same.
        let dnskey_rrset_ttl = if let Some(rrset) = apex_dnskey_rrset {
            let ttl = rrset.ttl();
            augmented_apex_dnskey_rrs.sorted_extend(rrset.iter().cloned());
            ttl
        } else {
            soa_ttl
        };

        for public_key in
            keys_in_use_idxs.iter().map(|&&idx| keys[idx].public_key())
        {
            let dnskey = public_key.to_dnskey();

            let signing_key_dnskey_rr = Record::new(
                expected_apex.clone(),
                zone_class,
                dnskey_rrset_ttl,
                Dnskey::convert(dnskey.clone()).into(),
            );

            // Add the DNSKEY RR to the set of DNSKEY RRs to create RRSIGs
            // for.
            let is_new_dnskey = augmented_apex_dnskey_rrs
                .insert(signing_key_dnskey_rr)
                .is_ok();

            if add_used_dnskeys && is_new_dnskey {
                // Add the DNSKEY RR to the set of new RRs to output for the
                // zone.
                res.push(Record::new(
                    expected_apex.clone(),
                    zone_class,
                    dnskey_rrset_ttl,
                    Dnskey::convert(dnskey).into(),
                ));
            }
        }

        let augmented_apex_dnskey_rrset =
            Rrset::new(&augmented_apex_dnskey_rrs);

        // Sign the apex RRSETs in canonical order.
        for rrset in apex_rrsets
            .filter(|rrset| rrset.rtype() != Rtype::DNSKEY)
            .chain(std::iter::once(augmented_apex_dnskey_rrset))
        {
            // For the DNSKEY RRSET, use signing keys chosen for that purpose
            // and sign the augmented set of DNSKEY RRs that we have generated
            // rather than the original set in the zonefile.
            let signing_key_idxs = if rrset.rtype() == Rtype::DNSKEY {
                &dnskey_signing_key_idxs
            } else {
                &non_dnskey_signing_key_idxs
            };

            for key in signing_key_idxs.iter().map(|&idx| &keys[idx]) {
                let rrsig_rr = sign_rrset_in(
                    key,
                    &rrset,
                    expected_apex,
                    &mut reusable_scratch,
                )?;
                res.push(rrsig_rr);
                trace!(
                    "Signed {} RRs in RRSET {} at the zone apex with keytag {}",
                    rrset.iter().len(),
                    rrset.rtype(),
                    key.public_key().key_tag()
                );
            }
        }
    }

    // For all RRSETs below the apex
    for owner_rrs in records {
        // If the owner is out of zone, we have moved out of our zone and are
        // done.
        if !owner_rrs.is_in_zone(expected_apex) {
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
        cut = if owner_rrs.is_zone_cut(expected_apex) {
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
                    expected_apex,
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

    debug!("Returning {} records from signing", res.len());

    Ok(res)
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
    use super::*;
    use crate::base::iana::SecAlg;
    use crate::base::{Serial, Ttl};
    use crate::rdata::dnssec::Timestamp;
    use crate::rdata::{Rrsig, A};
    use crate::sign::error::SignError;
    use crate::sign::{PublicKeyBytes, Signature};
    use bytes::Bytes;
    use core::str::FromStr;

    struct TestKey;

    impl SignRaw for TestKey {
        fn algorithm(&self) -> SecAlg {
            SecAlg::PRIVATEDNS
        }

        fn raw_public_key(&self) -> PublicKeyBytes {
            PublicKeyBytes::Ed25519([0_u8; 32].into())
        }

        fn sign_raw(&self, _data: &[u8]) -> Result<Signature, SignError> {
            Ok(Signature::Ed25519([0u8; 64].into()))
        }
    }

    #[test]
    fn rrset_sign_adheres_to_rules_in_rfc_4034_and_rfc_4035() {
        let apex_owner = Name::root();
        let key = SigningKey::new(apex_owner.clone(), 0, TestKey);
        let key = key.with_validity(Timestamp::from(0), Timestamp::from(0));

        // RFC 4034
        // 3.1.3.  The Labels Field
        //   ...
        //   "For example, "www.example.com." has a Labels field value of 3"
        // We can use any class as RRSIGs are class independent.
        let records = [mk_record(
            "www.example.com.",
            Class::CH,
            12345,
            ZoneRecordData::A(A::from_str("1.2.3.4").unwrap()),
        )];
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
    fn rrtest_sign_wildcard() {
        let apex_owner = Name::root();
        let key = SigningKey::new(apex_owner.clone(), 0, TestKey);
        let key = key.with_validity(Timestamp::from(0), Timestamp::from(0));

        // RFC 4034
        // 3.1.3.  The Labels Field
        //   ...
        //   ""*.example.com." has a Labels field value of 2"
        // We can use any class as RRSIGs are class independent.
        let records = [mk_record(
            "*.example.com.",
            Class::CH,
            12345,
            ZoneRecordData::A(A::from_str("1.2.3.4").unwrap()),
        )];
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

        let dummy_rrsig = Rrsig::new(
            Rtype::A,
            SecAlg::PRIVATEDNS,
            0,
            Ttl::default(),
            0.into(),
            0.into(),
            0,
            Name::root(),
            Bytes::new(),
        )
        .unwrap();

        let records = [mk_record(
            "any.",
            Class::CH,
            12345,
            ZoneRecordData::Rrsig(dummy_rrsig),
        )];
        let rrset = Rrset::new(&records);

        let res = sign_rrset(&key, &rrset, &apex_owner);
        assert!(matches!(res, Err(SigningError::RrsigRrsMustNotBeSigned)));
    }

    #[test]
    fn sign_rrsets_check_validity_period_handling() {
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

        let records = [mk_record(
            "any.",
            Class::CH,
            12345,
            ZoneRecordData::A(A::from_str("1.2.3.4").unwrap()),
        )];
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

    //------------ Helper fns ------------------------------------------------

    fn mk_record(
        owner: &str,
        class: Class,
        ttl_secs: u32,
        data: ZoneRecordData<Bytes, Name<Bytes>>,
    ) -> Record<Name<Bytes>, ZoneRecordData<Bytes, Name<Bytes>>> {
        Record::new(
            Name::from_str(owner).unwrap(),
            class,
            Ttl::from_secs(ttl_secs),
            data,
        )
    }
}
