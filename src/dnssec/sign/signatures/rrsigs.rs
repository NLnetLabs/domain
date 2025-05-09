//! DNSSEC RRSIG generation.
use core::convert::{AsRef, From};
use core::fmt::Display;
use core::marker::Send;

use std::boxed::Box;
use std::cmp::Ordering;
use std::fmt::Debug;
use std::vec::Vec;

use octseq::builder::FromBuilder;
use octseq::{OctetsFrom, OctetsInto};
use tracing::debug;

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::ToName;
use crate::base::rdata::{ComposeRecordData, RecordData};
use crate::base::record::Record;
use crate::base::Name;
use crate::crypto::sign::SignRaw;
use crate::dnssec::sign::error::SigningError;
use crate::dnssec::sign::keys::signingkey::SigningKey;
use crate::dnssec::sign::records::{RecordsIter, Rrset};
use crate::rdata::dnssec::{ProtoRrsig, Timestamp};
use crate::rdata::{Rrsig, ZoneRecordData};

//------------ GenerateRrsigConfig -------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct GenerateRrsigConfig {
    pub inception: Timestamp,

    pub expiration: Timestamp,
}

impl GenerateRrsigConfig {
    /// Create a new object.
    pub fn new(inception: Timestamp, expiration: Timestamp) -> Self {
        Self {
            inception,
            expiration,
        }
    }
}

//------------ generate_rrsigs -----------------------------------------------

/// Generate RRSIG records for a collection of zone records.
///
/// An implementation of [RFC 4035 section 2.2] for generating RRSIG RRs for a
/// zone.
///
/// This function takes DNS records and signing keys and uses the signing keys
/// to generate and output RRSIG RRs that sign the input records per [RFC
/// 9364].
///
/// RRSIG RRs will **NOT** be generated for records:
///   - With RTYPE RRSIG, because [RFC 4035 section 2.2] states that _"An
///     RRSIG RR itself MUST NOT be signed"_.
///   - With RTYPE DNSKEY, CDS or CDNSKEY RR, because, depending on the
///     operational practice (see [RFC 6871]), it may be that these RRs should
///     not be signed using the same key as the rest of the records in the
///     zone. To sign DNSKEY, CDS and CDNSKEY RRs see the [`sign_rrset()`]
///     function.
///
/// Note:
///   - The input records MUST be sorted according to [`CanonicalOrd`].
///   - The order of the output records should not be relied upon.
///
/// # Design rationale
///
/// The restriction to limit signing to records not involved in the chain of
/// trust with the parent zone is imposed because there is considerable
/// variation and complexity in the strategies used to protect and roll the
/// keys used to sign records in a DNSSEC signed zone.
///
/// It is common operational practice (see [RFC 6871]) to increase security by
/// using two separate keys to sign the zone. A Key Signing Key aka KSK is
/// used to sign the keys used to establish trust with the parent zone, and a
/// Zone Signing Key aka ZSK is used to sign the rest of the records in the
/// zone, with the KSK signing the ZSK. This allows the ZSK to be rolled
/// without needing to submit information about the new key to the parent zone
/// operator.
///
/// Deciding which key to use to sign which records at a given time,
/// especially during key rolls, can be complex. Attempting to cover all
/// possible cases in this function would increase the complexity and
/// fragility and reduce flexibility. As such it is left to the caller to
/// ensure that this is done correctly and doing so also enables the caller to
/// have complete control over the key signing strategy used.
///
/// [RFC 4035 section 2.2]: https://www.rfc-editor.org/rfc/rfc4035#section-2.2
/// [RFC 6871]: https://www.rfc-editor.org/rfc/rfc6871
/// [RFC 9364]: https://www.rfc-editor.org/rfc/rfc9364
// TODO: Add mutable iterator based variant.
#[allow(clippy::type_complexity)]
pub fn generate_rrsigs<N, Octs, Inner>(
    apex_owner: &N,
    mut records: RecordsIter<'_, N, ZoneRecordData<Octs, N>>,
    keys: &[&SigningKey<Octs, Inner>],
    config: &GenerateRrsigConfig,
) -> Result<Vec<Record<N, Rrsig<Octs, N>>>, SigningError>
where
    Inner: Debug + SignRaw,
    N: ToName
        + PartialEq
        + Clone
        + Debug
        + Display
        + Send
        + CanonicalOrd
        + From<Name<Octs>>,
    Octs: AsRef<[u8]>
        + Debug
        + From<Box<[u8]>>
        + Send
        + OctetsFrom<Vec<u8>>
        + Clone
        + FromBuilder
        + From<&'static [u8]>,
{
    // The generated collection of RRSIG RRs that will be returned to the
    // caller.
    let mut rrsigs = Vec::new();

    // A temporary scratch buffer used when generating signatures that can be
    // allocated once and reused for each new signature that we generate.
    let mut reusable_scratch = Vec::new();

    // The owner name of a zone cut if we currently are at or below one.
    let mut cut: Option<N> = None;

    // Skip any glue records that sort earlier than the zone apex.
    records.skip_before(apex_owner);

    // For all records
    for owner_rrs in records {
        // If the owner is out of zone, we have moved out of our zone and are
        // done.
        if !owner_rrs.is_in_zone(apex_owner) {
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
        cut = if owner_rrs.is_zone_cut(apex_owner) {
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
            } else if (rrset.rtype() == Rtype::DNSKEY
                || rrset.rtype() == Rtype::CDS
                || rrset.rtype() == Rtype::CDNSKEY)
                && name.canonical_cmp(apex_owner) == Ordering::Equal
            {
                // Ignore the DNSKEY, CDS, and CDNSKEY RRsets at the apex.
                // Sign other DNSKEY, CDS, and CDNSKEY RRsets as other
                // records.
                // See RFC 7344 Section 4.1 for CDS and CDNSKEY.
                continue;
            } else {
                // Otherwise we only ignore RRSIGs.
                if rrset.rtype() == Rtype::RRSIG {
                    continue;
                }
            }

            for key in keys {
                let inception = config.inception;
                let expiration = config.expiration;
                let rrsig_rr = sign_sorted_rrset_in(
                    key,
                    &rrset,
                    inception,
                    expiration,
                    &mut reusable_scratch,
                )?;
                rrsigs.push(rrsig_rr);
                debug!(
                    "Signed {} RRSET at {} with keytag {}",
                    rrset.rtype(),
                    rrset.owner(),
                    key.dnskey().key_tag()
                );
            }
        }
    }

    debug!(
        "Returning {} RRSIG RRs from signature generation",
        rrsigs.len(),
    );

    Ok(rrsigs)
}

/// Generate `RRSIG` records for a given RRset.
///
/// See [`sign_sorted_rrset_in()`].
///
/// If signing multiple RRsets, calling [`sign_sorted_rrset_in()`] directly
/// will be more efficient as you can allocate the scratch buffer once
/// and re-use it across multiple calls.
///
/// This function will sort the RRset in canonical ordering prior to signing.
pub fn sign_rrset<N, D, Octs, Inner>(
    key: &SigningKey<Octs, Inner>,
    rrset: &Rrset<'_, N, D>,
    inception: Timestamp,
    expiration: Timestamp,
) -> Result<Record<N, Rrsig<Octs, N>>, SigningError>
where
    N: ToName + Debug + Clone + From<Name<Octs>>,
    D: Clone + Debug + RecordData + ComposeRecordData + CanonicalOrd,
    Inner: Debug + SignRaw,
    Octs: AsRef<[u8]> + Clone + Debug + OctetsFrom<Vec<u8>>,
{
    let mut records = rrset.as_slice().to_vec();
    records
        .sort_by(|a, b| a.as_ref().data().canonical_cmp(b.as_ref().data()));
    let rrset = Rrset::new(&records)
        .expect("records is not empty so new should not fail");

    sign_sorted_rrset_in(key, &rrset, inception, expiration, &mut vec![])
}

/// Generate `RRSIG` records for a given RRset.
///
/// This function generates an `RRSIG` record for the given RRset based on the
/// given signing key, according to the rules defined in [RFC 4034 section 3]
/// _"The RRSIG Resource Record"_, [RFC 4035 section 2.2] _"Including RRSIG
/// RRs in a Zone"_ and [RFC 6840 section 5.11] _"Mandatory Algorithm Rules"_.
///
/// The RRset must be sorted in canonical ordering before calling this
/// function.
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
pub fn sign_sorted_rrset_in<N, D, Octs, Inner>(
    key: &SigningKey<Octs, Inner>,
    rrset: &Rrset<'_, N, D>,
    inception: Timestamp,
    expiration: Timestamp,
    scratch: &mut Vec<u8>,
) -> Result<Record<N, Rrsig<Octs, N>>, SigningError>
where
    N: ToName + Clone + Debug + From<Name<Octs>>,
    D: RecordData + Debug + ComposeRecordData + CanonicalOrd,
    Inner: Debug + SignRaw,
    Octs: AsRef<[u8]> + Clone + Debug + OctetsFrom<Vec<u8>>,
{
    // RFC 4035
    // 2.2.  Including RRSIG RRs in a Zone
    //   ...
    //   "An RRSIG RR itself MUST NOT be signed"
    if rrset.rtype() == Rtype::RRSIG {
        return Err(SigningError::RrsigRrsMustNotBeSigned);
    }

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
        key.dnskey().key_tag(),
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
        key.owner().clone().into(),
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
        rrsig,
    ))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use core::str::FromStr;
    use pretty_assertions::assert_eq;

    use crate::base::iana::SecurityAlgorithm;
    use crate::base::Serial;
    use crate::crypto::sign::{KeyPair, SignError, Signature};
    use crate::dnssec::sign::records::SortedRecords;
    use crate::dnssec::sign::test_util;
    use crate::dnssec::sign::test_util::*;
    use crate::rdata::dnssec::Timestamp;
    use crate::rdata::Dnskey;
    use crate::zonetree::StoredName;

    use super::*;
    use crate::zonetree::types::StoredRecordData;
    use rand::Rng;

    const TEST_INCEPTION: u32 = 0;
    const TEST_EXPIRATION: u32 = 100;

    #[test]
    fn sign_rrset_adheres_to_rules_in_rfc_4034_and_rfc_4035() {
        let apex_owner = Name::root();
        let key = SigningKey::new(apex_owner.clone(), 0, TestKey::default());
        let (inception, expiration) =
            (Timestamp::from(0), Timestamp::from(0));

        // RFC 4034
        // 3.1.3.  The Labels Field
        //   ...
        //   "For example, "www.example.com." has a Labels field value of 3"
        // We can use any class as RRSIGs are class independent.
        let mut records =
            SortedRecords::<StoredName, StoredRecordData>::default();
        records.insert(mk_a_rr("www.example.com.")).unwrap();
        let rrset = Rrset::new(&records).expect("records is not empty");

        let rrsig_rr =
            sign_rrset(&key, &rrset, inception, expiration).unwrap();
        let rrsig = rrsig_rr.data();

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
        let key = SigningKey::new(apex_owner.clone(), 0, TestKey::default());
        let (inception, expiration) =
            (Timestamp::from(0), Timestamp::from(0));

        // RFC 4034
        // 3.1.3.  The Labels Field
        //   ...
        //   ""*.example.com." has a Labels field value of 2"
        let mut records =
            SortedRecords::<StoredName, StoredRecordData>::default();
        records.insert(mk_a_rr("*.example.com.")).unwrap();
        let rrset = Rrset::new(&records).expect("records is not empty");

        let rrsig_rr =
            sign_rrset(&key, &rrset, inception, expiration).unwrap();
        let rrsig = rrsig_rr.data();

        assert_eq!(rrsig.labels(), 2);
    }

    #[test]
    fn sign_rrset_must_not_sign_rrsigs() {
        // RFC 4035
        // 2.2.  Including RRSIG RRs in a Zone
        //   ...
        //   "An RRSIG RR itself MUST NOT be signed"

        let apex_owner = Name::root();
        let key = SigningKey::new(apex_owner.clone(), 0, TestKey::default());
        let (inception, expiration) =
            (Timestamp::from(0), Timestamp::from(0));
        let dnskey = key.dnskey().convert();

        let mut records =
            SortedRecords::<StoredName, StoredRecordData>::default();
        records
            .insert(mk_rrsig_rr("any.", Rtype::A, 1, ".", &dnskey))
            .unwrap();
        let rrset = Rrset::new(&records).expect("records is not empty");

        let res = sign_rrset(&key, &rrset, inception, expiration);
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
        let key = SigningKey::new(apex_owner.clone(), 0, TestKey::default());

        let mut records =
            SortedRecords::<StoredName, StoredRecordData>::default();
        records.insert(mk_a_rr("any.")).unwrap();
        let rrset = Rrset::new(&records).expect("records is not empty");

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
        sign_rrset(&key, &rrset, inception, expiration).unwrap();

        // Good: Expiration == Inception.
        let (inception, expiration) = calc_timestamps(10, 0);
        sign_rrset(&key, &rrset, inception, expiration).unwrap();

        // Bad: Expiration < Inception.
        let (expiration, inception) = calc_timestamps(5, 10);
        let res = sign_rrset(&key, &rrset, inception, expiration);
        assert!(matches!(
            res,
            Err(SigningError::InvalidSignatureValidityPeriod(_, _))
        ));

        // Good: Expiration > Inception with Expiration near wrap around
        // point.
        let (inception, expiration) = calc_timestamps(u32::MAX - 10, 10);
        sign_rrset(&key, &rrset, inception, expiration).unwrap();

        // Good: Expiration > Inception with Inception near wrap around point.
        let (inception, expiration) = calc_timestamps(0, 10);
        sign_rrset(&key, &rrset, inception, expiration).unwrap();

        // Good: Expiration > Inception with Exception crossing the wrap
        // around point.
        let (inception, expiration) = calc_timestamps(u32::MAX - 10, 20);
        sign_rrset(&key, &rrset, inception, expiration).unwrap();

        // Good: Expiration - Inception == 68 years.
        let sixty_eight_years_in_secs = 68 * 365 * 24 * 60 * 60;
        let (inception, expiration) =
            calc_timestamps(0, sixty_eight_years_in_secs);
        sign_rrset(&key, &rrset, inception, expiration).unwrap();

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
        let res = sign_rrset(&key, &rrset, inception, expiration);
        assert!(matches!(
            res,
            Err(SigningError::InvalidSignatureValidityPeriod(_, _))
        ));
    }

    #[test]
    fn generate_rrsigs_without_keys_should_succeed_for_empty_zone() {
        let apex = Name::from_str("example.").unwrap();
        let records =
            SortedRecords::<StoredName, StoredRecordData>::default();
        let no_keys: [&SigningKey<Bytes, KeyPair>; 0] = [];

        generate_rrsigs(
            &apex,
            RecordsIter::new(&records),
            &no_keys,
            &GenerateRrsigConfig::new(
                TEST_INCEPTION.into(),
                TEST_EXPIRATION.into(),
            ),
        )
        .unwrap();
    }

    #[test]
    fn generate_rrsigs_without_keys_generates_no_rrsigs() {
        let apex = Name::from_str("example.").unwrap();
        let mut records = SortedRecords::default();
        records.insert(mk_a_rr("example.")).unwrap();
        let no_keys: [&SigningKey<Bytes, KeyPair>; 0] = [];

        let rrsigs = generate_rrsigs(
            &apex,
            RecordsIter::new(&records),
            &no_keys,
            &GenerateRrsigConfig::new(
                TEST_INCEPTION.into(),
                TEST_EXPIRATION.into(),
            ),
        )
        .unwrap();

        assert!(rrsigs.is_empty());
    }

    #[test]
    fn generate_rrsigs_for_partial_zone_at_apex() {
        generate_rrsigs_for_partial_zone("example.", "example.");
    }

    #[test]
    fn generate_rrsigs_for_partial_zone_beneath_apex() {
        generate_rrsigs_for_partial_zone("example.", "in.example.");
    }

    fn generate_rrsigs_for_partial_zone(zone_apex: &str, record_owner: &str) {
        // This is an example of generating RRSIGs for something other than a
        // full zone, in this case just for an A record. This test
        // deliberately does not include a SOA record as the zone is partial.
        let apex = Name::from_str(zone_apex).unwrap();
        let mut records = SortedRecords::default();
        records.insert(mk_a_rr(record_owner)).unwrap();

        // Prepare a zone signing key and a key signing key.
        let keys = [&mk_dnssec_signing_key(true)];
        let dnskey = keys[0].dnskey().convert();

        // Generate RRSIGs. Use the default signing config and thus also the
        // DefaultSigningKeyUsageStrategy which will honour the purpose of the
        // key when selecting a key to use for signing DNSKEY RRs or other
        // zone RRs. We supply the zone apex because we are not supplying an
        // entire zone complete with SOA.
        let generated_records = generate_rrsigs(
            &apex,
            RecordsIter::new(&records),
            &keys,
            &GenerateRrsigConfig::new(
                TEST_INCEPTION.into(),
                TEST_EXPIRATION.into(),
            ),
        )
        .unwrap();

        // Check the generated RRSIG records
        let expected_labels = mk_name(record_owner).rrsig_label_count();
        assert_eq!(generated_records.len(), 1);
        assert_eq!(
            generated_records[0],
            mk_rrsig_rr(
                record_owner,
                Rtype::A,
                expected_labels,
                zone_apex,
                &dnskey
            )
        );
    }

    #[test]
    fn generate_rrsigs_ignores_records_outside_the_zone() {
        let apex = Name::from_str("example.").unwrap();
        let mut records = SortedRecords::default();
        records.extend([
            mk_soa_rr("example.", "mname.", "rname."),
            mk_a_rr("in_zone.example."),
            mk_a_rr("out_of_zone."),
        ]);

        // Prepare a zone signing key and a key signing key.
        let keys = [&mk_dnssec_signing_key(true)];
        let dnskey = keys[0].dnskey().convert();

        let generated_records = generate_rrsigs(
            &apex,
            RecordsIter::new(&records),
            &keys,
            &GenerateRrsigConfig::new(
                TEST_INCEPTION.into(),
                TEST_EXPIRATION.into(),
            ),
        )
        .unwrap();

        // Check the generated RRSIG records
        assert_eq!(
            generated_records,
            [
                mk_rrsig_rr("example.", Rtype::SOA, 1, "example.", &dnskey),
                mk_rrsig_rr(
                    "in_zone.example.",
                    Rtype::A,
                    2,
                    "example.",
                    &dnskey
                ),
            ]
        );
    }

    #[test]
    fn generate_rrsigs_ignores_glue_records() {
        let apex = Name::from_str("example.").unwrap();
        let mut records = SortedRecords::default();
        records.extend([
            mk_soa_rr("example.", "mname.", "rname."),
            mk_ns_rr("example.", "early_sorting_glue."),
            mk_ns_rr("example.", "late_sorting_glue."),
            mk_a_rr("in_zone.example."),
            mk_a_rr("early_sorting_glue."),
            mk_a_rr("late_sorting_glue."),
        ]);

        // Prepare a zone signing key and a key signing key.
        let keys = [&mk_dnssec_signing_key(true)];
        let dnskey = keys[0].dnskey().convert();

        let generated_records = generate_rrsigs(
            &apex,
            RecordsIter::new(&records),
            &keys,
            &GenerateRrsigConfig::new(
                TEST_INCEPTION.into(),
                TEST_EXPIRATION.into(),
            ),
        )
        .unwrap();

        // Check the generated RRSIG records
        assert_eq!(
            generated_records,
            [
                mk_rrsig_rr("example.", Rtype::NS, 1, "example.", &dnskey),
                mk_rrsig_rr("example.", Rtype::SOA, 1, "example.", &dnskey),
                mk_rrsig_rr(
                    "in_zone.example.",
                    Rtype::A,
                    2,
                    "example.",
                    &dnskey
                ),
            ]
        );
    }

    #[test]
    fn generate_rrsigs_for_complete_zone_with_csk() {
        let keys = [&mk_dnssec_signing_key(true)];
        let cfg = GenerateRrsigConfig::new(
            TEST_INCEPTION.into(),
            TEST_EXPIRATION.into(),
        );
        generate_rrsigs_for_complete_zone(&keys, 0, 0, &cfg).unwrap();
    }

    #[test]
    fn generate_rrsigs_for_complete_zone_with_only_zsk() {
        let keys = [&mk_dnssec_signing_key(false)];
        let cfg = GenerateRrsigConfig::new(
            TEST_INCEPTION.into(),
            TEST_EXPIRATION.into(),
        );
        generate_rrsigs_for_complete_zone(&keys, 0, 0, &cfg).unwrap();
    }

    fn generate_rrsigs_for_complete_zone(
        keys: &[&SigningKey<Bytes, TestKey>],
        _ksk_idx: usize,
        zsk_idx: usize,
        cfg: &GenerateRrsigConfig,
    ) -> Result<(), SigningError> {
        // See https://datatracker.ietf.org/doc/html/rfc4035#appendix-A
        let zonefile = include_bytes!(
            "../../../../test-data/zonefiles/rfc4035-appendix-A.zone"
        );

        // Load the zone to generate RRSIGs for.
        let apex = Name::from_str("example.").unwrap();
        let records = bytes_to_records(&zonefile[..]);

        // Generate DNSKEYs and RRSIGs.
        let generated_records =
            generate_rrsigs(&apex, RecordsIter::new(&records), keys, cfg)?;

        let dnskeys = keys
            .iter()
            .map(|k| k.dnskey().convert())
            .collect::<Vec<_>>();

        let zsk = &dnskeys[zsk_idx];

        // Check the generated records.
        let mut rrsig_iter = generated_records.iter();

        // The records should be in a fixed canonical order because the input
        // records must be in canonical order, with the exception of the added
        // DNSKEY RRs which will be ordered in the order in the supplied
        // collection of keys to sign with. While we tell users of
        // generate_rrsigs() not to rely on the order of the output, we assume
        // that we know what that order is for this test, but would have to
        // update this test if that order later changes.
        //
        // We check each record explicitly by index because assert_eq() on an
        // array of objects that includes Rrsig produces hard to read output
        // due to the large RRSIG signature bytes being printed one byte per
        // line. It also wouldn't support dynamically checking for certain
        // records based on the signing configuration used.

        // NOTE: As we only invoked generate_rrsigs() and not generate_nsecs()
        // there will not be any RRSIGs covering NSEC records.

        // -- example.

        // RRSIG records should have been generated for the zone apex records,
        // one RRSIG per ZSK used.
        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("example.", Rtype::NS, 1, "example.", zsk)
        );
        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("example.", Rtype::SOA, 1, "example.", zsk)
        );
        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("example.", Rtype::MX, 1, "example.", zsk)
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
            *rrsig_iter.next().unwrap(),
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
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("ai.example.", Rtype::A, 2, "example.", zsk)
        );
        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("ai.example.", Rtype::HINFO, 2, "example.", zsk)
        );
        assert_eq!(
            *rrsig_iter.next().unwrap(),
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
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("ns1.example.", Rtype::A, 2, "example.", zsk)
        );

        // -- ns2.example.

        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("ns2.example.", Rtype::A, 2, "example.", zsk)
        );

        // -- *.w.example.

        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("*.w.example.", Rtype::MX, 2, "example.", zsk)
        );

        // -- x.w.example.

        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("x.w.example.", Rtype::MX, 3, "example.", zsk)
        );

        // -- x.y.w.example.

        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("x.y.w.example.", Rtype::MX, 4, "example.", zsk)
        );

        // -- xx.example.

        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("xx.example.", Rtype::A, 2, "example.", zsk)
        );
        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("xx.example.", Rtype::HINFO, 2, "example.", zsk)
        );
        assert_eq!(
            *rrsig_iter.next().unwrap(),
            mk_rrsig_rr("xx.example.", Rtype::AAAA, 2, "example.", zsk)
        );

        // No other records should have been generated.

        assert!(rrsig_iter.next().is_none());

        Ok(())
    }

    #[test]
    fn generate_rrsigs_for_complete_zone_with_multiple_zsks() {
        let apex = "example.";

        let apex_owner = Name::from_str(apex).unwrap();
        let mut records = SortedRecords::default();
        records.extend([
            mk_soa_rr(apex, "some.mname.", "some.rname."),
            mk_ns_rr(apex, "ns.example."),
            mk_a_rr("ns.example."),
        ]);

        let keys =
            [&mk_dnssec_signing_key(false), &mk_dnssec_signing_key(false)];

        let zsk1 = keys[0].dnskey().convert();
        let zsk2 = keys[1].dnskey().convert();

        let generated_records = generate_rrsigs(
            &apex_owner,
            RecordsIter::new(&records),
            &keys,
            &GenerateRrsigConfig::new(
                TEST_INCEPTION.into(),
                TEST_EXPIRATION.into(),
            ),
        )
        .unwrap();

        // Check the generated records.
        assert_eq!(generated_records.len(), 6);

        // Filter out the records one by one until there should be none left.
        let it = generated_records
            .iter()
            .filter(|&rr| {
                rr != &mk_rrsig_rr(apex, Rtype::SOA, 1, apex, &zsk1)
            })
            .filter(|&rr| {
                rr != &mk_rrsig_rr(apex, Rtype::SOA, 1, apex, &zsk2)
            })
            .filter(|&rr| rr != &mk_rrsig_rr(apex, Rtype::NS, 1, apex, &zsk1))
            .filter(|&rr| rr != &mk_rrsig_rr(apex, Rtype::NS, 1, apex, &zsk2))
            .filter(|&rr| {
                rr != &mk_rrsig_rr("ns.example.", Rtype::A, 2, apex, &zsk1)
            })
            .filter(|&rr| {
                rr != &mk_rrsig_rr("ns.example.", Rtype::A, 2, apex, &zsk2)
            });

        let mut it = it.inspect(|rr| {
            eprintln!(
                "Warning: Unexpected RRSIG RRs remaining after filtering: {} {} => {:?}",
                rr.owner(),
                rr.rtype(),
                rr.data(),
            );
        });

        assert!(it.next().is_none());
    }

    #[test]
    fn generate_rrsigs_for_already_signed_zone() {
        let keys = [&mk_dnssec_signing_key(true)];

        let dnskey = keys[0].dnskey().convert();

        let apex = Name::from_str("example.").unwrap();
        let mut records = SortedRecords::default();
        records.extend([
            // -- example.
            mk_soa_rr("example.", "some.mname.", "some.rname."),
            mk_ns_rr("example.", "ns.example."),
            mk_dnskey_rr("example.", &dnskey),
            mk_nsec_rr("example", "ns.example.", "SOA NS DNSKEY NSEC RRSIG"),
            mk_rrsig_rr("example.", Rtype::SOA, 1, "example.", &dnskey),
            mk_rrsig_rr("example.", Rtype::NS, 1, "example.", &dnskey),
            mk_rrsig_rr("example.", Rtype::DNSKEY, 1, "example.", &dnskey),
            mk_rrsig_rr("example.", Rtype::NSEC, 1, "example.", &dnskey),
            // -- ns.example.
            mk_a_rr("ns.example."),
            mk_nsec_rr("ns.example", "example.", "A NSEC RRSIG"),
            mk_rrsig_rr("ns.example.", Rtype::A, 1, "example.", &dnskey),
            mk_rrsig_rr("ns.example.", Rtype::NSEC, 1, "example.", &dnskey),
        ]);

        let generated_records = generate_rrsigs(
            &apex,
            RecordsIter::new(&records),
            &keys,
            &GenerateRrsigConfig::new(
                TEST_INCEPTION.into(),
                TEST_EXPIRATION.into(),
            ),
        )
        .unwrap();

        // Check the generated records.
        let mut iter = generated_records.iter();

        // The records should be in a fixed canonical order because the input
        // records must be in canonical order, with the exception of the added
        // DNSKEY RRs which will be ordered in the order in the supplied
        // collection of keys to sign with. While we tell users of
        // generate_rrsigs() not to rely on the order of the output, we assume
        // that we know what that order is for this test, but would have to
        // update this test if that order later changes.
        //
        // We check each record explicitly by index because assert_eq() on an
        // array of objects that includes Rrsig produces hard to read output
        // due to the large RRSIG signature bytes being printed one byte per
        // line. It also wouldn't support dynamically checking for certain
        // records based on the signing configuration used.

        // -- example.

        // RRSIG records should have been generated for the zone apex records,
        // one RRSIG per ZSK used, even if RRSIG RRs already exist.
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("example.", Rtype::NS, 1, "example.", &dnskey)
        );
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("example.", Rtype::SOA, 1, "example.", &dnskey)
        );
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("example.", Rtype::NSEC, 1, "example.", &dnskey)
        );

        // -- ns.example.

        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("ns.example.", Rtype::A, 2, "example.", &dnskey)
        );
        assert_eq!(
            *iter.next().unwrap(),
            mk_rrsig_rr("ns.example.", Rtype::NSEC, 2, "example.", &dnskey)
        );

        // No other records should have been generated.

        assert!(iter.next().is_none());
    }

    //------------ Helper fns ------------------------------------------------

    fn mk_dnssec_signing_key(make_ksk: bool) -> SigningKey<Bytes, TestKey> {
        // Note: The flags value has no impact on the role the key will play
        // in signing, that is instead determined by its designated purpose
        // AND the SigningKeyUsageStrategy in use.
        let flags = match make_ksk {
            true => 257,
            false => 256,
        };

        SigningKey::new(
            Name::from_str("example").unwrap(),
            flags,
            TestKey::default(),
        )
    }

    fn mk_dnskey_rr<R>(
        name: &str,
        dnskey: &Dnskey<Bytes>,
    ) -> Record<StoredName, R>
    where
        R: From<Dnskey<Bytes>>,
    {
        test_util::mk_dnskey_rr(
            name,
            dnskey.flags(),
            dnskey.algorithm(),
            dnskey.public_key(),
        )
    }

    fn mk_rrsig_rr<R>(
        name: &str,
        covered_rtype: Rtype,
        labels: u8,
        signer_name: &str,
        dnskey: &Dnskey<Bytes>,
    ) -> Record<StoredName, R>
    where
        R: From<Rrsig<Bytes, StoredName>>,
    {
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

    #[derive(Debug)]
    struct TestKey([u8; 32]);

    impl SignRaw for TestKey {
        fn algorithm(&self) -> SecurityAlgorithm {
            SecurityAlgorithm::ED25519
        }

        fn dnskey(&self) -> Dnskey<Vec<u8>> {
            let flags = 0;
            Dnskey::new(flags, 3, SecurityAlgorithm::ED25519, self.0.to_vec())
                .unwrap()
        }

        fn sign_raw(&self, _data: &[u8]) -> Result<Signature, SignError> {
            Ok(Signature::Ed25519(TEST_SIGNATURE_RAW.into()))
        }
    }

    impl Default for TestKey {
        fn default() -> Self {
            Self(rand::thread_rng().gen())
        }
    }
}
