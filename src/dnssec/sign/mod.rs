//! DNSSEC signing.
//!
//! **This module is experimental and likely to change significantly.**
//!
//! This module provides support for DNSSEC ([RFC 9364]) signing of zones and
//! managing of the keys used for signing, with support for `NSEC3` ([RFC
//! 5155]), [RFC 9077] compliant `NSEC(3)` TTLs, and [RFC 9276] compliant
//! `NSEC3` parameter settings.
//!
//! # Background
//!
//! DNSSEC signed zones are normal DNS zones (i.e. with records at the apex
//! such as the `SOA` and `NS` records, records in the zone such as `A`
//! records, and delegations to child zones). What makes them different to
//! non-DNSSEC signed zones is that they also contain additional configuration
//! data such as `DNSKEY` and `NSEC3PARAM` records, a chain of `NSEC(3)`
//! records used to provably deny the existence of records, and `RRSIG`
//! signatures that authenticate the authoritative content of the zone. See
//! "Signed Zone" in [RFC 9499 section 10] for more information.
//!
//! Signatures are generated using a private key and can be validated using
//! the corresponding public key.
//!
//! In a DNSSEC signed zone each generated signature covers a single resource
//! record set (a group of records having the same owner name, class and type)
//! and is stored in an `RRSIG` record under the same owner name in the zone.
//! These `RRSIG` records can then be validated later by a resolver using the
//! public key.
//!
//! Private keys must be stored in a safe location by zone signers while
//! public keys can be stored in `DNSKEY` records in public DNS zones.
//! Validating resolvers query the `DNSKEY`s in order to validate `RRSIG`s in
//! the signed zone and thus authenticate the data which the `RRSIG`s cover.
//! `DNSKEY` records can be trusted because a chain of trust is established
//! from a trust anchor to the signed zone with each parent zone in the chain
//! authenticating the public key used to sign a child zone. A `DS` record in
//! the parent zone that refers to a `DNSKEY` record in the child zone
//! establishes this link.
//!
//! For increased security keys are rotated (aka "rolled") over time. This key
//! rolling has to be carefully orchestrated so that at all times the signed
//! zone which the key belongs to remains valid from the perspective of
//! resolvers.
//!
//! # Usage
//!
//! - To generate and/or import signing keys see the [`crypto`] module.
//! - To sign a collection of [`Record`]s that represent a zone see the
//!   [`SignableZoneInPlace`] trait.
//! - To manage the life cycle of signing keys see the [`keyset`] module.
//!
//! # Advanced usage
//!
//! - For more control over the signing process see the [`SigningConfig`] type
//!   and the [`SigningKeyUsageStrategy`] and [`DnssecSigningKey`] traits.
//! - For additional ways to sign zones see the [`SignableZone`] trait and the
//!   [`sign_zone()`] function.
//! - To invoke specific stages of the signing process manually see the
//!   [`Signable`] trait and the [`generate_nsecs()`], [`generate_nsec3s()`],
//!   [`generate_rrsigs()`] and [`sign_rrset()`] functions.
//! - To generate signatures for arbitrary data see the [`SignRaw`] trait.
//!
//! # Limitations
//!
//! This module does not yet support:
//! - `async` signing (useful for interacting with cryptographic hardware like
//!   Hardware Security Modules (HSMs)).
//! - Re-signing an already signed zone, only unsigned zones can be signed.
//! - Signing of unsorted zones, record collections must be sorted according
//!   to [`CanonicalOrd`].
//! - Signing of [`Zone`] types or via an [`core::iter::Iterator`] over
//!   [`Record`]s, only signing of slices is supported.
//! - Signing with both `NSEC` and `NSEC3` or multiple `NSEC3` configurations
//!   at once.
//! - Rewriting the DNSKEY RR algorithm identifier when using NSEC3 with the
//!   older DSA or RSASHA1 algorithms (which is anyway only possible at
//!   present if you bring your own cryptography).
//!
//! [`common`]: crate::sign::crypto::common
//! [`keyset`]: crate::sign::keys::keyset
//! [`openssl`]: crate::sign::crypto::openssl
//! [`ring`]: crate::sign::crypto::ring
//! [`sign_rrset()`]: crate::sign::signatures::rrsigs::sign_rrset
//! [`DnssecSigningKey`]: crate::sign::keys::DnssecSigningKey
//! [`Record`]: crate::base::record::Record
//! [RFC 5155]: https://rfc-editor.org/rfc/rfc5155
//! [RFC 6781 section 3.1]: https://rfc-editor.org/rfc/rfc6781#section-3.1
//! [RFC 9077]: https://rfc-editor.org/rfc/rfc9077
//! [RFC 9276]: https://rfc-editor.org/rfc/rfc9276
//! [RFC 9364]: https://rfc-editor.org/rfc/rfc9364
//! [RFC 9499 section 10]:
//!     https://www.rfc-editor.org/rfc/rfc9499.html#section-10
//! [`GenerateParams`]: crate::sign::crypto::common::GenerateParams
//! [`KeyPair`]: crate::sign::crypto::common::KeyPair
//! [`SigningKeyUsageStrategy`]:
//!     crate::sign::signing::strategy::SigningKeyUsageStrategy
//! [`Signable`]: crate::sign::traits::Signable
//! [`SignableZone`]: crate::sign::traits::SignableZone
//! [`SignableZoneInPlace`]: crate::sign::traits::SignableZoneInPlace
//! [`SigningKey`]: crate::sign::keys::SigningKey
//! [`SortedRecords`]: crate::sign::SortedRecords
//! [`Zone`]: crate::zonetree::Zone

#![cfg(feature = "unstable-sign")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-sign")))]

pub mod config;
//pub mod crypto;
pub mod denial;
pub mod error;
pub mod keys;
pub mod records;
pub mod signatures;
pub mod traits;

#[cfg(test)]
pub mod test_util;

use crate::crypto::misc::SignRaw;

pub use self::config::SigningConfig;
pub use self::keys::bytes::{RsaSecretKeyBytes, SecretKeyBytes};

use core::fmt::Display;
use core::hash::Hash;
use core::marker::PhantomData;
use core::ops::Deref;

use std::boxed::Box;
use std::fmt::Debug;
use std::vec::Vec;

use crate::base::{CanonicalOrd, ToName};
use crate::base::{Name, Record, Rtype};
use crate::rdata::ZoneRecordData;

use denial::config::DenialConfig;
use denial::nsec::generate_nsecs;
use denial::nsec3::{generate_nsec3s, Nsec3HashProvider, Nsec3Records};
use error::SigningError;
use keys::keymeta::DesignatedSigningKey;
use octseq::{
    EmptyBuilder, FromBuilder, OctetsBuilder, OctetsFrom, Truncate,
};
use records::{RecordsIter, Sorter};
use signatures::rrsigs::{
    generate_rrsigs, GenerateRrsigConfig, RrsigRecords,
};
use signatures::strategy::{
    RrsigValidityPeriodStrategy, SigningKeyUsageStrategy,
};
use traits::{SignableZone, SortedExtend};

//------------ SignableZoneInOut ---------------------------------------------

/// Combined in and out input type for use with [`sign_zone()`].
///
/// This type exists, similar to [`Cow`], to allow [`sign_zone()`] to operate
/// on both mutable and immutable zones as input, acting as an in-out
/// parameter whereby the same zone is read from and written to, or as
/// separate in and out parameters where one is an in parameter, the zone to
/// read from, and the other is an out parameter, the collection to write
/// generated records to.
///
/// Prefer signing via the [`SignableZone`] or [`SignableZoneInPlace`] traits
/// as they handle the construction of this type and calling [`sign_zone()`].
///
/// [`Cow`]: std::borrow::Cow
/// [`SignableZoneInPlace`]: crate::sign::traits::SignableZoneInPlace
pub enum SignableZoneInOut<'a, 'b, N, Octs, S, T, Sort>
where
    N: Clone + ToName + From<Name<Octs>> + Ord + Hash,
    Octs: Clone
        + FromBuilder
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Sort: Sorter,
    T: SortedExtend<N, Octs, Sort> + ?Sized,
{
    SignInPlace(&'a mut T, PhantomData<(N, Octs, Sort)>),
    SignInto(&'a S, &'b mut T),
}

//--- Construction

impl<'a, 'b, N, Octs, S, T, Sort>
    SignableZoneInOut<'a, 'b, N, Octs, S, T, Sort>
where
    N: Clone + ToName + From<Name<Octs>> + Ord + Hash,
    Octs: Clone
        + FromBuilder
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Sort: Sorter,
    T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>
        + SortedExtend<N, Octs, Sort>
        + ?Sized,
{
    /// Create an input suitable for signing a zone in-place.
    fn new_in_place(signable_zone: &'a mut T) -> Self {
        Self::SignInPlace(signable_zone, Default::default())
    }

    /// Create an input suitable for signing a read-only zone.
    ///
    /// Records generated by signing should be written into the provided
    /// separate collection.
    fn new_into(signable_zone: &'a S, out: &'b mut T) -> Self {
        Self::SignInto(signable_zone, out)
    }
}

//--- Accessors

impl<N, Octs, S, T, Sort> SignableZoneInOut<'_, '_, N, Octs, S, T, Sort>
where
    N: Clone + ToName + From<Name<Octs>> + Ord + Hash,
    Octs: Clone
        + FromBuilder
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    S: SignableZone<N, Octs, Sort>,
    Sort: Sorter,
    T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>
        + SortedExtend<N, Octs, Sort>
        + ?Sized,
{
    /// Read-only slice based access to the zone to be signed.
    ///
    /// Allows the zone, whether mutable or immutable, to be accessed via
    /// an immutable reference.
    fn as_slice(&self) -> &[Record<N, ZoneRecordData<Octs, N>>] {
        match self {
            SignableZoneInOut::SignInPlace(input_output, _) => input_output,

            SignableZoneInOut::SignInto(input, _) => input,
        }
    }

    /// Read-only slice based access to the record collection being written
    /// to.
    fn as_out_slice(&self) -> &[Record<N, ZoneRecordData<Octs, N>>] {
        match self {
            SignableZoneInOut::SignInPlace(input_output, _) => input_output,
            SignableZoneInOut::SignInto(_, output) => output,
        }
    }

    /// Add records in sort order to the output.
    ///
    /// For an immutable zone this will cause records to be added to the
    /// separate output collection.
    ///
    /// For a mutable zone this will cause records to be added to the zone
    /// itself.
    ///
    /// The destination type is required via the [`SortedExtend`] trait bound
    /// to ensure that the records are added in [`CanonicalOrd`] order.
    fn sorted_extend<
        U: IntoIterator<Item = Record<N, ZoneRecordData<Octs, N>>>,
    >(
        &mut self,
        iter: U,
    ) {
        match self {
            SignableZoneInOut::SignInPlace(input_output, _) => {
                input_output.sorted_extend(iter)
            }
            SignableZoneInOut::SignInto(_, output) => {
                output.sorted_extend(iter)
            }
        }
    }
}

//------------ sign_zone() ---------------------------------------------------

/// DNSSEC sign an unsigned zone using the given configuration and keys.
///
/// An implementation of [RFC 4035 section 2 Zone Signing] with optional
/// support for NSEC3 ([RFC 5155]), i.e. it will generate `DNSKEY` (if
/// configured), `NSEC` or `NSEC3` (and if NSEC3 is in use then also
/// `NSEC3PARAM`), and `RRSIG` records.
///
/// Signing can either be done in-place (records generated by signing will be
/// added to the record collection being signed) or into some other provided
/// record collection (records generated by signing will be added to the other
/// collection, the record collection being signed will remain untouched).
///
/// Prefer signing via the [`SignableZone`] or [`SignableZoneInPlace`] traits
/// as they handle the construction of the [`SignableZoneInOut`] type and
/// calling of this function for you.
///
/// # Requirements
///
/// The record collection to be signed is required to implement the
/// [`SignableZone`] trait. The collection to extend with generated records is
/// required to implement the [`SortedExtend`] trait, implementations of which
/// are provided for the [`SortedRecords`] and [`Vec`] types.
///
/// The record collection to be signed must meet the following requirements.
/// Failure to meet these requirements will likely lead to incorrect signing
/// output.
///
/// 1. The record collection to be signed **MUST** be ordered according to
///    [`CanonicalOrd`]. This is always true for [`SortedRecords`].
/// 2. The record collection to be signed **MUST** be unsigned, i.e. must not
///    contain `DNSKEY`, `NSEC`, `NSEC3`, `NSEC3PARAM`, or `RRSIG` records.
///
/// <div class="warning">
///
///   When using a type other than [`SortedRecords`] as input to this function
///   you **MUST** be sure that its content is already sorted according to
///   [`CanonicalOrd`] prior to calling this function.
///
/// </div>
///
/// # Limitations
///
/// This function does not yet support:
///
/// - Enforcement of [RFC 5155 section 2 Backwards Compatibility] regarding
///   use of NSEC3 algorithm aliases in DNSKEY RRs.
///
/// - Re-signing, i.e. re-generating expired `RRSIG` signatures, updating the
///   NSEC(3) chain to match added or removed records or adding signatures for
///   another key to an already signed zone e.g. to support key rollover. For
///   the latter case it does however support providing multiple sets of key
///   to sign with the [`SigningKeyUsageStrategy`] implementation being used
///   to determine which keys to use to sign which records.
///
/// - Signing with multiple NSEC(3) configurations at once, e.g. to migrate
///   from NSEC <-> NSEC3 or between NSEC3 configurations.
///
/// - Signing of record collections stored in the [`Zone`] type as it
///   currently only support signing of record slices whereas the records in a
///   [`Zone`] currently only supports a visitor style read interface via
///   [`ReadableZone`] whereby a callback function is invoked for each node
///   that is "walked".
///
/// # Configuration
///
/// Various aspects of the signing process are configurable, see
/// [`SigningConfig`] for more information.
///
/// [`ReadableZone`]: crate::zonetree::ReadableZone
/// [RFC 4035 section 2 Zone Signing]:
///     https://www.rfc-editor.org/rfc/rfc4035.html#section-2
/// [RFC 5155]: https://www.rfc-editor.org/info/rfc5155
/// [RFC 5155 section 2 Backwards Compatibility]:
///     https://www.rfc-editor.org/rfc/rfc5155.html#section-2
/// [`SignableZoneInPlace`]: crate::sign::traits::SignableZoneInPlace
/// [`SortedRecords`]: crate::sign::records::SortedRecords
/// [`Zone`]: crate::zonetree::Zone
pub fn sign_zone<
    N,
    Octs,
    S,
    DSK,
    Inner,
    KeyStrat,
    ValidityStrat,
    Sort,
    HP,
    T,
>(
    mut in_out: SignableZoneInOut<N, Octs, S, T, Sort>,
    signing_config: &mut SigningConfig<
        N,
        Octs,
        Inner,
        KeyStrat,
        ValidityStrat,
        Sort,
        HP,
    >,
    signing_keys: &[DSK],
) -> Result<(), SigningError>
where
    DSK: DesignatedSigningKey<Octs, Inner>,
    HP: Nsec3HashProvider<N, Octs>,
    Inner: SignRaw,
    N: Display
        + Send
        + CanonicalOrd
        + Clone
        + ToName
        + From<Name<Octs>>
        + Ord
        + Hash,
    <Octs as FromBuilder>::Builder:
        Truncate + EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    <<Octs as FromBuilder>::Builder as OctetsBuilder>::AppendError: Debug,
    KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
    ValidityStrat: RrsigValidityPeriodStrategy + Clone,
    S: SignableZone<N, Octs, Sort>,
    Sort: Sorter,
    T: SortedExtend<N, Octs, Sort> + ?Sized,
    Octs: FromBuilder
        + Clone
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>,
{
    // Iterate over the RR sets of the first owner name (should be the apex as
    // the input should be ordered according to [`CanonicalOrd`] and should be
    // a complete zone) to find the SOA record. There should be one and only
    // one SOA record.
    let soa_rr = get_apex_soa_rr(in_out.as_slice())?;

    let apex_owner = soa_rr.owner().clone();

    let owner_rrs = RecordsIter::new(in_out.as_slice());

    match &mut signing_config.denial {
        DenialConfig::AlreadyPresent => {
            // Nothing to do.
        }

        DenialConfig::Nsec(ref cfg) => {
            let nsecs = generate_nsecs(owner_rrs, cfg)?;

            in_out.sorted_extend(nsecs.into_iter().map(Record::from_record));
        }

        DenialConfig::Nsec3(ref mut cfg) => {
            // RFC 5155 7.1 step 5: "Sort the set of NSEC3 RRs into hash
            // order." We store the NSEC3s as we create them and sort them
            // afterwards.
            let Nsec3Records { nsec3s, nsec3param } =
                generate_nsec3s::<N, Octs, HP, Sort>(owner_rrs, cfg)?;

            // Add the generated NSEC3 records.
            in_out.sorted_extend(
                std::iter::once(Record::from_record(nsec3param))
                    .chain(nsec3s.into_iter().map(Record::from_record)),
            );
        }
    }

    if !signing_keys.is_empty() {
        let mut rrsig_config =
            GenerateRrsigConfig::<N, KeyStrat, ValidityStrat, Sort>::new(
                signing_config.rrsig_validity_period_strategy.clone(),
            );
        rrsig_config.add_used_dnskeys = signing_config.add_used_dnskeys;
        rrsig_config.zone_apex = Some(&apex_owner);

        // Sign the NSEC(3)s.
        let owner_rrs = RecordsIter::new(in_out.as_out_slice());

        let RrsigRecords { rrsigs, dnskeys } =
            generate_rrsigs(owner_rrs, signing_keys, &rrsig_config)?;

        // Sorting may not be strictly needed, but we don't have the option to
        // extend without sort at the moment.
        in_out.sorted_extend(
            dnskeys
                .into_iter()
                .map(Record::from_record)
                .chain(rrsigs.into_iter().map(Record::from_record)),
        );

        // Sign the original unsigned records.
        let owner_rrs = RecordsIter::new(in_out.as_slice());

        let RrsigRecords { rrsigs, dnskeys } =
            generate_rrsigs(owner_rrs, signing_keys, &rrsig_config)?;

        // Sorting may not be strictly needed, but we don't have the option to
        // extend without sort at the moment.
        in_out.sorted_extend(
            dnskeys
                .into_iter()
                .map(Record::from_record)
                .chain(rrsigs.into_iter().map(Record::from_record)),
        );
    }

    Ok(())
}

// Assumes that the given records are sorted in [`CanonicalOrd`] order.
fn get_apex_soa_rr<N, Octs>(
    slice: &[Record<N, ZoneRecordData<Octs, N>>],
) -> Result<&Record<N, ZoneRecordData<Octs, N>>, SigningError>
where
    N: ToName,
{
    let first_owner_rrs = RecordsIter::new(slice)
        .next()
        .ok_or(SigningError::SoaRecordCouldNotBeDetermined)?;
    let mut soa_rrs = first_owner_rrs
        .records()
        .filter(|rr| rr.rtype() == Rtype::SOA);
    let soa_rr = soa_rrs
        .next()
        .ok_or(SigningError::SoaRecordCouldNotBeDetermined)?;
    if soa_rrs.next().is_some() {
        return Err(SigningError::SoaRecordCouldNotBeDetermined);
    }
    Ok(soa_rr)
}
