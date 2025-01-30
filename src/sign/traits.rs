//! Signing related traits.
//!
//! This module provides traits which can be used to simplify invocation of
//! [`crate::sign::sign_zone()`] for [`Record`] collection types.
use core::convert::From;
use core::fmt::{Debug, Display};
use core::iter::Extend;
use core::marker::Send;
use core::ops::Deref;

use std::boxed::Box;
use std::hash::Hash;
use std::vec::Vec;

use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, Truncate};
use octseq::OctetsFrom;

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::SecAlg;
use crate::base::name::ToName;
use crate::base::record::Record;
use crate::base::Name;
use crate::rdata::ZoneRecordData;
use crate::sign::denial::nsec3::Nsec3HashProvider;
use crate::sign::error::{SignError, SigningError};
use crate::sign::keys::keymeta::DesignatedSigningKey;
use crate::sign::records::{
    DefaultSorter, RecordsIter, Rrset, SortedRecords, Sorter,
};
use crate::sign::sign_zone;
use crate::sign::signatures::rrsigs::generate_rrsigs;
use crate::sign::signatures::rrsigs::GenerateRrsigConfig;
use crate::sign::signatures::rrsigs::RrsigRecords;
use crate::sign::signatures::strategy::RrsigValidityPeriodStrategy;
use crate::sign::signatures::strategy::SigningKeyUsageStrategy;
use crate::sign::SigningConfig;
use crate::sign::{PublicKeyBytes, SignableZoneInOut, Signature};

//----------- SignRaw --------------------------------------------------------

/// Low-level signing functionality.
///
/// Types that implement this trait own a private key and can sign arbitrary
/// information (in the form of slices of bytes).
///
/// Implementing types should validate keys during construction, so that
/// signing does not fail due to invalid keys.  If the implementing type
/// allows [`sign_raw()`] to be called on unvalidated keys, it will have to
/// check the validity of the key for every signature; this is unnecessary
/// overhead when many signatures have to be generated.
///
/// [`sign_raw()`]: SignRaw::sign_raw()
pub trait SignRaw {
    /// The signature algorithm used.
    ///
    /// See [RFC 8624, section 3.1] for IETF implementation recommendations.
    ///
    /// [RFC 8624, section 3.1]: https://datatracker.ietf.org/doc/html/rfc8624#section-3.1
    fn algorithm(&self) -> SecAlg;

    /// The raw public key.
    ///
    /// This can be used to verify produced signatures.  It must use the same
    /// algorithm as returned by [`algorithm()`].
    ///
    /// [`algorithm()`]: Self::algorithm()
    fn raw_public_key(&self) -> PublicKeyBytes;

    /// Sign the given bytes.
    ///
    /// # Errors
    ///
    /// See [`SignError`] for a discussion of possible failure cases.  To the
    /// greatest extent possible, the implementation should check for failure
    /// cases beforehand and prevent them (e.g. when the keypair is created).
    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError>;
}

//------------ SortedExtend --------------------------------------------------

pub trait SortedExtend<N, Octs, Sort>
where
    Sort: Sorter,
{
    fn sorted_extend<
        T: IntoIterator<Item = Record<N, ZoneRecordData<Octs, N>>>,
    >(
        &mut self,
        iter: T,
    );
}

impl<N, Octs, Sort> SortedExtend<N, Octs, Sort>
    for SortedRecords<N, ZoneRecordData<Octs, N>, Sort>
where
    N: Send + PartialEq + ToName,
    Octs: Send,
    Sort: Sorter,
    ZoneRecordData<Octs, N>: CanonicalOrd + PartialEq,
{
    fn sorted_extend<
        T: IntoIterator<Item = Record<N, ZoneRecordData<Octs, N>>>,
    >(
        &mut self,
        iter: T,
    ) {
        // SortedRecords::extend() takes care of sorting and de-duplication so
        // we don't have to.
        self.extend(iter);
    }
}

//---- impl for Vec

impl<N, Octs, Sort> SortedExtend<N, Octs, Sort>
    for Vec<Record<N, ZoneRecordData<Octs, N>>>
where
    N: Send + PartialEq + ToName,
    Octs: Send,
    Sort: Sorter,
    ZoneRecordData<Octs, N>: CanonicalOrd + PartialEq,
{
    fn sorted_extend<
        T: IntoIterator<Item = Record<N, ZoneRecordData<Octs, N>>>,
    >(
        &mut self,
        iter: T,
    ) {
        // This call to extend may add duplicates.
        self.extend(iter);

        // Sort the records using the provided sort implementation.
        Sort::sort_by(self, CanonicalOrd::canonical_cmp);

        // And remove any duplicates that were created.
        // Requires that the vector first be sorted.
        self.dedup();
    }
}

//------------ SignableZone --------------------------------------------------

/// DNSSEC sign an unsigned zone using the given configuration and keys.
///
/// Types that implement this trait can be signed using the trait provided
/// [`sign_zone()`] function which will insert the generated records in order
/// (assuming that it correctly implements [`SortedExtend`]) into the given
/// `out` record collection.
///
/// # Example
///
/// ```
/// # use domain::base::{Name, Record, Serial, Ttl};
/// # use domain::base::iana::Class;
/// # use domain::sign::crypto::common;
/// # use domain::sign::crypto::common::GenerateParams;
/// # use domain::sign::crypto::common::KeyPair;
/// # use domain::sign::keys::SigningKey;
/// # let (sec_bytes, pub_bytes) = common::generate(GenerateParams::Ed25519).unwrap();
/// # let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
/// # let root = Name::<Vec<u8>>::root();
/// # let key = SigningKey::new(root.clone(), 257, key_pair);
/// use domain::rdata::{rfc1035::Soa, ZoneRecordData};
/// use domain::rdata::dnssec::Timestamp;
/// use domain::sign::keys::DnssecSigningKey;
/// use domain::sign::records::SortedRecords;
/// use domain::sign::signatures::strategy::FixedRrsigValidityPeriodStrategy;
/// use domain::sign::traits::SignableZone;
/// use domain::sign::SigningConfig;
///
/// // Create a sorted collection of records.
/// //
/// // Note: You can also use a plain Vec here (or any other type that is
/// // compatible with the SignableZone or SignableZoneInPlace trait bounds)
/// // but then you are responsible for ensuring that records in the zone are
/// // in DNSSEC compatible order, e.g. by calling
/// // `sort_by(CanonicalOrd::canonical_cmp)` before calling `sign_zone()`.
/// let mut records = SortedRecords::default();
///
/// // Insert records into the collection. Just a dummy SOA for this example.
/// let soa = ZoneRecordData::Soa(Soa::new(
///     root.clone(),
///     root.clone(),
///     Serial::now(),
///     Ttl::ZERO,
///     Ttl::ZERO,
///     Ttl::ZERO,
///     Ttl::ZERO));
/// records.insert(Record::new(root, Class::IN, Ttl::ZERO, soa)).unwrap();
///
/// // Generate or import signing keys (see above).
///
/// // Assign signature validity period and operator intent to the keys.
/// let validity = FixedRrsigValidityPeriodStrategy::from((0, 0));
/// let keys = [DnssecSigningKey::new_csk(key)];
///
/// // Create a signing configuration.
/// let mut signing_config = SigningConfig::default(validity);
///
/// // Then generate the records which when added to the zone make it signed.
/// let mut signer_generated_records = SortedRecords::default();
///
/// records.sign_zone(
///     &mut signing_config,
///     &keys,
///     &mut signer_generated_records).unwrap();
/// ```
///
/// [`sign_zone()`]: SignableZone::sign_zone
pub trait SignableZone<N, Octs, Sort>:
    Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>
where
    N: Clone + ToName + From<Name<Octs>> + PartialEq + Ord + Hash,
    Octs: Clone
        + FromBuilder
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Sort: Sorter,
{
    // TODO
    // fn iter_mut<T>(&mut self) -> T;

    /// DNSSEC sign an unsigned zone using the given configuration and keys.
    ///
    /// This function is a convenience wrapper around calling
    /// [`crate::sign::sign_zone()`] function with enum variant
    /// [`SignableZoneInOut::SignInto`].
    fn sign_zone<DSK, Inner, KeyStrat, ValidityStrat, HP, T>(
        &self,
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
        out: &mut T,
    ) -> Result<(), SigningError>
    where
        DSK: DesignatedSigningKey<Octs, Inner>,
        HP: Nsec3HashProvider<N, Octs>,
        Inner: SignRaw,
        N: Display + Send + CanonicalOrd,
        <Octs as FromBuilder>::Builder: Truncate,
        <<Octs as FromBuilder>::Builder as OctetsBuilder>::AppendError: Debug,
        KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
        ValidityStrat: RrsigValidityPeriodStrategy + Clone,
        T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>
            + SortedExtend<N, Octs, Sort>
            + ?Sized,
        Self: Sized,
    {
        let in_out = SignableZoneInOut::new_into(self, out);
        sign_zone(in_out, signing_config, signing_keys)
    }
}

/// DNSSEC sign an unsigned zone using the given configuration and keys.
///
/// Implemented for any type that dereferences to `[Record<N,
/// ZoneRecordData<Octs, N>>]`.
impl<N, Octs, Sort, T> SignableZone<N, Octs, Sort> for T
where
    N: Clone
        + ToName
        + From<Name<Octs>>
        + PartialEq
        + Send
        + CanonicalOrd
        + Ord
        + Hash,
    Octs: Clone
        + FromBuilder
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Sort: Sorter,
    T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>,
{
}

//------------ SignableZoneInPlace -------------------------------------------

/// DNSSEC sign an unsigned zone in-place using the given configuration and
/// keys.
///
/// Types that implement this trait can be signed using the trait provided
/// [`sign_zone()`] function which will insert the generated records in order
/// (assuming that it correctly implements [`SortedExtend`]) into the
/// collection being signed.
///
/// # Example
///
/// ```
/// # use domain::base::{Name, Record, Serial, Ttl};
/// # use domain::base::iana::Class;
/// # use domain::sign::crypto::common;
/// # use domain::sign::crypto::common::GenerateParams;
/// # use domain::sign::crypto::common::KeyPair;
/// # use domain::sign::keys::SigningKey;
/// # let (sec_bytes, pub_bytes) = common::generate(GenerateParams::Ed25519).unwrap();
/// # let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
/// # let root = Name::<Vec<u8>>::root();
/// # let key = SigningKey::new(root.clone(), 257, key_pair);
/// use domain::rdata::{rfc1035::Soa, ZoneRecordData};
/// use domain::rdata::dnssec::Timestamp;
/// use domain::sign::keys::DnssecSigningKey;
/// use domain::sign::records::SortedRecords;
/// use domain::sign::signatures::strategy::FixedRrsigValidityPeriodStrategy;
/// use domain::sign::traits::SignableZoneInPlace;
/// use domain::sign::SigningConfig;
///
/// // Create a sorted collection of records.
/// //
/// // Note: You can also use a plain Vec here (or any other type that is
/// // compatible with the SignableZone or SignableZoneInPlace trait bounds)
/// // but then you are responsible for ensuring that records in the zone are
/// // in DNSSEC compatible order, e.g. by calling
/// // `sort_by(CanonicalOrd::canonical_cmp)` before calling `sign_zone()`.
/// let mut records = SortedRecords::default();
///
/// // Insert records into the collection. Just a dummy SOA for this example.
/// let soa = ZoneRecordData::Soa(Soa::new(
///     root.clone(),
///     root.clone(),
///     Serial::now(),
///     Ttl::ZERO,
///     Ttl::ZERO,
///     Ttl::ZERO,
///     Ttl::ZERO));
/// records.insert(Record::new(root, Class::IN, Ttl::ZERO, soa)).unwrap();
///
/// // Generate or import signing keys (see above).
///
/// // Assign signature validity period and operator intent to the keys.
/// let validity = FixedRrsigValidityPeriodStrategy::from((0, 0));
/// let keys = [DnssecSigningKey::new_csk(key)];
///
/// // Create a signing configuration.
/// let mut signing_config = SigningConfig::default(validity);
///
/// // Then sign the zone in-place.
/// records.sign_zone(&mut signing_config, &keys).unwrap();
/// ```
///
/// [`sign_zone()`]: SignableZoneInPlace::sign_zone
pub trait SignableZoneInPlace<N, Octs, Sort>:
    SignableZone<N, Octs, Sort> + SortedExtend<N, Octs, Sort>
where
    N: Clone + ToName + From<Name<Octs>> + PartialEq + Ord + Hash,
    Octs: Clone
        + FromBuilder
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Self: SortedExtend<N, Octs, Sort> + Sized,
    Sort: Sorter,
{
    /// DNSSEC sign an unsigned zone in-place using the given configuration
    /// and keys.
    ///
    /// This function is a convenience wrapper around calling
    /// [`crate::sign::sign_zone()`] function with enum variant
    /// [`SignableZoneInOut::SignInPlace`].
    fn sign_zone<DSK, Inner, KeyStrat, ValidityStrat, HP>(
        &mut self,
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
        N: Display + Send + CanonicalOrd,
        <Octs as FromBuilder>::Builder: Truncate,
        <<Octs as FromBuilder>::Builder as OctetsBuilder>::AppendError: Debug,
        KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
        ValidityStrat: RrsigValidityPeriodStrategy + Clone,
    {
        let in_out =
            SignableZoneInOut::<_, _, Self, _, _>::new_in_place(self);
        sign_zone(in_out, signing_config, signing_keys)
    }
}

//--- impl SignableZoneInPlace for SortedRecords

/// DNSSEC sign an unsigned zone in-place using the given configuration and
/// keys.
///
/// Implemented for any type that dereferences to `[Record<N,
/// ZoneRecordData<Octs, N>>]` and which implements the [`SortedExtend`]
/// trait.
impl<N, Octs, Sort, T> SignableZoneInPlace<N, Octs, Sort> for T
where
    N: Clone
        + ToName
        + From<Name<Octs>>
        + PartialEq
        + Send
        + CanonicalOrd
        + Hash
        + Ord,
    Octs: Clone
        + FromBuilder
        + From<&'static [u8]>
        + Send
        + OctetsFrom<Vec<u8>>
        + From<Box<[u8]>>
        + Default,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Sort: Sorter,
    T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>,
    T: SortedExtend<N, Octs, Sort> + Sized,
{
}

//------------ Signable ------------------------------------------------------

/// A trait for generating DNSSEC signatures for one or more [`Record`]s.
///
/// Unlike [`SignableZone`] this trait is intended to be implemented by types
/// that represent one or more [`Record`]s that together do **NOT** constitute
/// a full DNS zone, specifically collections that lack the zone apex records.
///
/// Functions offered by this trait will **only** generate `RRSIG` records.
/// Other DNSSEC record types such as `NSEC(3)` and `DNSKEY` can only be
/// generated in the context of a full zone and so will **NOT** be generated
/// by the functions offered by this trait.
///
/// # Example
///
/// ```
/// # use domain::base::Name;
/// # use domain::base::iana::Class;
/// # use domain::sign::crypto::common;
/// # use domain::sign::crypto::common::GenerateParams;
/// # use domain::sign::crypto::common::KeyPair;
/// # use domain::sign::keys::{DnssecSigningKey, SigningKey};
/// # use domain::sign::records::{Rrset, SortedRecords};
/// # let (sec_bytes, pub_bytes) = common::generate(GenerateParams::Ed25519).unwrap();
/// # let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
/// # let root = Name::<Vec<u8>>::root();
/// # let key = SigningKey::new(root, 257, key_pair);
/// # let keys = [DnssecSigningKey::from(key)];
/// # let mut records = SortedRecords::default();
/// use domain::sign::traits::Signable;
/// use domain::sign::signatures::strategy::DefaultSigningKeyUsageStrategy as KeyStrat;
/// use domain::sign::signatures::strategy::FixedRrsigValidityPeriodStrategy;
/// let apex = Name::<Vec<u8>>::root();
/// let rrset = Rrset::new(&records);
/// let validity = FixedRrsigValidityPeriodStrategy::from((0, 0));
/// let generated_records = rrset.sign::<KeyStrat, _>(&apex, &keys, validity).unwrap();
/// ```
pub trait Signable<N, Octs, DSK, Inner, Sort = DefaultSorter>
where
    N: ToName
        + CanonicalOrd
        + Send
        + Display
        + Clone
        + PartialEq
        + From<Name<Octs>>,
    Inner: SignRaw,
    Octs: From<Box<[u8]>>
        + From<&'static [u8]>
        + FromBuilder
        + Clone
        + OctetsFrom<std::vec::Vec<u8>>
        + Send,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Sort: Sorter,
{
    fn owner_rrs(&self) -> RecordsIter<'_, N, ZoneRecordData<Octs, N>>;

    /// Generate `RRSIG` records for this type.
    ///
    /// This function is a thin wrapper around [`generate_rrsigs()`].
    #[allow(clippy::type_complexity)]
    fn sign<KeyStrat, ValidityStrat>(
        &self,
        expected_apex: &N,
        keys: &[DSK],
        rrsig_validity_period_strategy: ValidityStrat,
    ) -> Result<RrsigRecords<N, Octs>, SigningError>
    where
        DSK: DesignatedSigningKey<Octs, Inner>,
        KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
        ValidityStrat: RrsigValidityPeriodStrategy,
    {
        let rrsig_config =
            GenerateRrsigConfig::<N, KeyStrat, ValidityStrat, Sort>::new(
                rrsig_validity_period_strategy,
            )
            .with_zone_apex(expected_apex);

        generate_rrsigs(self.owner_rrs(), keys, &rrsig_config)
    }
}

//--- impl Signable for Rrset

impl<N, Octs, DSK, Inner> Signable<N, Octs, DSK, Inner>
    for Rrset<'_, N, ZoneRecordData<Octs, N>>
where
    Inner: SignRaw,
    N: From<Name<Octs>>
        + PartialEq
        + Clone
        + Display
        + Send
        + CanonicalOrd
        + ToName,
    Octs: octseq::FromBuilder
        + Send
        + OctetsFrom<Vec<u8>>
        + Clone
        + From<&'static [u8]>
        + From<Box<[u8]>>,
    <Octs as FromBuilder>::Builder: AsRef<[u8]> + AsMut<[u8]> + EmptyBuilder,
{
    fn owner_rrs(&self) -> RecordsIter<'_, N, ZoneRecordData<Octs, N>> {
        RecordsIter::new(self.as_slice())
    }
}
