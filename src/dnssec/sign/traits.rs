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
use crate::base::name::ToName;
use crate::base::record::Record;
use crate::base::Name;
use crate::crypto::misc::SignRaw;
use crate::dnssec::sign::denial::nsec3::Nsec3HashProvider;
use crate::dnssec::sign::error::SigningError;
use crate::dnssec::sign::keys::keymeta::DesignatedSigningKey;
use crate::dnssec::sign::records::{
    DefaultSorter, RecordsIter, Rrset, SortedRecords, Sorter,
};
use crate::dnssec::sign::sign_zone;
use crate::dnssec::sign::signatures::rrsigs::generate_rrsigs;
use crate::dnssec::sign::signatures::rrsigs::GenerateRrsigConfig;
use crate::dnssec::sign::signatures::rrsigs::RrsigRecords;
use crate::dnssec::sign::signatures::strategy::SigningKeyUsageStrategy;
use crate::dnssec::sign::SignableZoneInOut;
use crate::dnssec::sign::SigningConfig;
use crate::rdata::dnssec::Timestamp;
use crate::rdata::ZoneRecordData;

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
/// # use domain::crypto::common;
/// # use domain::crypto::common::GenerateParams;
/// # use domain::crypto::common::KeyPair;
/// # use domain::dnssec::sign::keys::SigningKey;
/// # let (sec_bytes, pub_bytes) = common::generate(GenerateParams::Ed25519).unwrap();
/// # let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
/// # let root = Name::<Vec<u8>>::root();
/// # let key = SigningKey::new(root.clone(), 257, key_pair);
/// use domain::rdata::{rfc1035::Soa, ZoneRecordData};
/// use domain::rdata::dnssec::Timestamp;
/// use domain::dnssec::sign::keys::DnssecSigningKey;
/// use domain::dnssec::sign::records::SortedRecords;
/// use domain::dnssec::sign::traits::SignableZone;
/// use domain::dnssec::sign::SigningConfig;
/// use domain::dnssec::sign::signatures::strategy::DefaultSigningKeyUsageStrategy;
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
/// let keys = [DnssecSigningKey::new_csk(key)];
///
/// // Create a signing configuration.
/// let mut signing_config = SigningConfig::new(Default::default(), false, 0.into(), 0.into());
///
/// // Then generate the records which when added to the zone make it signed.
/// let mut signer_generated_records = SortedRecords::default();
///
/// records.sign_zone::<_,_, DefaultSigningKeyUsageStrategy, _, _>(
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
    fn sign_zone<DSK, Inner, KeyStrat, HP, T>(
        &self,
        signing_config: &mut SigningConfig<N, Octs, Sort, HP>,
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
        T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>
            + SortedExtend<N, Octs, Sort>
            + ?Sized,
        Self: Sized,
    {
        let in_out = SignableZoneInOut::new_into(self, out);
        sign_zone::<N, Octs, _, DSK, Inner, KeyStrat, Sort, HP, T>(
            in_out,
            signing_config,
            signing_keys,
        )
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
/// # use domain::crypto::common;
/// # use domain::crypto::common::GenerateParams;
/// # use domain::crypto::common::KeyPair;
/// # use domain::dnssec::sign::keys::SigningKey;
/// # let (sec_bytes, pub_bytes) = common::generate(GenerateParams::Ed25519).unwrap();
/// # let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
/// # let root = Name::<Vec<u8>>::root();
/// # let key = SigningKey::new(root.clone(), 257, key_pair);
/// use domain::rdata::{rfc1035::Soa, ZoneRecordData};
/// use domain::rdata::dnssec::Timestamp;
/// use domain::dnssec::sign::keys::DnssecSigningKey;
/// use domain::dnssec::sign::records::SortedRecords;
/// use domain::dnssec::sign::traits::SignableZoneInPlace;
/// use domain::dnssec::sign::SigningConfig;
/// use domain::dnssec::sign::records::DefaultSorter;
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
/// let soa = ZoneRecordData::<Vec<u8>, _>::Soa(Soa::new(
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
/// let keys = [DnssecSigningKey::new_csk(key)];
///
/// // Create a signing configuration.
/// let mut signing_config: SigningConfig<Name<Vec<u8>>, Vec<u8>, DefaultSorter> = SigningConfig::new(Default::default(), false, 0.into(), 0.into());
///
/// // Then sign the zone in-place.
//r records.sign_zone::<DefaultSigningKeyUsageStrategy>(&mut signing_config, &keys).unwrap();
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
    fn sign_zone<DSK, Inner, KeyStrat, HP>(
        &mut self,
        signing_config: &mut SigningConfig<N, Octs, Sort, HP>,
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
    {
        let in_out =
            SignableZoneInOut::<_, _, Self, _, _>::new_in_place(self);
        sign_zone::<N, Octs, _, DSK, Inner, KeyStrat, Sort, HP, _>(
            in_out,
            signing_config,
            signing_keys,
        )
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
/// # use domain::crypto::common;
/// # use domain::crypto::common::GenerateParams;
/// # use domain::crypto::common::KeyPair;
/// # use domain::dnssec::sign::keys::{DnssecSigningKey, SigningKey};
/// # use domain::dnssec::sign::records::{Rrset, SortedRecords};
/// # let (sec_bytes, pub_bytes) = common::generate(GenerateParams::Ed25519).unwrap();
/// # let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
/// # let root = Name::<Vec<u8>>::root();
/// # let key = SigningKey::new(root, 257, key_pair);
/// # let keys = [DnssecSigningKey::from(key)];
/// # let mut records = SortedRecords::default();
/// use domain::dnssec::sign::traits::Signable;
/// use domain::dnssec::sign::signatures::strategy::DefaultSigningKeyUsageStrategy as KeyStrat;
/// let apex = Name::<Vec<u8>>::root();
/// let rrset = Rrset::new(&records);
/// let generated_records = rrset.sign::<KeyStrat>(&apex, &keys, 0.into(), 0.into()).unwrap();
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
    fn sign<KeyStrat>(
        &self,
        expected_apex: &N,
        keys: &[DSK],
        inception: Timestamp,
        expiration: Timestamp,
    ) -> Result<RrsigRecords<N, Octs>, SigningError>
    where
        DSK: DesignatedSigningKey<Octs, Inner>,
        KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
    {
        let rrsig_config =
            GenerateRrsigConfig::<N, Sort>::new(inception, expiration)
                .with_zone_apex(expected_apex);

        generate_rrsigs::<N, Octs, DSK, Inner, KeyStrat, Sort>(
            self.owner_rrs(),
            keys,
            &rrsig_config,
        )
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
