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
use crate::sign::authnonext::nsec3::Nsec3HashProvider;
use crate::sign::error::{SignError, SigningError};
use crate::sign::keys::keymeta::DesignatedSigningKey;
use crate::sign::records::{
    DefaultSorter, RecordsIter, Rrset, SortedRecords, Sorter,
};
use crate::sign::sign_zone;
use crate::sign::signing::config::SigningConfig;
use crate::sign::signing::rrsigs::generate_rrsigs;
use crate::sign::signing::strategy::SigningKeyUsageStrategy;
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

    fn sign_zone<DSK, Inner, KeyStrat, HP, T>(
        &self,
        signing_config: &mut SigningConfig<
            N,
            Octs,
            Inner,
            KeyStrat,
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
        T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>
            + SortedExtend<N, Octs, Sort>
            + ?Sized,
        Self: Sized,
    {
        let in_out = SignableZoneInOut::new_into(self, out);
        sign_zone::<N, Octs, Self, DSK, Inner, KeyStrat, Sort, HP, T>(
            in_out,
            signing_config,
            signing_keys,
        )
    }
}

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
    fn sign_zone<DSK, Inner, KeyStrat, HP>(
        &mut self,
        signing_config: &mut SigningConfig<
            N,
            Octs,
            Inner,
            KeyStrat,
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
    {
        let in_out = SignableZoneInOut::new_in_place(self);
        sign_zone::<N, Octs, Self, DSK, Inner, KeyStrat, Sort, HP, Self>(
            in_out,
            signing_config,
            signing_keys,
        )
    }
}

//--- impl SignableZoneInPlace for SortedRecords

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

    #[allow(clippy::type_complexity)]
    fn sign<KeyStrat>(
        &self,
        expected_apex: &N,
        keys: &[DSK],
    ) -> Result<Vec<Record<N, ZoneRecordData<Octs, N>>>, SigningError>
    where
        DSK: DesignatedSigningKey<Octs, Inner>,
        KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
    {
        generate_rrsigs::<_, _, DSK, _, KeyStrat, Sort>(
            expected_apex,
            self.owner_rrs(),
            keys,
            false,
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
