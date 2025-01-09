use core::cmp::min;
use core::convert::From;
use core::fmt::{Debug, Display};
use core::iter::Extend;
use core::marker::{PhantomData, Send};
use core::ops::Deref;

use std::boxed::Box;
use std::hash::Hash;
use std::vec::Vec;

use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder, Truncate};
use octseq::OctetsFrom;

use super::config::SigningConfig;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::ToName;
use crate::base::record::Record;
use crate::base::Name;
use crate::rdata::ZoneRecordData;
use crate::sign::error::SigningError;
use crate::sign::hashing::config::HashingConfig;
use crate::sign::hashing::nsec::generate_nsecs;
use crate::sign::hashing::nsec3::{
    generate_nsec3s, Nsec3Config, Nsec3HashProvider, Nsec3ParamTtlMode,
    Nsec3Records,
};
use crate::sign::keys::keymeta::DesignatedSigningKey;
use crate::sign::records::{
    DefaultSorter, FamilyName, RecordsIter, Rrset, SortedRecords, Sorter,
};
use crate::sign::signing::rrsigs::generate_rrsigs;
use crate::sign::signing::strategy::SigningKeyUsageStrategy;
use crate::sign::SignRaw;

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

//------------ SignableZoneInOut ---------------------------------------------

enum SignableZoneInOut<'a, 'b, N, Octs, S, T, Sort>
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
    T: SortedExtend<N, Octs, Sort> + ?Sized,
{
    SignInPlace(&'a mut T, PhantomData<(N, Octs, Sort)>),
    SignInto(&'a S, &'b mut T),
}

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
    S: SignableZone<N, Octs, Sort>,
    Sort: Sorter,
    T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>
        + SortedExtend<N, Octs, Sort>
        + ?Sized,
{
    fn new_in_place(signable_zone: &'a mut T) -> Self {
        Self::SignInPlace(signable_zone, Default::default())
    }

    fn new_into(signable_zone: &'a S, out: &'b mut T) -> Self {
        Self::SignInto(signable_zone, out)
    }
}

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
    fn as_slice(&self) -> &[Record<N, ZoneRecordData<Octs, N>>] {
        match self {
            SignableZoneInOut::SignInPlace(input_output, _) => input_output,

            SignableZoneInOut::SignInto(input, _) => input,
        }
    }

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

fn sign_zone<N, Octs, S, Key, KeyStrat, Sort, HP, T>(
    mut in_out: SignableZoneInOut<N, Octs, S, T, Sort>,
    apex: &FamilyName<N>,
    signing_config: &mut SigningConfig<N, Octs, Key, KeyStrat, Sort, HP>,
    signing_keys: &[&dyn DesignatedSigningKey<Octs, Key>],
) -> Result<(), SigningError>
where
    HP: Nsec3HashProvider<N, Octs>,
    Key: SignRaw,
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
    KeyStrat: SigningKeyUsageStrategy<Octs, Key>,
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
    let soa = in_out
        .as_slice()
        .iter()
        .find(|r| r.rtype() == Rtype::SOA)
        .ok_or(SigningError::NoSoaFound)?;
    let ZoneRecordData::Soa(ref soa_data) = soa.data() else {
        return Err(SigningError::NoSoaFound);
    };

    // RFC 9077 updated RFC 4034 (NSEC) and RFC 5155 (NSEC3) to say that
    // the "TTL of the NSEC(3) RR that is returned MUST be the lesser of
    // the MINIMUM field of the SOA record and the TTL of the SOA itself".
    let ttl = min(soa_data.minimum(), soa.ttl());

    let families = RecordsIter::new(in_out.as_slice());

    match &mut signing_config.hashing {
        HashingConfig::Prehashed => {
            // Nothing to do.
        }

        HashingConfig::Nsec => {
            let nsecs = generate_nsecs(
                apex,
                ttl,
                families,
                signing_config.add_used_dnskeys,
            );

            in_out.sorted_extend(nsecs.into_iter().map(Record::from_record));
        }

        HashingConfig::Nsec3(
            Nsec3Config {
                params,
                opt_out,
                ttl_mode,
                hash_provider,
                ..
            },
            extra,
        ) if extra.is_empty() => {
            // RFC 5155 7.1 step 5: "Sort the set of NSEC3 RRs into hash
            // order." We store the NSEC3s as we create them and sort them
            // afterwards.
            let Nsec3Records { recs, mut param } =
                generate_nsec3s::<N, Octs, HP, Sort>(
                    apex,
                    ttl,
                    families,
                    params.clone(),
                    *opt_out,
                    signing_config.add_used_dnskeys,
                    hash_provider,
                )
                .map_err(SigningError::Nsec3HashingError)?;

            let ttl = match ttl_mode {
                Nsec3ParamTtlMode::Fixed(ttl) => *ttl,
                Nsec3ParamTtlMode::Soa => soa.ttl(),
                Nsec3ParamTtlMode::SoaMinimum => {
                    if let ZoneRecordData::Soa(soa_data) = soa.data() {
                        soa_data.minimum()
                    } else {
                        // Errm, this is unexpected. TODO: Should we abort
                        // with an error here about a malformed zonefile?
                        soa.ttl()
                    }
                }
            };

            param.set_ttl(ttl);

            // Add the generated NSEC3 records.
            in_out.sorted_extend(
                std::iter::once(Record::from_record(param))
                    .chain(recs.into_iter().map(Record::from_record)),
            );
        }

        HashingConfig::Nsec3(_nsec3_config, _extra) => {
            todo!();
        }

        HashingConfig::TransitioningNsecToNsec3(
            _nsec3_config,
            _nsec_to_nsec3_transition_state,
        ) => {
            todo!();
        }

        HashingConfig::TransitioningNsec3ToNsec(
            _nsec3_config,
            _nsec3_to_nsec_transition_state,
        ) => {
            todo!();
        }
    }

    if !signing_keys.is_empty() {
        let families = RecordsIter::new(in_out.as_slice());

        let rrsigs_and_dnskeys =
            generate_rrsigs::<N, Octs, Key, KeyStrat, Sort>(
                apex,
                families,
                signing_keys,
                signing_config.add_used_dnskeys,
            )?;

        in_out.sorted_extend(rrsigs_and_dnskeys);
    }

    Ok(())
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
    fn apex(&self) -> Option<FamilyName<N>>;

    // TODO
    // fn iter_mut<T>(&mut self) -> T;

    fn sign_zone<Key, KeyStrat, HP, T>(
        &self,
        signing_config: &mut SigningConfig<N, Octs, Key, KeyStrat, Sort, HP>,
        signing_keys: &[&dyn DesignatedSigningKey<Octs, Key>],
        out: &mut T,
    ) -> Result<(), SigningError>
    where
        HP: Nsec3HashProvider<N, Octs>,
        Key: SignRaw,
        N: Display + Send + CanonicalOrd,
        <Octs as FromBuilder>::Builder: Truncate,
        <<Octs as FromBuilder>::Builder as OctetsBuilder>::AppendError: Debug,
        KeyStrat: SigningKeyUsageStrategy<Octs, Key>,
        T: Deref<Target = [Record<N, ZoneRecordData<Octs, N>>]>
            + SortedExtend<N, Octs, Sort>
            + ?Sized,
        Self: Sized,
    {
        let in_out = SignableZoneInOut::new_into(self, out);
        sign_zone::<N, Octs, Self, Key, KeyStrat, Sort, HP, T>(
            in_out,
            &self.apex().ok_or(SigningError::NoSoaFound)?,
            signing_config,
            signing_keys,
        )
    }
}

//--- impl SignableZone for SortedRecords

impl<N, Octs, Sort> SignableZone<N, Octs, Sort>
    for SortedRecords<N, ZoneRecordData<Octs, N>, Sort>
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
{
    fn apex(&self) -> Option<FamilyName<N>> {
        self.find_soa().map(|soa| soa.family_name().cloned())
    }
}

//--- impl SignableZone for Vec

// NOTE: Assumes that the Vec is already sorted according to CanonicalOrd.
impl<N, Octs, Sort> SignableZone<N, Octs, Sort>
    for Vec<Record<N, ZoneRecordData<Octs, N>>>
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
{
    fn apex(&self) -> Option<FamilyName<N>> {
        self.iter()
            .find(|r| r.rtype() == Rtype::SOA)
            .map(|r| FamilyName::new(r.owner().clone(), r.class()))
    }
}

//------------ SignableZoneInPlace -------------------------------------------

pub trait SignableZoneInPlace<N, Octs, S>:
    SignableZone<N, Octs, S> + SortedExtend<N, Octs, S>
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
    Self: SortedExtend<N, Octs, S> + Sized,
    S: Sorter,
{
    fn sign_zone<Key, KeyStrat, HP>(
        &mut self,
        signing_config: &mut SigningConfig<N, Octs, Key, KeyStrat, S, HP>,
        signing_keys: &[&dyn DesignatedSigningKey<Octs, Key>],
    ) -> Result<(), SigningError>
    where
        HP: Nsec3HashProvider<N, Octs>,
        Key: SignRaw,
        N: Display + Send + CanonicalOrd,
        <Octs as FromBuilder>::Builder: Truncate,
        <<Octs as FromBuilder>::Builder as OctetsBuilder>::AppendError: Debug,
        KeyStrat: SigningKeyUsageStrategy<Octs, Key>,
    {
        let apex = self.apex().ok_or(SigningError::NoSoaFound)?;
        let in_out = SignableZoneInOut::new_in_place(self);
        sign_zone::<N, Octs, Self, Key, KeyStrat, S, HP, Self>(
            in_out,
            &apex,
            signing_config,
            signing_keys,
        )
    }
}

//--- impl SignableZoneInPlace for SortedRecords

impl<N, Octs, Sort> SignableZoneInPlace<N, Octs, Sort>
    for SortedRecords<N, ZoneRecordData<Octs, N>, Sort>
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
{
}

//------------ Signable ------------------------------------------------------

pub trait Signable<N, Octs, KeyPair, Sort = DefaultSorter>
where
    N: ToName
        + CanonicalOrd
        + Send
        + Display
        + Clone
        + PartialEq
        + From<Name<Octs>>,
    KeyPair: SignRaw,
    Octs: From<Box<[u8]>>
        + From<&'static [u8]>
        + FromBuilder
        + Clone
        + OctetsFrom<std::vec::Vec<u8>>
        + Send,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Sort: Sorter,
{
    fn families(&self) -> RecordsIter<'_, N, ZoneRecordData<Octs, N>>;

    #[allow(clippy::type_complexity)]
    fn sign<KeyStrat>(
        &self,
        apex: &FamilyName<N>,
        keys: &[&dyn DesignatedSigningKey<Octs, KeyPair>],
    ) -> Result<Vec<Record<N, ZoneRecordData<Octs, N>>>, SigningError>
    where
        KeyStrat: SigningKeyUsageStrategy<Octs, KeyPair>,
    {
        generate_rrsigs::<_, _, _, KeyStrat, Sort>(
            apex,
            self.families(),
            keys,
            false,
        )
    }
}

//--- impl Signable for Rrset

impl<N, Octs, KeyPair> Signable<N, Octs, KeyPair>
    for Rrset<'_, N, ZoneRecordData<Octs, N>>
where
    KeyPair: SignRaw,
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
    fn families(&self) -> RecordsIter<'_, N, ZoneRecordData<Octs, N>> {
        RecordsIter::new(self.as_slice())
    }
}
