//! Types for tuning configurable aspects of DNSSEC signing.
use core::marker::PhantomData;

use octseq::{EmptyBuilder, FromBuilder};

use crate::base::{Name, ToName};
use crate::sign::denial::config::DenialConfig;
use crate::sign::denial::nsec3::{
    Nsec3HashProvider, OnDemandNsec3HashProvider,
};
use crate::sign::records::{DefaultSorter, Sorter};
use crate::sign::signatures::strategy::DefaultSigningKeyUsageStrategy;
use crate::sign::signatures::strategy::RrsigValidityPeriodStrategy;
use crate::sign::signatures::strategy::SigningKeyUsageStrategy;
use crate::sign::SignRaw;

//------------ SigningConfig -------------------------------------------------

/// Signing configuration for a DNSSEC signed zone.
pub struct SigningConfig<
    N,
    Octs,
    Inner,
    KeyStrat,
    ValidityStrat,
    Sort,
    HP = OnDemandNsec3HashProvider<Octs>,
> where
    HP: Nsec3HashProvider<N, Octs>,
    Octs: AsRef<[u8]> + From<&'static [u8]>,
    Inner: SignRaw,
    KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
    ValidityStrat: RrsigValidityPeriodStrategy,
    Sort: Sorter,
{
    /// Authenticated denial of existing mechanism configuration.
    pub denial: DenialConfig<N, Octs, HP, Sort>,

    /// Should keys used to sign the zone be added as DNSKEY RRs?
    pub add_used_dnskeys: bool,

    pub rrsig_validity_period_strategy: ValidityStrat,

    _phantom: PhantomData<(Inner, KeyStrat, Sort)>,
}

impl<N, Octs, Inner, KeyStrat, Sort, ValidityStrat, HP>
    SigningConfig<N, Octs, Inner, KeyStrat, ValidityStrat, Sort, HP>
where
    HP: Nsec3HashProvider<N, Octs>,
    Octs: AsRef<[u8]> + From<&'static [u8]>,
    Inner: SignRaw,
    KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
    ValidityStrat: RrsigValidityPeriodStrategy,
    Sort: Sorter,
{
    pub fn new(
        denial: DenialConfig<N, Octs, HP, Sort>,
        add_used_dnskeys: bool,
        rrsig_validity_period_strategy: ValidityStrat,
    ) -> Self {
        Self {
            denial,
            add_used_dnskeys,
            rrsig_validity_period_strategy,
            _phantom: PhantomData,
        }
    }
}

impl<N, Octs, Inner, ValidityStrat>
    SigningConfig<
        N,
        Octs,
        Inner,
        DefaultSigningKeyUsageStrategy,
        ValidityStrat,
        DefaultSorter,
        OnDemandNsec3HashProvider<Octs>,
    >
where
    N: ToName + From<Name<Octs>>,
    Octs: AsRef<[u8]> + From<&'static [u8]> + FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Inner: SignRaw,
    ValidityStrat: RrsigValidityPeriodStrategy,
{
    pub fn default(rrsig_validity_period_strategy: ValidityStrat) -> Self {
        Self {
            denial: Default::default(),
            add_used_dnskeys: true,
            rrsig_validity_period_strategy,
            _phantom: Default::default(),
        }
    }
}
