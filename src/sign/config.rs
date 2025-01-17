//! Types for tuning configurable aspects of DNSSEC signing.
use core::marker::PhantomData;

use octseq::{EmptyBuilder, FromBuilder};

use super::signatures::strategy::DefaultSigningKeyUsageStrategy;
use crate::base::{Name, ToName};
use crate::sign::denial::config::DenialConfig;
use crate::sign::denial::nsec3::{
    Nsec3HashProvider, OnDemandNsec3HashProvider,
};
use crate::sign::records::{DefaultSorter, Sorter};
use crate::sign::signatures::strategy::SigningKeyUsageStrategy;
use crate::sign::SignRaw;

//------------ SigningConfig -------------------------------------------------

/// Signing configuration for a DNSSEC signed zone.
pub struct SigningConfig<
    N,
    Octs,
    Inner,
    KeyStrat,
    Sort,
    HP = OnDemandNsec3HashProvider<Octs>,
> where
    HP: Nsec3HashProvider<N, Octs>,
    Octs: AsRef<[u8]> + From<&'static [u8]>,
    Inner: SignRaw,
    KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
    Sort: Sorter,
{
    /// Authenticated denial of existing mechanism configuration.
    pub denial: DenialConfig<N, Octs, HP>,

    /// Should keys used to sign the zone be added as DNSKEY RRs?
    pub add_used_dnskeys: bool,

    _phantom: PhantomData<(Inner, KeyStrat, Sort)>,
}

impl<N, Octs, Inner, KeyStrat, Sort, HP>
    SigningConfig<N, Octs, Inner, KeyStrat, Sort, HP>
where
    HP: Nsec3HashProvider<N, Octs>,
    Octs: AsRef<[u8]> + From<&'static [u8]>,
    Inner: SignRaw,
    KeyStrat: SigningKeyUsageStrategy<Octs, Inner>,
    Sort: Sorter,
{
    pub fn new(
        denial: DenialConfig<N, Octs, HP>,
        add_used_dnskeys: bool,
    ) -> Self {
        Self {
            denial,
            add_used_dnskeys,
            _phantom: PhantomData,
        }
    }
}

impl<N, Octs, Inner> Default
    for SigningConfig<
        N,
        Octs,
        Inner,
        DefaultSigningKeyUsageStrategy,
        DefaultSorter,
        OnDemandNsec3HashProvider<Octs>,
    >
where
    N: ToName + From<Name<Octs>>,
    Octs: AsRef<[u8]> + From<&'static [u8]> + FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Inner: SignRaw,
{
    fn default() -> Self {
        Self {
            denial: Default::default(),
            add_used_dnskeys: true,
            _phantom: Default::default(),
        }
    }
}
