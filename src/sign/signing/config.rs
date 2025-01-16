use core::marker::PhantomData;

use octseq::{EmptyBuilder, FromBuilder};

use crate::base::{Name, ToName};
use crate::sign::denial::config::HashingConfig;
use crate::sign::denial::nsec3::{
    Nsec3HashProvider, OnDemandNsec3HashProvider,
};
use crate::sign::records::{DefaultSorter, Sorter};
use crate::sign::signing::strategy::SigningKeyUsageStrategy;
use crate::sign::SignRaw;

use super::strategy::DefaultSigningKeyUsageStrategy;

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
    /// Hashing configuration.
    pub hashing: HashingConfig<N, Octs, HP>,

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
        hashing: HashingConfig<N, Octs, HP>,
        add_used_dnskeys: bool,
    ) -> Self {
        Self {
            hashing,
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
            hashing: Default::default(),
            add_used_dnskeys: true,
            _phantom: Default::default(),
        }
    }
}
