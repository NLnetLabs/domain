use core::marker::PhantomData;

use octseq::{EmptyBuilder, FromBuilder};

use crate::base::{Name, ToName};
use crate::sign::hashing::config::HashingConfig;
use crate::sign::hashing::nsec3::{
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
    Octs: AsRef<[u8]> + From<&'static [u8]>,
    Key: SignRaw,
    KeyStrat: SigningKeyUsageStrategy<Octs, Key>,
    Sort: Sorter,
    HP = OnDemandNsec3HashProvider<Octs>,
> where
    HP: Nsec3HashProvider<N, Octs>,
{
    /// Hashing configuration.
    pub hashing: HashingConfig<N, Octs, HP>,

    /// Should keys used to sign the zone be added as DNSKEY RRs?
    pub add_used_dnskeys: bool,

    _phantom: PhantomData<(Key, KeyStrat, Sort)>,
}

impl<N, Octs, Key, KeyStrat, Sort, HP>
    SigningConfig<N, Octs, Key, KeyStrat, Sort, HP>
where
    HP: Nsec3HashProvider<N, Octs>,
    Octs: AsRef<[u8]> + From<&'static [u8]>,
    Key: SignRaw,
    KeyStrat: SigningKeyUsageStrategy<Octs, Key>,
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

impl<N, Octs, Key> Default
    for SigningConfig<
        N,
        Octs,
        Key,
        DefaultSigningKeyUsageStrategy,
        DefaultSorter,
        OnDemandNsec3HashProvider<Octs>,
    >
where
    N: ToName + From<Name<Octs>>,
    Octs: AsRef<[u8]> + From<&'static [u8]> + FromBuilder,
    <Octs as FromBuilder>::Builder: EmptyBuilder + AsRef<[u8]> + AsMut<[u8]>,
    Key: SignRaw,
{
    fn default() -> Self {
        Self {
            hashing: Default::default(),
            add_used_dnskeys: true,
            _phantom: Default::default(),
        }
    }
}
