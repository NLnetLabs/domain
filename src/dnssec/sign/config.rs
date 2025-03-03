//! Types for tuning configurable aspects of DNSSEC signing.
use core::marker::PhantomData;

use super::denial::config::DenialConfig;
use super::denial::nsec3::{Nsec3HashProvider, OnDemandNsec3HashProvider};
use super::records::Sorter;
use crate::rdata::dnssec::Timestamp;

//------------ SigningConfig -------------------------------------------------

/// Signing configuration for a DNSSEC signed zone.
pub struct SigningConfig<N, Octs, Sort, HP = OnDemandNsec3HashProvider<Octs>>
where
    HP: Nsec3HashProvider<N, Octs>,
    Octs: AsRef<[u8]> + From<&'static [u8]>,
    Sort: Sorter,
{
    /// Authenticated denial of existing mechanism configuration.
    pub denial: DenialConfig<N, Octs, HP, Sort>,

    pub inception: Timestamp,

    pub expiration: Timestamp,

    _phantom: PhantomData<Sort>,
}

impl<N, Octs, Sort, HP> SigningConfig<N, Octs, Sort, HP>
where
    HP: Nsec3HashProvider<N, Octs>,
    Octs: AsRef<[u8]> + From<&'static [u8]>,
    Sort: Sorter,
{
    pub fn new(
        denial: DenialConfig<N, Octs, HP, Sort>,
        inception: Timestamp,
        expiration: Timestamp,
    ) -> Self {
        Self {
            denial,
            inception,
            expiration,
            _phantom: PhantomData,
        }
    }
}
