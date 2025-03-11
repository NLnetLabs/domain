//! Types for tuning configurable aspects of DNSSEC signing.
use core::marker::PhantomData;

use super::denial::config::DenialConfig;
use super::records::Sorter;
use crate::rdata::dnssec::Timestamp;

//------------ SigningConfig -------------------------------------------------

/// Signing configuration for a DNSSEC signed zone.
pub struct SigningConfig<Octs, Sort>
where
    Octs: AsRef<[u8]> + From<&'static [u8]>,
    Sort: Sorter,
{
    /// Authenticated denial of existing mechanism configuration.
    pub denial: DenialConfig<Octs, Sort>,

    pub inception: Timestamp,

    pub expiration: Timestamp,

    _phantom: PhantomData<Sort>,
}

impl<Octs, Sort> SigningConfig<Octs, Sort>
where
    Octs: AsRef<[u8]> + From<&'static [u8]>,
    Sort: Sorter,
{
    pub fn new(
        denial: DenialConfig<Octs, Sort>,
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
