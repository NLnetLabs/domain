use smallvec::SmallVec;

use crate::base::Rtype;
use crate::rdata::dnssec::Timestamp;
use crate::sign::keys::keymeta::DesignatedSigningKey;
use crate::sign::records::Rrset;
use crate::sign::SignRaw;

//------------ SigningKeyUsageStrategy ---------------------------------------

// Ala ldns-signzone the default strategy signs with a minimal number of keys
// to keep the response size for the DNSKEY query small, only keys designated
// as being used to sign apex DNSKEY RRs (usually keys with the Secure Entry
// Point (SEP) flag set) will be used to sign DNSKEY RRs.
pub trait SigningKeyUsageStrategy<Octs, Inner>
where
    Octs: AsRef<[u8]>,
    Inner: SignRaw,
{
    const NAME: &'static str;

    fn select_signing_keys_for_rtype<
        DSK: DesignatedSigningKey<Octs, Inner>,
    >(
        candidate_keys: &[DSK],
        rtype: Option<Rtype>,
    ) -> SmallVec<[usize; 4]> {
        if matches!(rtype, Some(Rtype::DNSKEY)) {
            Self::filter_keys(candidate_keys, |k| k.signs_keys())
        } else {
            Self::filter_keys(candidate_keys, |k| k.signs_zone_data())
        }
    }

    fn filter_keys<DSK: DesignatedSigningKey<Octs, Inner>>(
        candidate_keys: &[DSK],
        filter: fn(&DSK) -> bool,
    ) -> SmallVec<[usize; 4]> {
        candidate_keys
            .iter()
            .enumerate()
            .filter_map(|(i, k)| filter(k).then_some(i))
            .collect()
    }
}

//------------ DefaultSigningKeyUsageStrategy --------------------------------

pub struct DefaultSigningKeyUsageStrategy;

impl<Octs, Inner> SigningKeyUsageStrategy<Octs, Inner>
    for DefaultSigningKeyUsageStrategy
where
    Octs: AsRef<[u8]>,
    Inner: SignRaw,
{
    const NAME: &'static str = "Default key usage strategy";
}

//------------ RrsigValidityPeriodStrategy -----------------------------------

/// The strategy for determining the validity period for an RRSIG for an
/// RRSET.
///
/// Determining the right inception time and expiration time to use may depend
/// for example on the RTYPE of the RRSET being signed or on whether jitter
/// should be applied.
///
/// See https://datatracker.ietf.org/doc/html/rfc6781#section-4.4.2.
pub trait RrsigValidityPeriodStrategy {
    fn validity_period_for_rrset<N, D>(
        &self,
        rrset: &Rrset<'_, N, D>,
    ) -> (Timestamp, Timestamp);
}

//------------ FixedRrsigValidityPeriodStrategy ------------------------------

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FixedRrsigValidityPeriodStrategy {
    inception: Timestamp,
    expiration: Timestamp,
}

impl FixedRrsigValidityPeriodStrategy {
    pub fn new(inception: Timestamp, expiration: Timestamp) -> Self {
        Self {
            inception,
            expiration,
        }
    }
}

//--- impl From<(u32, u32)>

impl From<(u32, u32)> for FixedRrsigValidityPeriodStrategy {
    fn from((inception, expiration): (u32, u32)) -> Self {
        Self::new(Timestamp::from(inception), Timestamp::from(expiration))
    }
}

//--- impl RrsigValidityPeriodStrategy

impl RrsigValidityPeriodStrategy for FixedRrsigValidityPeriodStrategy {
    fn validity_period_for_rrset<N, D>(
        &self,
        _rrset: &Rrset<'_, N, D>,
    ) -> (Timestamp, Timestamp) {
        (self.inception, self.expiration)
    }
}
