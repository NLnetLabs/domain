use std::collections::HashSet;

use crate::base::Rtype;
use crate::sign::keys::keymeta::DesignatedSigningKey;
use crate::sign::SignRaw;

//------------ SigningKeyUsageStrategy ---------------------------------------

pub trait SigningKeyUsageStrategy<Octs, Inner>
where
    Octs: AsRef<[u8]>,
    Inner: SignRaw,
{
    const NAME: &'static str;

    fn select_signing_keys_for_rtype<K: DesignatedSigningKey<Octs, Inner>>(
        candidate_keys: &[K],
        rtype: Option<Rtype>,
    ) -> HashSet<usize> {
        if matches!(rtype, Some(Rtype::DNSKEY)) {
            Self::filter_keys(candidate_keys, |k| k.signs_keys())
        } else {
            Self::filter_keys(candidate_keys, |k| k.signs_zone_data())
        }
    }

    fn filter_keys<K: DesignatedSigningKey<Octs, Inner>>(
        candidate_keys: &[K],
        filter: fn(&K) -> bool,
    ) -> HashSet<usize> {
        candidate_keys
            .iter()
            .enumerate()
            .filter_map(|(i, k)| filter(k).then_some(i))
            .collect::<HashSet<_>>()
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
