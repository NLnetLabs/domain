use smallvec::SmallVec;

use crate::base::Rtype;
use crate::sign::keys::keymeta::DesignatedSigningKey;
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
