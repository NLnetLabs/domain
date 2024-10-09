//! DNSSEC signing using `ring`.

#![cfg(feature = "ring")]
#![cfg_attr(docsrs, doc(cfg(feature = "ring")))]

use core::fmt;
use std::vec::Vec;

use crate::base::iana::SecAlg;

use super::generic;

/// A key pair backed by `ring`.
pub enum SecretKey<'a> {
    /// An RSA/SHA-256 keypair.
    RsaSha256 {
        key: ring::signature::RsaKeyPair,
        rng: &'a dyn ring::rand::SecureRandom,
    },

    /// An Ed25519 keypair.
    Ed25519(ring::signature::Ed25519KeyPair),
}

impl<'a> SecretKey<'a> {
    /// Use a generic keypair with `ring`.
    pub fn import<B: AsRef<[u8]> + AsMut<[u8]>>(
        key: generic::SecretKey<B>,
        rng: &'a dyn ring::rand::SecureRandom,
    ) -> Result<Self, ImportError> {
        match &key {
            generic::SecretKey::RsaSha256(k) => {
                let components = ring::rsa::KeyPairComponents {
                    public_key: ring::rsa::PublicKeyComponents {
                        n: k.n.as_ref(),
                        e: k.e.as_ref(),
                    },
                    d: k.d.as_ref(),
                    p: k.p.as_ref(),
                    q: k.q.as_ref(),
                    dP: k.d_p.as_ref(),
                    dQ: k.d_q.as_ref(),
                    qInv: k.q_i.as_ref(),
                };
                ring::signature::RsaKeyPair::from_components(&components)
                    .inspect_err(|e| println!("Got err {e:?}"))
                    .map_err(|_| ImportError::InvalidKey)
                    .map(|key| Self::RsaSha256 { key, rng })
            }
            // TODO: Support ECDSA.
            generic::SecretKey::Ed25519(k) => {
                let k = k.as_ref();
                ring::signature::Ed25519KeyPair::from_seed_unchecked(k)
                    .map_err(|_| ImportError::InvalidKey)
                    .map(Self::Ed25519)
            }
            _ => Err(ImportError::UnsupportedAlgorithm),
        }
    }

    /// Export this key into a generic public key.
    pub fn export_public<B>(&self) -> generic::PublicKey<B>
    where
        B: AsRef<[u8]> + From<Vec<u8>>,
    {
        match self {
            Self::RsaSha256 { key, rng: _ } => {
                let components: ring::rsa::PublicKeyComponents<Vec<u8>> =
                    key.public().into();
                generic::PublicKey::RsaSha256(generic::RsaPublicKey {
                    n: components.n.into(),
                    e: components.e.into(),
                })
            }
            Self::Ed25519(key) => {
                use ring::signature::KeyPair;
                let key = key.public_key().as_ref();
                generic::PublicKey::Ed25519(key.try_into().unwrap())
            }
        }
    }
}

/// An error in importing a key into `ring`.
#[derive(Clone, Debug)]
pub enum ImportError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// The provided keypair was invalid.
    InvalidKey,
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::InvalidKey => "malformed or insecure private key",
        })
    }
}

impl<'a> super::Sign<Vec<u8>> for SecretKey<'a> {
    type Error = ring::error::Unspecified;

    fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha256 { .. } => SecAlg::RSASHA256,
            Self::Ed25519(_) => SecAlg::ED25519,
        }
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        match self {
            Self::RsaSha256 { key, rng } => {
                let mut buf = vec![0u8; key.public().modulus_len()];
                let pad = &ring::signature::RSA_PKCS1_SHA256;
                key.sign(pad, *rng, data, &mut buf)?;
                Ok(buf)
            }
            Self::Ed25519(key) => Ok(key.sign(data).as_ref().to_vec()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use crate::{
        base::{iana::SecAlg, scan::IterScanner},
        rdata::Dnskey,
        sign::generic,
    };

    const KEYS: &[(SecAlg, u16)] =
        &[(SecAlg::RSASHA256, 27096), (SecAlg::ED25519, 43769)];

    #[test]
    fn export_public() {
        type GenericSecretKey = generic::SecretKey<Vec<u8>>;
        type GenericPublicKey = generic::PublicKey<Vec<u8>>;

        for &(algorithm, key_tag) in KEYS {
            let name = format!("test.+{:03}+{}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let sec_key = GenericSecretKey::from_dns(&data).unwrap();
            let rng = ring::rand::SystemRandom::new();
            let sec_key = super::SecretKey::import(sec_key, &rng).unwrap();
            let pub_key: GenericPublicKey = sec_key.export_public();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let mut data = std::fs::read_to_string(path).unwrap();
            // Remove a trailing comment, if any.
            if let Some(pos) = data.bytes().position(|b| b == b';') {
                data.truncate(pos);
            }
            // Skip '<domain-name> <record-class> <record-type>'
            let data = data.split_ascii_whitespace().skip(3);
            let mut data = IterScanner::new(data);
            let dns_key: Dnskey<Vec<u8>> = Dnskey::scan(&mut data).unwrap();

            assert_eq!(dns_key.key_tag(), key_tag);
            assert_eq!(pub_key.into_dns::<Vec<u8>>(256), dns_key)
        }
    }
}
