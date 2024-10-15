//! DNSSEC signing using `ring`.

#![cfg(feature = "ring")]
#![cfg_attr(docsrs, doc(cfg(feature = "ring")))]

use core::fmt;
use std::{boxed::Box, vec::Vec};

use ring::signature::KeyPair;

use crate::{
    base::iana::SecAlg,
    validate::{PublicKey, RsaPublicKey, Signature},
};

use super::{generic, Sign};

/// A key pair backed by `ring`.
pub enum SecretKey<'a> {
    /// An RSA/SHA-256 keypair.
    RsaSha256 {
        key: ring::signature::RsaKeyPair,
        rng: &'a dyn ring::rand::SecureRandom,
    },

    /// An ECDSA P-256/SHA-256 keypair.
    EcdsaP256Sha256 {
        key: ring::signature::EcdsaKeyPair,
        rng: &'a dyn ring::rand::SecureRandom,
    },

    /// An ECDSA P-384/SHA-384 keypair.
    EcdsaP384Sha384 {
        key: ring::signature::EcdsaKeyPair,
        rng: &'a dyn ring::rand::SecureRandom,
    },

    /// An Ed25519 keypair.
    Ed25519(ring::signature::Ed25519KeyPair),
}

impl<'a> SecretKey<'a> {
    /// Use a generic keypair with `ring`.
    pub fn from_generic(
        secret: &generic::SecretKey,
        public: &PublicKey,
        rng: &'a dyn ring::rand::SecureRandom,
    ) -> Result<Self, FromGenericError> {
        match (secret, public) {
            (generic::SecretKey::RsaSha256(s), PublicKey::RsaSha256(p)) => {
                // Ensure that the public and private key match.
                if p != &RsaPublicKey::from(s) {
                    return Err(FromGenericError::InvalidKey);
                }

                let components = ring::rsa::KeyPairComponents {
                    public_key: ring::rsa::PublicKeyComponents {
                        n: s.n.as_ref(),
                        e: s.e.as_ref(),
                    },
                    d: s.d.as_ref(),
                    p: s.p.as_ref(),
                    q: s.q.as_ref(),
                    dP: s.d_p.as_ref(),
                    dQ: s.d_q.as_ref(),
                    qInv: s.q_i.as_ref(),
                };
                ring::signature::RsaKeyPair::from_components(&components)
                    .map_err(|_| FromGenericError::InvalidKey)
                    .map(|key| Self::RsaSha256 { key, rng })
            }

            (
                generic::SecretKey::EcdsaP256Sha256(s),
                PublicKey::EcdsaP256Sha256(p),
            ) => {
                let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
                ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
                        alg, s.as_slice(), p.as_slice(), rng)
                    .map_err(|_| FromGenericError::InvalidKey)
                    .map(|key| Self::EcdsaP256Sha256 { key, rng })
            }

            (
                generic::SecretKey::EcdsaP384Sha384(s),
                PublicKey::EcdsaP384Sha384(p),
            ) => {
                let alg = &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING;
                ring::signature::EcdsaKeyPair::from_private_key_and_public_key(
                        alg, s.as_slice(), p.as_slice(), rng)
                    .map_err(|_| FromGenericError::InvalidKey)
                    .map(|key| Self::EcdsaP384Sha384 { key, rng })
            }

            (generic::SecretKey::Ed25519(s), PublicKey::Ed25519(p)) => {
                ring::signature::Ed25519KeyPair::from_seed_and_public_key(
                    s.as_slice(),
                    p.as_slice(),
                )
                .map_err(|_| FromGenericError::InvalidKey)
                .map(Self::Ed25519)
            }

            (generic::SecretKey::Ed448(_), PublicKey::Ed448(_)) => {
                Err(FromGenericError::UnsupportedAlgorithm)
            }

            // The public and private key types did not match.
            _ => Err(FromGenericError::InvalidKey),
        }
    }
}

/// An error in importing a key into `ring`.
#[derive(Clone, Debug)]
pub enum FromGenericError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// The provided keypair was invalid.
    InvalidKey,
}

impl fmt::Display for FromGenericError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::InvalidKey => "malformed or insecure private key",
        })
    }
}

impl<'a> Sign for SecretKey<'a> {
    fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha256 { .. } => SecAlg::RSASHA256,
            Self::EcdsaP256Sha256 { .. } => SecAlg::ECDSAP256SHA256,
            Self::EcdsaP384Sha384 { .. } => SecAlg::ECDSAP384SHA384,
            Self::Ed25519(_) => SecAlg::ED25519,
        }
    }

    fn public_key(&self) -> PublicKey {
        match self {
            Self::RsaSha256 { key, rng: _ } => {
                let components: ring::rsa::PublicKeyComponents<Vec<u8>> =
                    key.public().into();
                PublicKey::RsaSha256(RsaPublicKey {
                    n: components.n.into(),
                    e: components.e.into(),
                })
            }

            Self::EcdsaP256Sha256 { key, rng: _ } => {
                let key = key.public_key().as_ref();
                let key = Box::<[u8]>::from(key);
                PublicKey::EcdsaP256Sha256(key.try_into().unwrap())
            }

            Self::EcdsaP384Sha384 { key, rng: _ } => {
                let key = key.public_key().as_ref();
                let key = Box::<[u8]>::from(key);
                PublicKey::EcdsaP384Sha384(key.try_into().unwrap())
            }

            Self::Ed25519(key) => {
                let key = key.public_key().as_ref();
                let key = Box::<[u8]>::from(key);
                PublicKey::Ed25519(key.try_into().unwrap())
            }
        }
    }

    fn sign(&self, data: &[u8]) -> Signature {
        match self {
            Self::RsaSha256 { key, rng } => {
                let mut buf = vec![0u8; key.public().modulus_len()];
                let pad = &ring::signature::RSA_PKCS1_SHA256;
                key.sign(pad, *rng, data, &mut buf)
                    .expect("random generators do not fail");
                Signature::RsaSha256(buf.into_boxed_slice())
            }
            Self::EcdsaP256Sha256 { key, rng } => {
                let mut buf = Box::new([0u8; 64]);
                buf.copy_from_slice(
                    key.sign(*rng, data)
                        .expect("random generators do not fail")
                        .as_ref(),
                );
                Signature::EcdsaP256Sha256(buf)
            }
            Self::EcdsaP384Sha384 { key, rng } => {
                let mut buf = Box::new([0u8; 96]);
                buf.copy_from_slice(
                    key.sign(*rng, data)
                        .expect("random generators do not fail")
                        .as_ref(),
                );
                Signature::EcdsaP384Sha384(buf)
            }
            Self::Ed25519(key) => {
                let mut buf = Box::new([0u8; 64]);
                buf.copy_from_slice(key.sign(data).as_ref());
                Signature::Ed25519(buf)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        base::iana::SecAlg,
        sign::{generic, Sign},
        validate::PublicKey,
    };

    use super::SecretKey;

    const KEYS: &[(SecAlg, u16)] =
        &[(SecAlg::RSASHA256, 27096), (SecAlg::ED25519, 43769)];

    #[test]
    fn public_key() {
        for &(algorithm, key_tag) in KEYS {
            let name = format!("test.+{:03}+{}", algorithm.to_int(), key_tag);
            let rng = ring::rand::SystemRandom::new();

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = generic::SecretKey::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = PublicKey::from_dnskey_text(&data).unwrap();

            let key =
                SecretKey::from_generic(&gen_key, &pub_key, &rng).unwrap();

            assert_eq!(key.public_key(), pub_key);
        }
    }

    #[test]
    fn sign() {
        for &(algorithm, key_tag) in KEYS {
            let name = format!("test.+{:03}+{}", algorithm.to_int(), key_tag);
            let rng = ring::rand::SystemRandom::new();

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = generic::SecretKey::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = PublicKey::from_dnskey_text(&data).unwrap();

            let key =
                SecretKey::from_generic(&gen_key, &pub_key, &rng).unwrap();

            let _ = key.sign(b"Hello, World!");
        }
    }
}
