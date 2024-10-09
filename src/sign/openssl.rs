//! Key and Signer using OpenSSL.

#![cfg(feature = "openssl")]
#![cfg_attr(docsrs, doc(cfg(feature = "openssl")))]

use core::fmt;
use std::vec::Vec;

use openssl::{
    bn::BigNum,
    pkey::{self, PKey, Private},
};

use crate::base::iana::SecAlg;

use super::generic;

/// A key pair backed by OpenSSL.
pub struct SecretKey {
    /// The algorithm used by the key.
    algorithm: SecAlg,

    /// The private key.
    pkey: PKey<Private>,
}

impl SecretKey {
    /// Use a generic secret key with OpenSSL.
    ///
    /// # Panics
    ///
    /// Panics if OpenSSL fails or if memory could not be allocated.
    pub fn import<B: AsRef<[u8]> + AsMut<[u8]>>(
        key: generic::SecretKey<B>,
    ) -> Result<Self, ImportError> {
        fn num(slice: &[u8]) -> BigNum {
            let mut v = BigNum::new_secure().unwrap();
            v.copy_from_slice(slice).unwrap();
            v
        }

        let pkey = match &key {
            generic::SecretKey::RsaSha256(k) => {
                let n = BigNum::from_slice(k.n.as_ref()).unwrap();
                let e = BigNum::from_slice(k.e.as_ref()).unwrap();
                let d = num(k.d.as_ref());
                let p = num(k.p.as_ref());
                let q = num(k.q.as_ref());
                let d_p = num(k.d_p.as_ref());
                let d_q = num(k.d_q.as_ref());
                let q_i = num(k.q_i.as_ref());

                // NOTE: The 'openssl' crate doesn't seem to expose
                // 'EVP_PKEY_fromdata', which could be used to replace the
                // deprecated methods called here.

                openssl::rsa::Rsa::from_private_components(
                    n, e, d, p, q, d_p, d_q, q_i,
                )
                .and_then(PKey::from_rsa)
                .unwrap()
            }
            generic::SecretKey::EcdsaP256Sha256(k) => {
                // Calculate the public key manually.
                let ctx = openssl::bn::BigNumContext::new_secure().unwrap();
                let group = openssl::nid::Nid::X9_62_PRIME256V1;
                let group =
                    openssl::ec::EcGroup::from_curve_name(group).unwrap();
                let mut p = openssl::ec::EcPoint::new(&group).unwrap();
                let n = num(k.as_slice());
                p.mul_generator(&group, &n, &ctx).unwrap();
                openssl::ec::EcKey::from_private_components(&group, &n, &p)
                    .and_then(PKey::from_ec_key)
                    .unwrap()
            }
            generic::SecretKey::EcdsaP384Sha384(k) => {
                // Calculate the public key manually.
                let ctx = openssl::bn::BigNumContext::new_secure().unwrap();
                let group = openssl::nid::Nid::SECP384R1;
                let group =
                    openssl::ec::EcGroup::from_curve_name(group).unwrap();
                let mut p = openssl::ec::EcPoint::new(&group).unwrap();
                let n = num(k.as_slice());
                p.mul_generator(&group, &n, &ctx).unwrap();
                openssl::ec::EcKey::from_private_components(&group, &n, &p)
                    .and_then(PKey::from_ec_key)
                    .unwrap()
            }
            generic::SecretKey::Ed25519(k) => {
                PKey::private_key_from_raw_bytes(
                    k.as_ref(),
                    pkey::Id::ED25519,
                )
                .unwrap()
            }
            generic::SecretKey::Ed448(k) => {
                PKey::private_key_from_raw_bytes(k.as_ref(), pkey::Id::ED448)
                    .unwrap()
            }
        };

        Ok(Self {
            algorithm: key.algorithm(),
            pkey,
        })
    }

    /// Export this key into a generic secret key.
    ///
    /// # Panics
    ///
    /// Panics if OpenSSL fails or if memory could not be allocated.
    pub fn export<B>(&self) -> generic::SecretKey<B>
    where
        B: AsRef<[u8]> + AsMut<[u8]> + From<Vec<u8>>,
    {
        // TODO: Consider security implications of secret data in 'Vec's.
        match self.algorithm {
            SecAlg::RSASHA256 => {
                let key = self.pkey.rsa().unwrap();
                generic::SecretKey::RsaSha256(generic::RsaSecretKey {
                    n: key.n().to_vec().into(),
                    e: key.e().to_vec().into(),
                    d: key.d().to_vec().into(),
                    p: key.p().unwrap().to_vec().into(),
                    q: key.q().unwrap().to_vec().into(),
                    d_p: key.dmp1().unwrap().to_vec().into(),
                    d_q: key.dmq1().unwrap().to_vec().into(),
                    q_i: key.iqmp().unwrap().to_vec().into(),
                })
            }
            SecAlg::ECDSAP256SHA256 => {
                let key = self.pkey.ec_key().unwrap();
                let key = key.private_key().to_vec();
                generic::SecretKey::EcdsaP256Sha256(key.try_into().unwrap())
            }
            SecAlg::ECDSAP384SHA384 => {
                let key = self.pkey.ec_key().unwrap();
                let key = key.private_key().to_vec();
                generic::SecretKey::EcdsaP384Sha384(key.try_into().unwrap())
            }
            SecAlg::ED25519 => {
                let key = self.pkey.raw_private_key().unwrap();
                generic::SecretKey::Ed25519(key.try_into().unwrap())
            }
            SecAlg::ED448 => {
                let key = self.pkey.raw_private_key().unwrap();
                generic::SecretKey::Ed448(key.try_into().unwrap())
            }
            _ => unreachable!(),
        }
    }
}

/// Generate a new secret key for the given algorithm.
///
/// If the algorithm is not supported, [`None`] is returned.
///
/// # Panics
///
/// Panics if OpenSSL fails or if memory could not be allocated.
pub fn generate(algorithm: SecAlg) -> Option<SecretKey> {
    let pkey = match algorithm {
        // We generate 3072-bit keys for an estimated 128 bits of security.
        SecAlg::RSASHA256 => openssl::rsa::Rsa::generate(3072)
            .and_then(PKey::from_rsa)
            .unwrap(),
        SecAlg::ECDSAP256SHA256 => {
            let group = openssl::nid::Nid::X9_62_PRIME256V1;
            let group = openssl::ec::EcGroup::from_curve_name(group).unwrap();
            openssl::ec::EcKey::generate(&group)
                .and_then(PKey::from_ec_key)
                .unwrap()
        }
        SecAlg::ECDSAP384SHA384 => {
            let group = openssl::nid::Nid::SECP384R1;
            let group = openssl::ec::EcGroup::from_curve_name(group).unwrap();
            openssl::ec::EcKey::generate(&group)
                .and_then(PKey::from_ec_key)
                .unwrap()
        }
        SecAlg::ED25519 => PKey::generate_ed25519().unwrap(),
        SecAlg::ED448 => PKey::generate_ed448().unwrap(),
        _ => return None,
    };

    Some(SecretKey { algorithm, pkey })
}

/// An error in importing a key into OpenSSL.
#[derive(Clone, Debug)]
pub enum ImportError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// The provided secret key was invalid.
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

impl std::error::Error for ImportError {}

#[cfg(test)]
mod tests {
    use std::vec::Vec;

    use crate::{base::iana::SecAlg, sign::generic};

    const ALGORITHMS: &[SecAlg] = &[
        SecAlg::RSASHA256,
        SecAlg::ECDSAP256SHA256,
        SecAlg::ECDSAP384SHA384,
        SecAlg::ED25519,
        SecAlg::ED448,
    ];

    #[test]
    fn generate_all() {
        for &algorithm in ALGORITHMS {
            let _ = super::generate(algorithm).unwrap();
        }
    }

    #[test]
    fn export_and_import() {
        for &algorithm in ALGORITHMS {
            let key = super::generate(algorithm).unwrap();
            let exp: generic::SecretKey<Vec<u8>> = key.export();
            let imp = super::SecretKey::import(exp).unwrap();
            assert!(key.pkey.public_eq(&imp.pkey));
        }
    }
}
