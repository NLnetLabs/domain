//! Key and Signer using OpenSSL.

use core::fmt;
use std::boxed::Box;

use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    pkey::{self, PKey, Private},
};

use crate::{
    base::iana::SecAlg,
    validate::{RawPublicKey, RsaPublicKey, Signature},
};

use super::{generic, SignRaw};

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
    pub fn from_generic(
        secret: &generic::SecretKey,
        public: &RawPublicKey,
    ) -> Result<Self, FromGenericError> {
        fn num(slice: &[u8]) -> BigNum {
            let mut v = BigNum::new_secure().unwrap();
            v.copy_from_slice(slice).unwrap();
            v
        }

        let pkey = match (secret, public) {
            (
                generic::SecretKey::RsaSha256(s),
                RawPublicKey::RsaSha256(p),
            ) => {
                // Ensure that the public and private key match.
                if p != &RsaPublicKey::from(s) {
                    return Err(FromGenericError::InvalidKey);
                }

                let n = BigNum::from_slice(&s.n).unwrap();
                let e = BigNum::from_slice(&s.e).unwrap();
                let d = num(&s.d);
                let p = num(&s.p);
                let q = num(&s.q);
                let d_p = num(&s.d_p);
                let d_q = num(&s.d_q);
                let q_i = num(&s.q_i);

                // NOTE: The 'openssl' crate doesn't seem to expose
                // 'EVP_PKEY_fromdata', which could be used to replace the
                // deprecated methods called here.

                openssl::rsa::Rsa::from_private_components(
                    n, e, d, p, q, d_p, d_q, q_i,
                )
                .and_then(PKey::from_rsa)
                .unwrap()
            }

            (
                generic::SecretKey::EcdsaP256Sha256(s),
                RawPublicKey::EcdsaP256Sha256(p),
            ) => {
                use openssl::{bn, ec, nid};

                let mut ctx = bn::BigNumContext::new_secure().unwrap();
                let group = nid::Nid::X9_62_PRIME256V1;
                let group = ec::EcGroup::from_curve_name(group).unwrap();
                let n = num(s.as_slice());
                let p = ec::EcPoint::from_bytes(&group, &**p, &mut ctx)
                    .map_err(|_| FromGenericError::InvalidKey)?;
                let k = ec::EcKey::from_private_components(&group, &n, &p)
                    .map_err(|_| FromGenericError::InvalidKey)?;
                k.check_key().map_err(|_| FromGenericError::InvalidKey)?;
                PKey::from_ec_key(k).unwrap()
            }

            (
                generic::SecretKey::EcdsaP384Sha384(s),
                RawPublicKey::EcdsaP384Sha384(p),
            ) => {
                use openssl::{bn, ec, nid};

                let mut ctx = bn::BigNumContext::new_secure().unwrap();
                let group = nid::Nid::SECP384R1;
                let group = ec::EcGroup::from_curve_name(group).unwrap();
                let n = num(s.as_slice());
                let p = ec::EcPoint::from_bytes(&group, &**p, &mut ctx)
                    .map_err(|_| FromGenericError::InvalidKey)?;
                let k = ec::EcKey::from_private_components(&group, &n, &p)
                    .map_err(|_| FromGenericError::InvalidKey)?;
                k.check_key().map_err(|_| FromGenericError::InvalidKey)?;
                PKey::from_ec_key(k).unwrap()
            }

            (generic::SecretKey::Ed25519(s), RawPublicKey::Ed25519(p)) => {
                use openssl::memcmp;

                let id = pkey::Id::ED25519;
                let k = PKey::private_key_from_raw_bytes(&**s, id)
                    .map_err(|_| FromGenericError::InvalidKey)?;
                if memcmp::eq(&k.raw_public_key().unwrap(), &**p) {
                    k
                } else {
                    return Err(FromGenericError::InvalidKey);
                }
            }

            (generic::SecretKey::Ed448(s), RawPublicKey::Ed448(p)) => {
                use openssl::memcmp;

                let id = pkey::Id::ED448;
                let k = PKey::private_key_from_raw_bytes(&**s, id)
                    .map_err(|_| FromGenericError::InvalidKey)?;
                if memcmp::eq(&k.raw_public_key().unwrap(), &**p) {
                    k
                } else {
                    return Err(FromGenericError::InvalidKey);
                }
            }

            // The public and private key types did not match.
            _ => return Err(FromGenericError::InvalidKey),
        };

        Ok(Self {
            algorithm: secret.algorithm(),
            pkey,
        })
    }

    /// Export this key into a generic secret key.
    ///
    /// # Panics
    ///
    /// Panics if OpenSSL fails or if memory could not be allocated.
    pub fn to_generic(&self) -> generic::SecretKey {
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
                let key = key.private_key().to_vec_padded(32).unwrap();
                generic::SecretKey::EcdsaP256Sha256(key.try_into().unwrap())
            }
            SecAlg::ECDSAP384SHA384 => {
                let key = self.pkey.ec_key().unwrap();
                let key = key.private_key().to_vec_padded(48).unwrap();
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

impl SignRaw for SecretKey {
    fn algorithm(&self) -> SecAlg {
        self.algorithm
    }

    fn raw_public_key(&self) -> RawPublicKey {
        match self.algorithm {
            SecAlg::RSASHA256 => {
                let key = self.pkey.rsa().unwrap();
                RawPublicKey::RsaSha256(RsaPublicKey {
                    n: key.n().to_vec().into(),
                    e: key.e().to_vec().into(),
                })
            }
            SecAlg::ECDSAP256SHA256 => {
                let key = self.pkey.ec_key().unwrap();
                let form = openssl::ec::PointConversionForm::UNCOMPRESSED;
                let mut ctx = openssl::bn::BigNumContext::new().unwrap();
                let key = key
                    .public_key()
                    .to_bytes(key.group(), form, &mut ctx)
                    .unwrap();
                RawPublicKey::EcdsaP256Sha256(key.try_into().unwrap())
            }
            SecAlg::ECDSAP384SHA384 => {
                let key = self.pkey.ec_key().unwrap();
                let form = openssl::ec::PointConversionForm::UNCOMPRESSED;
                let mut ctx = openssl::bn::BigNumContext::new().unwrap();
                let key = key
                    .public_key()
                    .to_bytes(key.group(), form, &mut ctx)
                    .unwrap();
                RawPublicKey::EcdsaP384Sha384(key.try_into().unwrap())
            }
            SecAlg::ED25519 => {
                let key = self.pkey.raw_public_key().unwrap();
                RawPublicKey::Ed25519(key.try_into().unwrap())
            }
            SecAlg::ED448 => {
                let key = self.pkey.raw_public_key().unwrap();
                RawPublicKey::Ed448(key.try_into().unwrap())
            }
            _ => unreachable!(),
        }
    }

    fn sign_raw(&self, data: &[u8]) -> Signature {
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;

        match self.algorithm {
            SecAlg::RSASHA256 => {
                let mut s =
                    Signer::new(MessageDigest::sha256(), &self.pkey).unwrap();
                s.set_rsa_padding(openssl::rsa::Padding::PKCS1).unwrap();
                let signature = s.sign_oneshot_to_vec(data).unwrap();
                Signature::RsaSha256(signature.into_boxed_slice())
            }
            SecAlg::ECDSAP256SHA256 => {
                let mut s =
                    Signer::new(MessageDigest::sha256(), &self.pkey).unwrap();
                let signature = s.sign_oneshot_to_vec(data).unwrap();
                // Convert from DER to the fixed representation.
                let signature = EcdsaSig::from_der(&signature).unwrap();
                let r = signature.r().to_vec_padded(32).unwrap();
                let s = signature.s().to_vec_padded(32).unwrap();
                let mut signature = Box::new([0u8; 64]);
                signature[..32].copy_from_slice(&r);
                signature[32..].copy_from_slice(&s);
                Signature::EcdsaP256Sha256(signature)
            }
            SecAlg::ECDSAP384SHA384 => {
                let mut s =
                    Signer::new(MessageDigest::sha384(), &self.pkey).unwrap();
                let signature = s.sign_oneshot_to_vec(data).unwrap();
                // Convert from DER to the fixed representation.
                let signature = EcdsaSig::from_der(&signature).unwrap();
                let r = signature.r().to_vec_padded(48).unwrap();
                let s = signature.s().to_vec_padded(48).unwrap();
                let mut signature = Box::new([0u8; 96]);
                signature[..48].copy_from_slice(&r);
                signature[48..].copy_from_slice(&s);
                Signature::EcdsaP384Sha384(signature)
            }
            SecAlg::ED25519 => {
                let mut s = Signer::new_without_digest(&self.pkey).unwrap();
                let signature =
                    s.sign_oneshot_to_vec(data).unwrap().into_boxed_slice();
                Signature::Ed25519(signature.try_into().unwrap())
            }
            SecAlg::ED448 => {
                let mut s = Signer::new_without_digest(&self.pkey).unwrap();
                let signature =
                    s.sign_oneshot_to_vec(data).unwrap().into_boxed_slice();
                Signature::Ed448(signature.try_into().unwrap())
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
pub enum FromGenericError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// The key's parameters were invalid.
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

impl std::error::Error for FromGenericError {}

#[cfg(test)]
mod tests {
    use std::{string::String, vec::Vec};

    use crate::{
        base::iana::SecAlg,
        sign::{generic, SignRaw},
        validate::Key,
    };

    use super::SecretKey;

    const KEYS: &[(SecAlg, u16)] = &[
        (SecAlg::RSASHA256, 60616),
        (SecAlg::ECDSAP256SHA256, 42253),
        (SecAlg::ECDSAP384SHA384, 33566),
        (SecAlg::ED25519, 56037),
        (SecAlg::ED448, 7379),
    ];

    #[test]
    fn generate() {
        for &(algorithm, _) in KEYS {
            let _ = super::generate(algorithm).unwrap();
        }
    }

    #[test]
    fn generated_roundtrip() {
        for &(algorithm, _) in KEYS {
            let key = super::generate(algorithm).unwrap();
            let gen_key = key.to_generic();
            let pub_key = key.raw_public_key();
            let equiv = SecretKey::from_generic(&gen_key, &pub_key).unwrap();
            assert!(key.pkey.public_eq(&equiv.pkey));
        }
    }

    #[test]
    fn imported_roundtrip() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            let pub_key = pub_key.raw_public_key();

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = generic::SecretKey::parse_from_bind(&data).unwrap();

            let key = SecretKey::from_generic(&gen_key, pub_key).unwrap();

            let equiv = key.to_generic();
            let mut same = String::new();
            equiv.format_as_bind(&mut same).unwrap();

            let data = data.lines().collect::<Vec<_>>();
            let same = same.lines().collect::<Vec<_>>();
            assert_eq!(data, same);
        }
    }

    #[test]
    fn public_key() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = generic::SecretKey::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            let pub_key = pub_key.raw_public_key();

            let key = SecretKey::from_generic(&gen_key, pub_key).unwrap();

            assert_eq!(key.raw_public_key(), *pub_key);
        }
    }

    #[test]
    fn sign() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = generic::SecretKey::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            let pub_key = pub_key.raw_public_key();

            let key = SecretKey::from_generic(&gen_key, pub_key).unwrap();

            let _ = key.sign_raw(b"Hello, World!");
        }
    }
}
