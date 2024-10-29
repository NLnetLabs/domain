//! DNSSEC signing using OpenSSL.

#![cfg(feature = "openssl")]
#![cfg_attr(docsrs, doc(cfg(feature = "openssl")))]

use core::fmt;
use std::vec::Vec;

use openssl::{
    bn::BigNum,
    ecdsa::EcdsaSig,
    error::ErrorStack,
    pkey::{self, PKey, Private},
};

use crate::{
    base::iana::SecAlg,
    validate::{RawPublicKey, RsaPublicKey, Signature},
};

use super::{GenerateParams, KeyBytes, RsaKeyBytes, SignError, SignRaw};

//----------- KeyPair --------------------------------------------------------

/// A key pair backed by OpenSSL.
pub struct KeyPair {
    /// The algorithm used by the key.
    algorithm: SecAlg,

    /// The private key.
    pkey: PKey<Private>,
}

//--- Conversion to and from bytes

impl KeyPair {
    /// Import a key pair from bytes into OpenSSL.
    pub fn from_bytes(
        secret: &KeyBytes,
        public: &RawPublicKey,
    ) -> Result<Self, FromBytesError> {
        fn num(slice: &[u8]) -> Result<BigNum, FromBytesError> {
            let mut v = BigNum::new()?;
            v.copy_from_slice(slice)?;
            Ok(v)
        }

        fn secure_num(slice: &[u8]) -> Result<BigNum, FromBytesError> {
            let mut v = BigNum::new_secure()?;
            v.copy_from_slice(slice)?;
            Ok(v)
        }

        let pkey = match (secret, public) {
            (KeyBytes::RsaSha256(s), RawPublicKey::RsaSha256(p)) => {
                // Ensure that the public and private key match.
                if p != &RsaPublicKey::from(s) {
                    return Err(FromBytesError::InvalidKey);
                }

                let n = num(&s.n)?;
                let e = num(&s.e)?;
                let d = secure_num(&s.d)?;
                let p = secure_num(&s.p)?;
                let q = secure_num(&s.q)?;
                let d_p = secure_num(&s.d_p)?;
                let d_q = secure_num(&s.d_q)?;
                let q_i = secure_num(&s.q_i)?;

                // NOTE: The 'openssl' crate doesn't seem to expose
                // 'EVP_PKEY_fromdata', which could be used to replace the
                // deprecated methods called here.

                let key = openssl::rsa::Rsa::from_private_components(
                    n, e, d, p, q, d_p, d_q, q_i,
                )?;

                if !key.check_key()? {
                    return Err(FromBytesError::InvalidKey);
                }

                PKey::from_rsa(key)?
            }

            (
                KeyBytes::EcdsaP256Sha256(s),
                RawPublicKey::EcdsaP256Sha256(p),
            ) => {
                use openssl::{bn, ec, nid};

                let mut ctx = bn::BigNumContext::new_secure()?;
                let group = nid::Nid::X9_62_PRIME256V1;
                let group = ec::EcGroup::from_curve_name(group)?;
                let n = secure_num(s.as_slice())?;
                let p = ec::EcPoint::from_bytes(&group, &**p, &mut ctx)?;
                let k = ec::EcKey::from_private_components(&group, &n, &p)?;
                k.check_key().map_err(|_| FromBytesError::InvalidKey)?;
                PKey::from_ec_key(k)?
            }

            (
                KeyBytes::EcdsaP384Sha384(s),
                RawPublicKey::EcdsaP384Sha384(p),
            ) => {
                use openssl::{bn, ec, nid};

                let mut ctx = bn::BigNumContext::new_secure()?;
                let group = nid::Nid::SECP384R1;
                let group = ec::EcGroup::from_curve_name(group)?;
                let n = secure_num(s.as_slice())?;
                let p = ec::EcPoint::from_bytes(&group, &**p, &mut ctx)?;
                let k = ec::EcKey::from_private_components(&group, &n, &p)?;
                k.check_key().map_err(|_| FromBytesError::InvalidKey)?;
                PKey::from_ec_key(k)?
            }

            (KeyBytes::Ed25519(s), RawPublicKey::Ed25519(p)) => {
                use openssl::memcmp;

                let id = pkey::Id::ED25519;
                let k = PKey::private_key_from_raw_bytes(&**s, id)?;
                if memcmp::eq(&k.raw_public_key().unwrap(), &**p) {
                    k
                } else {
                    return Err(FromBytesError::InvalidKey);
                }
            }

            (KeyBytes::Ed448(s), RawPublicKey::Ed448(p)) => {
                use openssl::memcmp;

                let id = pkey::Id::ED448;
                let k = PKey::private_key_from_raw_bytes(&**s, id)?;
                if memcmp::eq(&k.raw_public_key().unwrap(), &**p) {
                    k
                } else {
                    return Err(FromBytesError::InvalidKey);
                }
            }

            // The public and private key types did not match.
            _ => return Err(FromBytesError::InvalidKey),
        };

        Ok(Self {
            algorithm: secret.algorithm(),
            pkey,
        })
    }

    /// Export the secret key into bytes.
    ///
    /// # Panics
    ///
    /// Panics if OpenSSL fails or if memory could not be allocated.
    pub fn to_bytes(&self) -> KeyBytes {
        // TODO: Consider security implications of secret data in 'Vec's.
        match self.algorithm {
            SecAlg::RSASHA256 => {
                let key = self.pkey.rsa().unwrap();
                KeyBytes::RsaSha256(RsaKeyBytes {
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
                KeyBytes::EcdsaP256Sha256(key.try_into().unwrap())
            }
            SecAlg::ECDSAP384SHA384 => {
                let key = self.pkey.ec_key().unwrap();
                let key = key.private_key().to_vec_padded(48).unwrap();
                KeyBytes::EcdsaP384Sha384(key.try_into().unwrap())
            }
            SecAlg::ED25519 => {
                let key = self.pkey.raw_private_key().unwrap();
                KeyBytes::Ed25519(key.try_into().unwrap())
            }
            SecAlg::ED448 => {
                let key = self.pkey.raw_private_key().unwrap();
                KeyBytes::Ed448(key.try_into().unwrap())
            }
            _ => unreachable!(),
        }
    }
}

//--- Signing

impl KeyPair {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
        use openssl::hash::MessageDigest;
        use openssl::sign::Signer;

        match self.algorithm {
            SecAlg::RSASHA256 => {
                let mut s = Signer::new(MessageDigest::sha256(), &self.pkey)?;
                s.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
                s.sign_oneshot_to_vec(data)
            }

            SecAlg::ECDSAP256SHA256 => {
                let mut s = Signer::new(MessageDigest::sha256(), &self.pkey)?;
                let signature = s.sign_oneshot_to_vec(data)?;
                // Convert from DER to the fixed representation.
                let signature = EcdsaSig::from_der(&signature)?;
                let mut r = signature.r().to_vec_padded(32)?;
                let mut s = signature.s().to_vec_padded(32)?;
                r.append(&mut s);
                Ok(r)
            }
            SecAlg::ECDSAP384SHA384 => {
                let mut s = Signer::new(MessageDigest::sha384(), &self.pkey)?;
                let signature = s.sign_oneshot_to_vec(data)?;
                // Convert from DER to the fixed representation.
                let signature = EcdsaSig::from_der(&signature)?;
                let mut r = signature.r().to_vec_padded(48)?;
                let mut s = signature.s().to_vec_padded(48)?;
                r.append(&mut s);
                Ok(r)
            }

            SecAlg::ED25519 => {
                let mut s = Signer::new_without_digest(&self.pkey)?;
                s.sign_oneshot_to_vec(data)
            }
            SecAlg::ED448 => {
                let mut s = Signer::new_without_digest(&self.pkey)?;
                s.sign_oneshot_to_vec(data)
            }

            _ => unreachable!(),
        }
    }
}

//--- SignRaw

impl SignRaw for KeyPair {
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

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
        let signature = self
            .sign(data)
            .map(Vec::into_boxed_slice)
            .map_err(|_| SignError)?;

        match self.algorithm {
            SecAlg::RSASHA256 => Ok(Signature::RsaSha256(signature)),

            SecAlg::ECDSAP256SHA256 => signature
                .try_into()
                .map(Signature::EcdsaP256Sha256)
                .map_err(|_| SignError),
            SecAlg::ECDSAP384SHA384 => signature
                .try_into()
                .map(Signature::EcdsaP384Sha384)
                .map_err(|_| SignError),

            SecAlg::ED25519 => signature
                .try_into()
                .map(Signature::Ed25519)
                .map_err(|_| SignError),
            SecAlg::ED448 => signature
                .try_into()
                .map(Signature::Ed448)
                .map_err(|_| SignError),

            _ => unreachable!(),
        }
    }
}

//----------- generate() -----------------------------------------------------

/// Generate a new secret key for the given algorithm.
pub fn generate(params: GenerateParams) -> Result<KeyPair, GenerateError> {
    let algorithm = params.algorithm();
    let pkey = match params {
        GenerateParams::RsaSha256 { bits } => {
            openssl::rsa::Rsa::generate(bits).and_then(PKey::from_rsa)?
        }
        GenerateParams::EcdsaP256Sha256 => {
            let group = openssl::nid::Nid::X9_62_PRIME256V1;
            let group = openssl::ec::EcGroup::from_curve_name(group)?;
            PKey::from_ec_key(openssl::ec::EcKey::generate(&group)?)?
        }
        GenerateParams::EcdsaP384Sha384 => {
            let group = openssl::nid::Nid::SECP384R1;
            let group = openssl::ec::EcGroup::from_curve_name(group)?;
            PKey::from_ec_key(openssl::ec::EcKey::generate(&group)?)?
        }
        GenerateParams::Ed25519 => PKey::generate_ed25519()?,
        GenerateParams::Ed448 => PKey::generate_ed448()?,
    };

    Ok(KeyPair { algorithm, pkey })
}

//============ Error Types ===================================================

//----------- FromBytesError -----------------------------------------------

/// An error in importing a key pair from bytes into OpenSSL.
#[derive(Clone, Debug)]
pub enum FromBytesError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// The key's parameters were invalid.
    InvalidKey,

    /// An implementation failure occurred.
    ///
    /// This includes memory allocation failures.
    Implementation,
}

//--- Conversion

impl From<ErrorStack> for FromBytesError {
    fn from(_: ErrorStack) -> Self {
        Self::Implementation
    }
}

//--- Formatting

impl fmt::Display for FromBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::InvalidKey => "malformed or insecure private key",
            Self::Implementation => "an internal error occurred",
        })
    }
}

//--- Error

impl std::error::Error for FromBytesError {}

//----------- GenerateError --------------------------------------------------

/// An error in generating a key pair with OpenSSL.
#[derive(Clone, Debug)]
pub enum GenerateError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// An implementation failure occurred.
    ///
    /// This includes memory allocation failures.
    Implementation,
}

//--- Conversion

impl From<ErrorStack> for GenerateError {
    fn from(_: ErrorStack) -> Self {
        Self::Implementation
    }
}

//--- Formatting

impl fmt::Display for GenerateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::Implementation => "an internal error occurred",
        })
    }
}

//--- Error

impl std::error::Error for GenerateError {}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use std::{string::String, vec::Vec};

    use crate::{
        base::iana::SecAlg,
        sign::{GenerateParams, KeyBytes, SignRaw},
        validate::Key,
    };

    use super::KeyPair;

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
            let params = match algorithm {
                SecAlg::RSASHA256 => GenerateParams::RsaSha256 { bits: 3072 },
                SecAlg::ECDSAP256SHA256 => GenerateParams::EcdsaP256Sha256,
                SecAlg::ECDSAP384SHA384 => GenerateParams::EcdsaP384Sha384,
                SecAlg::ED25519 => GenerateParams::Ed25519,
                SecAlg::ED448 => GenerateParams::Ed448,
                _ => unreachable!(),
            };

            let _ = super::generate(params).unwrap();
        }
    }

    #[test]
    fn generated_roundtrip() {
        for &(algorithm, _) in KEYS {
            let params = match algorithm {
                SecAlg::RSASHA256 => GenerateParams::RsaSha256 { bits: 3072 },
                SecAlg::ECDSAP256SHA256 => GenerateParams::EcdsaP256Sha256,
                SecAlg::ECDSAP384SHA384 => GenerateParams::EcdsaP384Sha384,
                SecAlg::ED25519 => GenerateParams::Ed25519,
                SecAlg::ED448 => GenerateParams::Ed448,
                _ => unreachable!(),
            };

            let key = super::generate(params).unwrap();
            let gen_key = key.to_bytes();
            let pub_key = key.raw_public_key();
            let equiv = KeyPair::from_bytes(&gen_key, &pub_key).unwrap();
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
            let gen_key = KeyBytes::parse_from_bind(&data).unwrap();

            let key = KeyPair::from_bytes(&gen_key, pub_key).unwrap();

            let equiv = key.to_bytes();
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
            let gen_key = KeyBytes::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            let pub_key = pub_key.raw_public_key();

            let key = KeyPair::from_bytes(&gen_key, pub_key).unwrap();

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
            let gen_key = KeyBytes::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = Key::<Vec<u8>>::parse_from_bind(&data).unwrap();
            let pub_key = pub_key.raw_public_key();

            let key = KeyPair::from_bytes(&gen_key, pub_key).unwrap();

            let _ = key.sign_raw(b"Hello, World!").unwrap();
        }
    }
}
