//! DNSSEC signing using `ring`.
//!
//! This backend supports the following algorithms:
//!
//! - RSA/SHA-256 (2048-bit keys or larger)
//! - ECDSA P-256/SHA-256
//! - ECDSA P-384/SHA-384
//! - Ed25519

#![cfg(feature = "ring")]
#![cfg_attr(docsrs, doc(cfg(feature = "ring")))]

use core::fmt;

use std::{boxed::Box, sync::Arc, vec::Vec};

use ring::digest;
use ring::digest::SHA1_FOR_LEGACY_USE_ONLY;
use ring::digest::{Context, Digest as RingDigest};
use ring::rsa::PublicKeyComponents;
use ring::signature::{
    self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RsaKeyPair,
    RsaParameters, UnparsedPublicKey,
};
use secrecy::ExposeSecret;

use super::common::{
    rsa_exponent_modulus, AlgorithmError, DigestType, GenerateParams,
};
use super::misc::{PublicKeyBytes, RsaPublicKeyBytes, SignRaw, Signature};
use crate::base::iana::SecAlg;
use crate::dnssec::sign::error::SignError;
use crate::dnssec::sign::SecretKeyBytes;
use crate::rdata::Dnskey;

//----------- KeyPair --------------------------------------------------------

/// A key pair backed by `ring`.
// Note: ring does not implement Clone for *KeyPair.
#[derive(Debug)]
pub enum KeyPair {
    /// An RSA/SHA-256 keypair.
    RsaSha256 {
        key: RsaKeyPair,
        rng: Arc<dyn ring::rand::SecureRandom>,
    },

    /// An ECDSA P-256/SHA-256 keypair.
    EcdsaP256Sha256 {
        key: EcdsaKeyPair,
        rng: Arc<dyn ring::rand::SecureRandom>,
    },

    /// An ECDSA P-384/SHA-384 keypair.
    EcdsaP384Sha384 {
        key: EcdsaKeyPair,
        rng: Arc<dyn ring::rand::SecureRandom>,
    },

    /// An Ed25519 keypair.
    Ed25519(Ed25519KeyPair),
}

//--- Conversion from bytes

impl KeyPair {
    /// Import a key pair from bytes into OpenSSL.
    pub fn from_bytes(
        secret: &SecretKeyBytes,
        public: &PublicKeyBytes,
        rng: Arc<dyn ring::rand::SecureRandom>,
    ) -> Result<Self, FromBytesError> {
        match (secret, public) {
            (SecretKeyBytes::RsaSha256(s), PublicKeyBytes::RsaSha256(p)) => {
                // Ensure that the public and private key match.
                if p != &RsaPublicKeyBytes::from(s) {
                    return Err(FromBytesError::InvalidKey);
                }

                // Ensure that the key is strong enough.
                if p.n.len() < 2048 / 8 {
                    return Err(FromBytesError::WeakKey);
                }

                let components = ring::rsa::KeyPairComponents {
                    public_key: ring::rsa::PublicKeyComponents {
                        n: s.n.as_ref(),
                        e: s.e.as_ref(),
                    },
                    d: s.d.expose_secret(),
                    p: s.p.expose_secret(),
                    q: s.q.expose_secret(),
                    dP: s.d_p.expose_secret(),
                    dQ: s.d_q.expose_secret(),
                    qInv: s.q_i.expose_secret(),
                };
                ring::signature::RsaKeyPair::from_components(&components)
                    .map_err(|_| FromBytesError::InvalidKey)
                    .map(|key| Self::RsaSha256 { key, rng })
            }

            (
                SecretKeyBytes::EcdsaP256Sha256(s),
                PublicKeyBytes::EcdsaP256Sha256(p),
            ) => {
                let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
                EcdsaKeyPair::from_private_key_and_public_key(
                    alg,
                    s.expose_secret(),
                    p.as_slice(),
                    &*rng,
                )
                .map_err(|_| FromBytesError::InvalidKey)
                .map(|key| Self::EcdsaP256Sha256 { key, rng })
            }

            (
                SecretKeyBytes::EcdsaP384Sha384(s),
                PublicKeyBytes::EcdsaP384Sha384(p),
            ) => {
                let alg = &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING;
                EcdsaKeyPair::from_private_key_and_public_key(
                    alg,
                    s.expose_secret(),
                    p.as_slice(),
                    &*rng,
                )
                .map_err(|_| FromBytesError::InvalidKey)
                .map(|key| Self::EcdsaP384Sha384 { key, rng })
            }

            (SecretKeyBytes::Ed25519(s), PublicKeyBytes::Ed25519(p)) => {
                Ed25519KeyPair::from_seed_and_public_key(
                    s.expose_secret(),
                    p.as_slice(),
                )
                .map_err(|_| FromBytesError::InvalidKey)
                .map(Self::Ed25519)
            }

            (SecretKeyBytes::Ed448(_), PublicKeyBytes::Ed448(_)) => {
                Err(FromBytesError::UnsupportedAlgorithm)
            }

            // The public and private key types did not match.
            _ => Err(FromBytesError::InvalidKey),
        }
    }
}

//--- SignRaw

impl SignRaw for KeyPair {
    fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha256 { .. } => SecAlg::RSASHA256,
            Self::EcdsaP256Sha256 { .. } => SecAlg::ECDSAP256SHA256,
            Self::EcdsaP384Sha384 { .. } => SecAlg::ECDSAP384SHA384,
            Self::Ed25519(_) => SecAlg::ED25519,
        }
    }

    fn raw_public_key(&self) -> PublicKeyBytes {
        match self {
            Self::RsaSha256 { key, rng: _ } => {
                let components: ring::rsa::PublicKeyComponents<Vec<u8>> =
                    key.public().into();
                PublicKeyBytes::RsaSha256(RsaPublicKeyBytes {
                    n: components.n.into(),
                    e: components.e.into(),
                })
            }

            Self::EcdsaP256Sha256 { key, rng: _ } => {
                let key = key.public_key().as_ref();
                let key = Box::<[u8]>::from(key);
                PublicKeyBytes::EcdsaP256Sha256(key.try_into().unwrap())
            }

            Self::EcdsaP384Sha384 { key, rng: _ } => {
                let key = key.public_key().as_ref();
                let key = Box::<[u8]>::from(key);
                PublicKeyBytes::EcdsaP384Sha384(key.try_into().unwrap())
            }

            Self::Ed25519(key) => {
                let key = key.public_key().as_ref();
                let key = Box::<[u8]>::from(key);
                PublicKeyBytes::Ed25519(key.try_into().unwrap())
            }
        }
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
        match self {
            Self::RsaSha256 { key, rng } => {
                let mut buf = vec![0u8; key.public().modulus_len()];
                let pad = &ring::signature::RSA_PKCS1_SHA256;
                key.sign(pad, &**rng, data, &mut buf)
                    .map(|()| Signature::RsaSha256(buf.into_boxed_slice()))
                    .map_err(|_| SignError)
            }

            Self::EcdsaP256Sha256 { key, rng } => key
                .sign(&**rng, data)
                .map(|sig| Box::<[u8]>::from(sig.as_ref()))
                .map_err(|_| SignError)
                .and_then(|buf| {
                    buf.try_into()
                        .map(Signature::EcdsaP256Sha256)
                        .map_err(|_| SignError)
                }),

            Self::EcdsaP384Sha384 { key, rng } => key
                .sign(&**rng, data)
                .map(|sig| Box::<[u8]>::from(sig.as_ref()))
                .map_err(|_| SignError)
                .and_then(|buf| {
                    buf.try_into()
                        .map(Signature::EcdsaP384Sha384)
                        .map_err(|_| SignError)
                }),

            Self::Ed25519(key) => {
                let sig = key.sign(data);
                let buf: Box<[u8]> = sig.as_ref().into();
                buf.try_into()
                    .map(Signature::Ed25519)
                    .map_err(|_| SignError)
            }
        }
    }
}

//----------- generate() -----------------------------------------------------

/// Generate a new key pair for the given algorithm.
///
/// While this uses Ring internally, the opaque nature of Ring means that it
/// is not possible to export a secret key from [`KeyPair`].  Thus, the bytes
/// of the secret key are returned directly.
pub fn generate(
    params: GenerateParams,
    rng: &dyn ring::rand::SecureRandom,
) -> Result<(SecretKeyBytes, PublicKeyBytes), GenerateError> {
    match params {
        GenerateParams::EcdsaP256Sha256 => {
            // Generate a key and a PKCS#8 document out of Ring.
            let alg = &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
            let doc = EcdsaKeyPair::generate_pkcs8(alg, rng)?;

            // Manually parse the PKCS#8 document for the private key.
            let sk: Box<[u8]> = Box::from(&doc.as_ref()[36..68]);
            let sk: Box<[u8; 32]> = sk.try_into().unwrap();
            let sk = SecretKeyBytes::EcdsaP256Sha256(sk.into());

            // Manually parse the PKCS#8 document for the public key.
            let pk: Box<[u8]> = Box::from(&doc.as_ref()[73..138]);
            let pk = pk.try_into().unwrap();
            let pk = PublicKeyBytes::EcdsaP256Sha256(pk);

            Ok((sk, pk))
        }

        GenerateParams::EcdsaP384Sha384 => {
            // Generate a key and a PKCS#8 document out of Ring.
            let alg = &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING;
            let doc = EcdsaKeyPair::generate_pkcs8(alg, rng)?;

            // Manually parse the PKCS#8 document for the private key.
            let sk: Box<[u8]> = Box::from(&doc.as_ref()[35..83]);
            let sk: Box<[u8; 48]> = sk.try_into().unwrap();
            let sk = SecretKeyBytes::EcdsaP384Sha384(sk.into());

            // Manually parse the PKCS#8 document for the public key.
            let pk: Box<[u8]> = Box::from(&doc.as_ref()[88..185]);
            let pk = pk.try_into().unwrap();
            let pk = PublicKeyBytes::EcdsaP384Sha384(pk);

            Ok((sk, pk))
        }

        GenerateParams::Ed25519 => {
            // Generate a key and a PKCS#8 document out of Ring.
            let doc = Ed25519KeyPair::generate_pkcs8(rng)?;

            // Manually parse the PKCS#8 document for the private key.
            let sk: Box<[u8]> = Box::from(&doc.as_ref()[16..48]);
            let sk: Box<[u8; 32]> = sk.try_into().unwrap();
            let sk = SecretKeyBytes::Ed25519(sk.into());

            // Manually parse the PKCS#8 document for the public key.
            let pk: Box<[u8]> = Box::from(&doc.as_ref()[51..83]);
            let pk = pk.try_into().unwrap();
            let pk = PublicKeyBytes::Ed25519(pk);

            Ok((sk, pk))
        }

        _ => Err(GenerateError::UnsupportedAlgorithm),
    }
}

//============ Error Types ===================================================

/// An error in importing a key pair from bytes into Ring.
#[derive(Clone, Debug)]
pub enum FromBytesError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// The provided keypair was invalid.
    InvalidKey,

    /// The implementation does not allow such weak keys.
    WeakKey,
}

//--- Formatting

impl fmt::Display for FromBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::InvalidKey => "malformed or insecure private key",
            Self::WeakKey => "key too weak to be supported",
        })
    }
}

//--- Error

impl std::error::Error for FromBytesError {}

//----------- GenerateError --------------------------------------------------

/// An error in generating a key pair with Ring.
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

impl From<ring::error::Unspecified> for GenerateError {
    fn from(_: ring::error::Unspecified) -> Self {
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

//----------- DigestContext --------------------------------------------------

pub struct DigestContext(Context);

impl DigestContext {
    pub fn new(digest_type: DigestType) -> Self {
        Self(match digest_type {
            DigestType::Sha1 => Context::new(&SHA1_FOR_LEGACY_USE_ONLY),
            DigestType::Sha256 => Context::new(&digest::SHA256),
            DigestType::Sha384 => Context::new(&digest::SHA384),
        })
    }

    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    pub fn finish(self) -> Digest {
        Digest(self.0.finish())
    }
}

//----------- Digest ---------------------------------------------------------

pub struct Digest(RingDigest);

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

//----------- PublicKey ------------------------------------------------------

pub enum PublicKey {
    Rsa((&'static RsaParameters, PublicKeyComponents<Vec<u8>>)),
    Unparsed(UnparsedPublicKey<Vec<u8>>),
}

impl PublicKey {
    pub fn from_dnskey(
        dnskey: &Dnskey<impl AsRef<[u8]>>,
    ) -> Result<Self, AlgorithmError> {
        let sec_alg = dnskey.algorithm();
        match sec_alg {
            SecAlg::RSASHA1
            | SecAlg::RSASHA1_NSEC3_SHA1
            | SecAlg::RSASHA256
            | SecAlg::RSASHA512 => {
                let (algorithm, min_bytes) = match sec_alg {
                    SecAlg::RSASHA1 | SecAlg::RSASHA1_NSEC3_SHA1 => (
                        &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                        1024 / 8,
                    ),
                    SecAlg::RSASHA256 => (
                        &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                        1024 / 8,
                    ),
                    SecAlg::RSASHA512 => (
                        &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
                        1024 / 8,
                    ),
                    _ => unreachable!(),
                };

                // The key isn't available in either PEM or DER, so use the
                // direct RSA verifier.
                let (e, n) = rsa_exponent_modulus(dnskey, min_bytes)?;
                let public_key = signature::RsaPublicKeyComponents { n, e };
                Ok(PublicKey::Rsa((algorithm, public_key)))
            }
            SecAlg::ECDSAP256SHA256 | SecAlg::ECDSAP384SHA384 => {
                let algorithm = match sec_alg {
                    SecAlg::ECDSAP256SHA256 => {
                        &signature::ECDSA_P256_SHA256_FIXED
                    }
                    SecAlg::ECDSAP384SHA384 => {
                        &signature::ECDSA_P384_SHA384_FIXED
                    }
                    _ => unreachable!(),
                };

                // Add 0x4 identifier to the ECDSA pubkey as expected by ring.
                let public_key = dnskey.public_key().as_ref();
                let mut key = Vec::with_capacity(public_key.len() + 1);
                key.push(0x4);
                key.extend_from_slice(public_key);

                Ok(PublicKey::Unparsed(signature::UnparsedPublicKey::new(
                    algorithm, key,
                )))
            }
            SecAlg::ED25519 => {
                let key = dnskey.public_key().as_ref().to_vec();
                Ok(PublicKey::Unparsed(signature::UnparsedPublicKey::new(
                    &signature::ED25519,
                    key,
                )))
            }
            _ => Err(AlgorithmError::Unsupported),
        }
    }

    pub fn verify(
        &self,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), AlgorithmError> {
        match self {
            PublicKey::Rsa((algorithm, public_key)) => {
                public_key.verify(algorithm, signed_data, signature)
            }
            PublicKey::Unparsed(public_key) => {
                public_key.verify(signed_data, signature)
            }
        }
        .map_err(|_| AlgorithmError::BadSig)
        .map_err(|_| AlgorithmError::BadSig)
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::vec::Vec;

    use crate::base::iana::SecAlg;
    use crate::crypto::common::GenerateParams;
    use crate::crypto::misc::SignRaw;
    use crate::crypto::ring::PublicKeyBytes;
    use crate::dnssec::common::parse_from_bind;
    use crate::dnssec::sign::SecretKeyBytes;

    use super::KeyPair;

    const KEYS: &[(SecAlg, u16)] = &[
        (SecAlg::RSASHA256, 60616),
        (SecAlg::ECDSAP256SHA256, 42253),
        (SecAlg::ECDSAP384SHA384, 33566),
        (SecAlg::ED25519, 56037),
    ];

    const GENERATE_PARAMS: &[GenerateParams] = &[
        GenerateParams::EcdsaP256Sha256,
        GenerateParams::EcdsaP384Sha384,
        GenerateParams::Ed25519,
    ];

    #[test]
    fn public_key() {
        let rng = Arc::new(ring::rand::SystemRandom::new());
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = SecretKeyBytes::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = parse_from_bind::<Vec<u8>>(&data).unwrap();
            let pub_key = PublicKeyBytes::from_dnskey_format(
                pub_key.data().algorithm(),
                pub_key.data().public_key(),
            )
            .unwrap();

            let key =
                KeyPair::from_bytes(&gen_key, &pub_key, rng.clone()).unwrap();

            assert_eq!(key.raw_public_key(), pub_key);
        }
    }

    #[test]
    fn generated_roundtrip() {
        let rng = Arc::new(ring::rand::SystemRandom::new());
        for params in GENERATE_PARAMS {
            let (sk, pk) = super::generate(params.clone(), &*rng).unwrap();
            let key = KeyPair::from_bytes(&sk, &pk, rng.clone()).unwrap();
            assert_eq!(key.raw_public_key(), pk);
        }
    }

    #[test]
    fn sign() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);
            let rng = Arc::new(ring::rand::SystemRandom::new());

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = SecretKeyBytes::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = parse_from_bind::<Vec<u8>>(&data).unwrap();
            let pub_key = PublicKeyBytes::from_dnskey_format(
                pub_key.data().algorithm(),
                pub_key.data().public_key(),
            )
            .unwrap();

            let key = KeyPair::from_bytes(&gen_key, &pub_key, rng).unwrap();

            let _ = key.sign_raw(b"Hello, World!").unwrap();
        }
    }
}
