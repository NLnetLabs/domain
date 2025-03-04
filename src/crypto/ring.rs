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

use std::ptr;
use std::ptr::addr_eq;
use std::vec::Vec;

use ring::digest;
use ring::digest::SHA1_FOR_LEGACY_USE_ONLY;
use ring::digest::{Context, Digest as RingDigest};
use ring::rsa::PublicKeyComponents;
use ring::signature::{
    self, RsaParameters, UnparsedPublicKey, VerificationAlgorithm,
};

use super::common::{rsa_exponent_modulus, AlgorithmError, DigestType};

use crate::base::iana::SecAlg;
use crate::rdata::Dnskey;

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
    Rsa(&'static RsaParameters, PublicKeyComponents<Vec<u8>>),
    Unparsed(
        &'static dyn VerificationAlgorithm,
        UnparsedPublicKey<Vec<u8>>,
    ),
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
                Ok(PublicKey::Rsa(algorithm, public_key))
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

                Ok(PublicKey::Unparsed(
                    algorithm,
                    signature::UnparsedPublicKey::new(algorithm, key),
                ))
            }
            SecAlg::ED25519 => {
                let key = dnskey.public_key().as_ref().to_vec();
                let algorithm = &signature::ED25519;
                Ok(PublicKey::Unparsed(
                    algorithm,
                    signature::UnparsedPublicKey::new(algorithm, key),
                ))
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
            PublicKey::Rsa(algorithm, public_key) => {
                public_key.verify(algorithm, signed_data, signature)
            }
            PublicKey::Unparsed(_, public_key) => {
                public_key.verify(signed_data, signature)
            }
        }
        .map_err(|_| AlgorithmError::BadSig)
        .map_err(|_| AlgorithmError::BadSig)
    }

    pub fn dnskey(&self, flags: u16) -> Dnskey<Vec<u8>> {
        match self {
            PublicKey::Rsa(parameters, components) => {
                let alg = if ptr::eq(
                    *parameters as *const _,
                    &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
                        as *const _,
                ) {
                    // This is a bit of a problem. It could also be RSASHA1.
                    // Assume that we do not generate new RSASHA1 keys.
                    // If we do, we need an extra field.
                    SecAlg::RSASHA1_NSEC3_SHA1
                } else if ptr::eq(
                    *parameters as *const _,
                    &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
                        as *const _,
                ) {
                    SecAlg::RSASHA256
                } else if ptr::eq(
                    *parameters as *const _,
                    &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
                        as *const _,
                ) {
                    SecAlg::RSASHA512
                } else {
                    unreachable!();
                };

                let e = &components.e;
                let n = &components.n;

                let mut key = Vec::new();

                // Encode the exponent length.
                if let Ok(exp_len) = u8::try_from(e.len()) {
                    key.reserve_exact(1 + e.len() + n.len());
                    key.push(exp_len);
                } else if let Ok(exp_len) = u16::try_from(e.len()) {
                    key.reserve_exact(3 + e.len() + n.len());
                    key.push(0u8);
                    key.extend(&exp_len.to_be_bytes());
                } else {
                    unreachable!(
                        "RSA exponents are (much) shorter than 64KiB"
                    )
                }

                key.extend(e);
                key.extend(n);

                Dnskey::new(flags, 3, alg, key).expect("new should not fail")
            }
            PublicKey::Unparsed(algorithm, unparsed) => {
                if addr_eq(
                    *algorithm as *const _,
                    &signature::ECDSA_P256_SHA256_FIXED as *const _,
                ) {
                    let alg = SecAlg::ECDSAP256SHA256;

                    // Ring has an extra byte with the value 4 in front.
                    let p = unparsed.as_ref();
                    let p = p[1..].to_vec();
                    Dnskey::new(flags, 3, alg, p)
                        .expect("new should not fail")
                } else if addr_eq(
                    *algorithm as *const _,
                    &signature::ECDSA_P384_SHA384_FIXED as *const _,
                ) {
                    let alg = SecAlg::ECDSAP384SHA384;

                    // Ring has an extra byte with the value 4 in front.
                    let p = unparsed.as_ref();
                    let p = p[1..].to_vec();
                    Dnskey::new(flags, 3, alg, p)
                        .expect("new should not fail")
                } else if addr_eq(
                    *algorithm as *const _,
                    &signature::ED25519 as *const _,
                ) {
                    let alg = SecAlg::ED25519;

                    Dnskey::new(flags, 3, alg, unparsed.as_ref().to_vec())
                        .expect("new should not fail")
                } else {
                    unreachable!();
                }
            }
        }
    }

    // key_size should only be called for RSA keys to see if the key is long
    // enough to be supported by ring.
    #[cfg(feature = "unstable-crypto-sign")]
    pub(super) fn key_size(&self) -> usize {
        match self {
            PublicKey::Rsa(_, components) => {
                let n = &components.n;
                n.len() * 8
            }
            PublicKey::Unparsed(_, _) => unreachable!(),
        }
    }
}

#[cfg(feature = "unstable-crypto-sign")]
pub(crate) mod sign {
    use std::boxed::Box;
    use std::sync::Arc;
    use std::vec::Vec;

    use secrecy::ExposeSecret;

    use crate::base::iana::SecAlg;
    use crate::crypto::sign::{
        FromBytesError, GenerateParams, SecretKeyBytes, SignError, SignRaw,
        Signature,
    };
    use crate::rdata::Dnskey;

    use super::{GenerateError, PublicKey};

    use ring::rand::SystemRandom;
    use ring::signature::{
        self, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RsaKeyPair,
    };

    //----------- KeyPair ----------------------------------------------------

    /// A key pair backed by `ring`.
    // Note: ring does not implement Clone for *KeyPair.
    #[derive(Debug)]
    pub enum KeyPair {
        /// An RSA/SHA-256 keypair.
        RsaSha256 {
            key: RsaKeyPair,
            flags: u16,
            rng: Arc<dyn ring::rand::SecureRandom>,
        },

        /// An ECDSA P-256/SHA-256 keypair.
        EcdsaP256Sha256 {
            key: EcdsaKeyPair,
            flags: u16,
            rng: Arc<dyn ring::rand::SecureRandom>,
        },

        /// An ECDSA P-384/SHA-384 keypair.
        EcdsaP384Sha384 {
            key: EcdsaKeyPair,
            flags: u16,
            rng: Arc<dyn ring::rand::SecureRandom>,
        },

        /// An Ed25519 keypair.
        Ed25519(Ed25519KeyPair, u16),
    }

    //--- Conversion from bytes

    impl KeyPair {
        /// Import a key pair from bytes into OpenSSL.
        pub fn from_bytes<Octs>(
            secret: &SecretKeyBytes,
            public: &Dnskey<Octs>,
        ) -> Result<Self, FromBytesError>
        where
            Octs: AsRef<[u8]>,
        {
            let rng = Arc::new(SystemRandom::new());
            match secret {
                SecretKeyBytes::RsaSha256(s) => {
                    let rsa_public = signature::RsaPublicKeyComponents {
                        n: s.n.to_vec(),
                        e: s.e.to_vec(),
                    };
                    let p = PublicKey::Rsa(&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, rsa_public).dnskey(public.flags());
                    // Ensure that the public and private key match.
                    if p != *public {
                        return Err(FromBytesError::InvalidKey);
                    }

                    // Ensure that the key is strong enough.
                    if s.n.len() < 2048 / 8 {
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
                        .map(|key| Self::RsaSha256 {
                            key,
                            flags: public.flags(),
                            rng,
                        })
                }

                SecretKeyBytes::EcdsaP256Sha256(s) => {
                    let alg =
                        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;

                    let public_key = PublicKey::from_dnskey(public)
                        .map_err(|_| FromBytesError::InvalidKey)?;
                    let PublicKey::Unparsed(_, unparsed) = public_key else {
                        return Err(FromBytesError::InvalidKey);
                    };

                    EcdsaKeyPair::from_private_key_and_public_key(
                        alg,
                        s.expose_secret(),
                        unparsed.as_ref(),
                        &*rng,
                    )
                    .map_err(|_| FromBytesError::InvalidKey)
                    .map(|key| Self::EcdsaP256Sha256 {
                        key,
                        flags: public.flags(),
                        rng,
                    })
                }

                SecretKeyBytes::EcdsaP384Sha384(s) => {
                    let alg =
                        &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING;

                    let public_key = PublicKey::from_dnskey(public)
                        .map_err(|_| FromBytesError::InvalidKey)?;
                    let PublicKey::Unparsed(_, unparsed) = public_key else {
                        return Err(FromBytesError::InvalidKey);
                    };

                    EcdsaKeyPair::from_private_key_and_public_key(
                        alg,
                        s.expose_secret(),
                        unparsed.as_ref(),
                        &*rng,
                    )
                    .map_err(|_| FromBytesError::InvalidKey)
                    .map(|key| Self::EcdsaP384Sha384 {
                        key,
                        flags: public.flags(),
                        rng,
                    })
                }

                SecretKeyBytes::Ed25519(s) => {
                    Ed25519KeyPair::from_seed_and_public_key(
                        s.expose_secret(),
                        public.public_key().as_ref(),
                    )
                    .map_err(|_| FromBytesError::InvalidKey)
                    .map(|k| Self::Ed25519(k, public.flags()))
                }

                SecretKeyBytes::Ed448(_) => {
                    Err(FromBytesError::UnsupportedAlgorithm)
                }
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
                Self::Ed25519(_, _) => SecAlg::ED25519,
            }
        }

        fn dnskey(&self) -> Dnskey<Vec<u8>> {
            match self {
                Self::RsaSha256 { key, flags, rng: _ } => {
                    let components: ring::rsa::PublicKeyComponents<Vec<u8>> =
                        key.public().into();
                    let n = components.n;
                    let e = components.e;
                    let public_key =
                        signature::RsaPublicKeyComponents { n, e };
                    let public = PublicKey::Rsa(&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, public_key);
                    public.dnskey(*flags)
                }

                Self::EcdsaP256Sha256 { key, flags, rng: _ }
                | Self::EcdsaP384Sha384 { key, flags, rng: _ } => {
                    let algorithm = match self {
                        Self::EcdsaP256Sha256 {
                            key: _,
                            flags: _,
                            rng: _,
                        } => &signature::ECDSA_P256_SHA256_FIXED,
                        Self::EcdsaP384Sha384 {
                            key: _,
                            flags: _,
                            rng: _,
                        } => &signature::ECDSA_P384_SHA384_FIXED,
                        _ => unreachable!(),
                    };
                    let key = key.public_key().as_ref();
                    let public = PublicKey::Unparsed(
                        algorithm,
                        signature::UnparsedPublicKey::new(
                            algorithm,
                            key.to_vec(),
                        ),
                    );
                    public.dnskey(*flags)
                }
                Self::Ed25519(key, flags) => {
                    let algorithm = match self {
                        Self::Ed25519(_, _) => &signature::ED25519,
                        _ => unreachable!(),
                    };
                    let key = key.public_key().as_ref();
                    let public = PublicKey::Unparsed(
                        algorithm,
                        signature::UnparsedPublicKey::new(
                            algorithm,
                            key.to_vec(),
                        ),
                    );
                    public.dnskey(*flags)
                }
            }
        }

        fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
            match self {
                Self::RsaSha256 { key, flags: _, rng } => {
                    let mut buf = vec![0u8; key.public().modulus_len()];
                    let pad = &ring::signature::RSA_PKCS1_SHA256;
                    key.sign(pad, &**rng, data, &mut buf)
                        .map(|()| {
                            Signature::RsaSha256(buf.into_boxed_slice())
                        })
                        .map_err(|_| SignError)
                }

                Self::EcdsaP256Sha256 { key, flags: _, rng } => key
                    .sign(&**rng, data)
                    .map(|sig| Box::<[u8]>::from(sig.as_ref()))
                    .map_err(|_| SignError)
                    .and_then(|buf| {
                        buf.try_into()
                            .map(Signature::EcdsaP256Sha256)
                            .map_err(|_| SignError)
                    }),

                Self::EcdsaP384Sha384 { key, flags: _, rng } => key
                    .sign(&**rng, data)
                    .map(|sig| Box::<[u8]>::from(sig.as_ref()))
                    .map_err(|_| SignError)
                    .and_then(|buf| {
                        buf.try_into()
                            .map(Signature::EcdsaP384Sha384)
                            .map_err(|_| SignError)
                    }),

                Self::Ed25519(key, _) => {
                    let sig = key.sign(data);
                    let buf: Box<[u8]> = sig.as_ref().into();
                    buf.try_into()
                        .map(Signature::Ed25519)
                        .map_err(|_| SignError)
                }
            }
        }
    }

    //----------- generate() -------------------------------------------------

    /// Generate a new key pair for the given algorithm.
    ///
    /// While this uses Ring internally, the opaque nature of Ring means that it
    /// is not possible to export a secret key from [`KeyPair`].  Thus, the bytes
    /// of the secret key are returned directly.
    pub fn generate(
        params: GenerateParams,
        flags: u16,
        rng: &dyn ring::rand::SecureRandom,
    ) -> Result<(SecretKeyBytes, Dnskey<Vec<u8>>), GenerateError> {
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
                let pk = doc.as_ref()[73..138].to_vec();
                let algorithm = &signature::ECDSA_P256_SHA256_FIXED;
                let pk = signature::UnparsedPublicKey::new(algorithm, pk);
                let pk = PublicKey::Unparsed(algorithm, pk);

                Ok((sk, pk.dnskey(flags)))
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
                let pk = doc.as_ref()[88..185].to_vec();
                let algorithm = &signature::ECDSA_P384_SHA384_FIXED;
                let pk = signature::UnparsedPublicKey::new(algorithm, pk);
                let pk = PublicKey::Unparsed(algorithm, pk);
                Ok((sk, pk.dnskey(flags)))
            }

            GenerateParams::Ed25519 => {
                // Generate a key and a PKCS#8 document out of Ring.
                let doc = Ed25519KeyPair::generate_pkcs8(rng)?;

                // Manually parse the PKCS#8 document for the private key.
                let sk: Box<[u8]> = Box::from(&doc.as_ref()[16..48]);
                let sk: Box<[u8; 32]> = sk.try_into().unwrap();
                let sk = SecretKeyBytes::Ed25519(sk.into());

                // Manually parse the PKCS#8 document for the public key.
                let pk = doc.as_ref()[51..83].to_vec();
                let algorithm = &signature::ED25519;
                let pk = signature::UnparsedPublicKey::new(algorithm, pk);
                let pk = PublicKey::Unparsed(algorithm, pk);

                Ok((sk, pk.dnskey(flags)))
            }

            _ => Err(GenerateError::UnsupportedAlgorithm),
        }
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::crypto::ring::sign::KeyPair;
    use crate::crypto::sign::{GenerateParams, SignRaw};

    #[cfg(feature = "unstable-validator")]
    use std::vec::Vec;

    #[cfg(feature = "unstable-validator")]
    use crate::base::iana::SecAlg;

    #[cfg(feature = "unstable-validator")]
    use crate::crypto::sign::SecretKeyBytes;

    #[cfg(feature = "unstable-validator")]
    use crate::dnssec::common::parse_from_bind;

    #[cfg(feature = "unstable-validator")]
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
    #[cfg(feature = "unstable-validator")]
    fn public_key() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = SecretKeyBytes::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = parse_from_bind::<Vec<u8>>(&data).unwrap();

            let key = KeyPair::from_bytes(&gen_key, pub_key.data()).unwrap();

            assert_eq!(key.dnskey(), *pub_key.data());
        }
    }

    #[test]
    fn generated_roundtrip() {
        let rng = Arc::new(ring::rand::SystemRandom::new());
        for params in GENERATE_PARAMS {
            let (sk, pk) =
                super::sign::generate(params.clone(), 256, &*rng).unwrap();
            let key = KeyPair::from_bytes(&sk, &pk).unwrap();
            assert_eq!(key.dnskey(), pk);
        }
    }

    #[test]
    #[cfg(feature = "unstable-validator")]
    fn sign() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = SecretKeyBytes::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = parse_from_bind::<Vec<u8>>(&data).unwrap();

            let key = KeyPair::from_bytes(&gen_key, pub_key.data()).unwrap();

            let _ = key.sign_raw(b"Hello, World!").unwrap();
        }
    }
}
