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
use std::vec::Vec;

use ring::digest;
use ring::digest::SHA1_FOR_LEGACY_USE_ONLY;
use ring::digest::{Context, Digest as RingDigest};
use ring::rsa::PublicKeyComponents;
use ring::signature::{self, RsaParameters, UnparsedPublicKey};

use super::common::{
    rsa_encode, rsa_exponent_modulus, AlgorithmError, DigestType,
};

use crate::base::iana::SecurityAlgorithm;
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

//----------- DigestBuilder --------------------------------------------------

/// Builder for computing a message digest.
pub struct DigestBuilder(Context);

impl DigestBuilder {
    /// Create a new builder for a specified digest type.
    pub fn new(digest_type: DigestType) -> Self {
        Self(match digest_type {
            DigestType::Sha1 => Context::new(&SHA1_FOR_LEGACY_USE_ONLY),
            DigestType::Sha256 => Context::new(&digest::SHA256),
            DigestType::Sha384 => Context::new(&digest::SHA384),
        })
    }

    /// Add input to the digest computation.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    /// Finish computing the digest.
    pub fn finish(self) -> Digest {
        Digest(self.0.finish())
    }
}

//----------- Digest ---------------------------------------------------------

/// A message digest.
pub struct Digest(RingDigest);

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

//----------- PublicKey ------------------------------------------------------

/// A public key for verifying a signature.
pub enum PublicKey {
    /// Variant for RSA public keys.
    Rsa(&'static RsaParameters, PublicKeyComponents<Vec<u8>>),

    /// Variant for elliptic-curve public keys.
    Unparsed(SecurityAlgorithm, UnparsedPublicKey<Vec<u8>>),
}

impl PublicKey {
    /// Create a public key from a [`Dnskey`].
    pub fn from_dnskey(
        dnskey: &Dnskey<impl AsRef<[u8]>>,
    ) -> Result<Self, AlgorithmError> {
        let sec_alg = dnskey.algorithm();
        match sec_alg {
            SecurityAlgorithm::RSASHA1
            | SecurityAlgorithm::RSASHA1_NSEC3_SHA1
            | SecurityAlgorithm::RSASHA256
            | SecurityAlgorithm::RSASHA512 => {
                let (algorithm, min_bytes) = match sec_alg {
                    SecurityAlgorithm::RSASHA1 | SecurityAlgorithm::RSASHA1_NSEC3_SHA1 => (
                        &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                        1024 / 8,
                    ),
                    SecurityAlgorithm::RSASHA256 => (
                        &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                        1024 / 8,
                    ),
                    SecurityAlgorithm::RSASHA512 => (
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
            SecurityAlgorithm::ECDSAP256SHA256
            | SecurityAlgorithm::ECDSAP384SHA384 => {
                let algorithm = match sec_alg {
                    SecurityAlgorithm::ECDSAP256SHA256 => {
                        &signature::ECDSA_P256_SHA256_FIXED
                    }
                    SecurityAlgorithm::ECDSAP384SHA384 => {
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
                    sec_alg,
                    signature::UnparsedPublicKey::new(algorithm, key),
                ))
            }
            SecurityAlgorithm::ED25519 => {
                let key = dnskey.public_key().as_ref().to_vec();
                let algorithm = &signature::ED25519;
                Ok(PublicKey::Unparsed(
                    sec_alg,
                    signature::UnparsedPublicKey::new(algorithm, key),
                ))
            }
            _ => Err(AlgorithmError::Unsupported),
        }
    }

    /// Verify a signature.
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
    }

    /// Convert to a [`Dnskey`].
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
                    SecurityAlgorithm::RSASHA1_NSEC3_SHA1
                } else if ptr::eq(
                    *parameters as *const _,
                    &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY
                        as *const _,
                ) {
                    SecurityAlgorithm::RSASHA256
                } else if ptr::eq(
                    *parameters as *const _,
                    &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY
                        as *const _,
                ) {
                    SecurityAlgorithm::RSASHA512
                } else {
                    unreachable!();
                };

                let e = &components.e;
                let n = &components.n;

                let key = rsa_encode(e, n);

                Dnskey::new(flags, 3, alg, key).expect("new should not fail")
            }
            PublicKey::Unparsed(algorithm, unparsed) => {
                match *algorithm {
                    SecurityAlgorithm::ECDSAP256SHA256
                    | SecurityAlgorithm::ECDSAP384SHA384 => {
                        // Ring has an extra byte with the value 4 in front.
                        let p = unparsed.as_ref();
                        let p = p[1..].to_vec();
                        Dnskey::new(flags, 3, *algorithm, p)
                            .expect("new should not fail")
                    }
                    SecurityAlgorithm::ED25519 => Dnskey::new(
                        flags,
                        3,
                        *algorithm,
                        unparsed.as_ref().to_vec(),
                    )
                    .expect("new should not fail"),
                    _ => unreachable!(),
                }
            }
        }
    }

    // key_size should only be called for RSA keys to see if the key is long
    // enough to be supported by ring.
    #[cfg(feature = "unstable-crypto-sign")]
    /// Compute the key size. This is currently only implemented for RSA.
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
/// Submodule for private keys and signing.
pub mod sign {
    use std::boxed::Box;
    use std::sync::Arc;
    use std::vec::Vec;

    use secrecy::ExposeSecret;

    use crate::base::iana::SecurityAlgorithm;
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
            /// They RSA key.
            key: RsaKeyPair,

            /// Flags from [`Dnskey`].
            flags: u16,

            /// Random number generator.
            rng: Arc<dyn ring::rand::SecureRandom + Send + Sync>,
        },

        /// An ECDSA P-256/SHA-256 keypair.
        EcdsaP256Sha256 {
            /// The ECDSA key.
            key: EcdsaKeyPair,

            /// Flags from [`Dnskey`].
            flags: u16,

            /// Random number generator.
            rng: Arc<dyn ring::rand::SecureRandom + Send + Sync>,
        },

        /// An ECDSA P-384/SHA-384 keypair.
        EcdsaP384Sha384 {
            /// The ECDSA key.
            key: EcdsaKeyPair,

            /// Flags from [`Dnskey`].
            flags: u16,

            /// Random number generator.
            rng: Arc<dyn ring::rand::SecureRandom + Send + Sync>,
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
        fn algorithm(&self) -> SecurityAlgorithm {
            match self {
                Self::RsaSha256 { .. } => SecurityAlgorithm::RSASHA256,
                Self::EcdsaP256Sha256 { .. } => {
                    SecurityAlgorithm::ECDSAP256SHA256
                }
                Self::EcdsaP384Sha384 { .. } => {
                    SecurityAlgorithm::ECDSAP384SHA384
                }
                Self::Ed25519(_, _) => SecurityAlgorithm::ED25519,
            }
        }

        fn flags(&self) -> u16 {
            match *self {
                KeyPair::RsaSha256 { flags, .. } => flags,
                KeyPair::EcdsaP256Sha256 { flags, .. } => flags,
                KeyPair::EcdsaP384Sha384 { flags, .. } => flags,
                KeyPair::Ed25519(_, flags) => flags,
            }
        }

        fn dnskey(&self) -> Result<Dnskey<Vec<u8>>, SignError> {
            match self {
                Self::RsaSha256 { key, flags, rng: _ } => {
                    let components: ring::rsa::PublicKeyComponents<Vec<u8>> =
                        key.public().into();
                    let n = components.n;
                    let e = components.e;
                    let public_key =
                        signature::RsaPublicKeyComponents { n, e };
                    let public = PublicKey::Rsa(&signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY, public_key);
                    Ok(public.dnskey(*flags))
                }

                Self::EcdsaP256Sha256 { key, flags, rng: _ }
                | Self::EcdsaP384Sha384 { key, flags, rng: _ } => {
                    let (algorithm, sec_alg) = match self {
                        Self::EcdsaP256Sha256 {
                            key: _,
                            flags: _,
                            rng: _,
                        } => (
                            &signature::ECDSA_P256_SHA256_FIXED,
                            SecurityAlgorithm::ECDSAP256SHA256,
                        ),
                        Self::EcdsaP384Sha384 {
                            key: _,
                            flags: _,
                            rng: _,
                        } => (
                            &signature::ECDSA_P384_SHA384_FIXED,
                            SecurityAlgorithm::ECDSAP384SHA384,
                        ),
                        _ => unreachable!(),
                    };
                    let key = key.public_key().as_ref();
                    let public = PublicKey::Unparsed(
                        sec_alg,
                        signature::UnparsedPublicKey::new(
                            algorithm,
                            key.to_vec(),
                        ),
                    );
                    Ok(public.dnskey(*flags))
                }
                Self::Ed25519(key, flags) => {
                    let (algorithm, sec_alg) = match self {
                        Self::Ed25519(_, _) => {
                            (&signature::ED25519, SecurityAlgorithm::ED25519)
                        }
                        _ => unreachable!(),
                    };
                    let key = key.public_key().as_ref();
                    let public = PublicKey::Unparsed(
                        sec_alg,
                        signature::UnparsedPublicKey::new(
                            algorithm,
                            key.to_vec(),
                        ),
                    );
                    Ok(public.dnskey(*flags))
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
                        .map_err(|_| "Ring RSASHA256 signing failed".into())
                }

                Self::EcdsaP256Sha256 { key, flags: _, rng } => key
                    .sign(&**rng, data)
                    .map(|sig| Box::<[u8]>::from(sig.as_ref()))
                    .map_err(|_| "Ring ECDSAP256SHA256 signing failed".into())
                    .and_then(|buf| {
                        buf.try_into()
                            .map(Signature::EcdsaP256Sha256)
                            .map_err(|_| {
                                "Ring ECDSAP256SHA256 signature too large"
                                    .into()
                            })
                    }),

                Self::EcdsaP384Sha384 { key, flags: _, rng } => key
                    .sign(&**rng, data)
                    .map(|sig| Box::<[u8]>::from(sig.as_ref()))
                    .map_err(|_| "Ring ECDSAP384SHA384 signing failed".into())
                    .and_then(|buf| {
                        buf.try_into()
                            .map(Signature::EcdsaP384Sha384)
                            .map_err(|_| {
                                "Ring ECDSAP384SHA384 signature too large"
                                    .into()
                            })
                    }),

                Self::Ed25519(key, _) => {
                    let sig = key.sign(data);
                    let buf: Box<[u8]> = sig.as_ref().into();
                    buf.try_into().map(Signature::Ed25519).map_err(|_| {
                        "Ring ED25519 signature too large".into()
                    })
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
                let sec_alg = SecurityAlgorithm::ECDSAP256SHA256;
                let pk = signature::UnparsedPublicKey::new(algorithm, pk);
                let pk = PublicKey::Unparsed(sec_alg, pk);

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
                let sec_alg = SecurityAlgorithm::ECDSAP384SHA384;
                let pk = signature::UnparsedPublicKey::new(algorithm, pk);
                let pk = PublicKey::Unparsed(sec_alg, pk);
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
                let sec_alg = SecurityAlgorithm::ED25519;
                let pk = signature::UnparsedPublicKey::new(algorithm, pk);
                let pk = PublicKey::Unparsed(sec_alg, pk);

                Ok((sk, pk.dnskey(flags)))
            }

            _ => Err(GenerateError::UnsupportedAlgorithm),
        }
    }

    //============ Tests =====================================================

    #[cfg(test)]
    mod test {

        use std::vec::Vec;

        use crate::base::iana::SecurityAlgorithm;
        use crate::crypto::ring::sign::KeyPair;
        use crate::crypto::sign::{GenerateParams, SecretKeyBytes, SignRaw};
        use crate::dnssec::common::parse_from_bind;

        const GENERATE_PARAMS: &[GenerateParams] = &[
            GenerateParams::EcdsaP256Sha256,
            GenerateParams::EcdsaP384Sha384,
            GenerateParams::Ed25519,
        ];

        const KEYS: &[(SecurityAlgorithm, u16)] = &[
            (SecurityAlgorithm::RSASHA256, 60616),
            (SecurityAlgorithm::ECDSAP256SHA256, 42253),
            (SecurityAlgorithm::ECDSAP384SHA384, 33566),
            (SecurityAlgorithm::ED25519, 56037),
        ];

        #[test]
        fn generated_roundtrip() {
            for params in GENERATE_PARAMS {
                let (sk, pk) =
                    crate::crypto::sign::generate(params.clone(), 256)
                        .unwrap();
                let key = KeyPair::from_bytes(&sk, &pk).unwrap();
                assert_eq!(key.dnskey().unwrap(), pk);
            }
        }

        #[test]
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

                let key =
                    KeyPair::from_bytes(&gen_key, pub_key.data()).unwrap();

                assert_eq!(key.dnskey().unwrap(), *pub_key.data());
            }
        }

        #[test]
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

                let key =
                    KeyPair::from_bytes(&gen_key, pub_key.data()).unwrap();

                let _ = key.sign_raw(b"Hello, World!").unwrap();
            }
        }
    }
}
