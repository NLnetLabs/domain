//! DNSSEC signing using OpenSSL.
//!
//! This backend supports the following algorithms:
//!
//! - RSA/SHA-256 (512-bit keys or larger)
//! - ECDSA P-256/SHA-256
//! - ECDSA P-384/SHA-384
//! - Ed25519
//! - Ed448

#![cfg(feature = "openssl")]
#![cfg_attr(docsrs, doc(cfg(feature = "openssl")))]

use core::fmt;

use std::vec::Vec;

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint, PointConversionForm};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::{DigestBytes, Hasher, MessageDigest};
use openssl::nid::Nid;
use openssl::pkey::{Id, PKey, Public};
use openssl::rsa::Rsa;
use openssl::sign::Verifier;

use super::common::{rsa_exponent_modulus, AlgorithmError, DigestType};
use crate::base::iana::SecAlg;
use crate::rdata::Dnskey;

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

//----------- DigestContext --------------------------------------------------

/// Context for computing a message digest.
pub struct DigestContext(Hasher);

impl DigestContext {
    /// Create a new context for a specified digest type.
    pub fn new(digest_type: DigestType) -> Self {
        Self(
            match digest_type {
                DigestType::Sha1 => Hasher::new(MessageDigest::sha1()),
                DigestType::Sha256 => Hasher::new(MessageDigest::sha256()),
                DigestType::Sha384 => Hasher::new(MessageDigest::sha384()),
            }
            .expect("assume that new cannot fail"),
        )
    }

    /// Add input to the digest computation.
    pub fn update(&mut self, data: &[u8]) {
        self.0
            .update(data)
            .expect("assume that update does not fail")
    }

    /// Finish computing the digest.
    pub fn finish(mut self) -> Digest {
        Digest(self.0.finish().expect("assume that finish does not fail"))
    }
}

//----------- Digest ---------------------------------------------------------

/// A message digest.
pub struct Digest(DigestBytes);

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

//----------- PublicKey ------------------------------------------------------

/// A public key for verifying a signature.
pub enum PublicKey {
    /// Default variant, used for RSA.
    Default(MessageDigest, PKey<Public>, u16),

    /// Variant for Ed25519 and Ed448.
    NoDigest(PKey<Public>, u16),

    /// Variant for EcDsa.
    EcDsa(MessageDigest, EcKey<Public>, u16),
}

impl PublicKey {
    /// Create a public key from a [`Dnskey`].
    pub fn from_dnskey(
        dnskey: &Dnskey<impl AsRef<[u8]>>,
    ) -> Result<Self, AlgorithmError> {
        let sec_alg = dnskey.algorithm();
        match sec_alg {
            SecAlg::RSASHA1
            | SecAlg::RSASHA1_NSEC3_SHA1
            | SecAlg::RSASHA256
            | SecAlg::RSASHA512 => {
                let (digest_algorithm, min_bytes) = match sec_alg {
                    SecAlg::RSASHA1 | SecAlg::RSASHA1_NSEC3_SHA1 => {
                        (MessageDigest::sha1(), 1024 / 8)
                    }
                    SecAlg::RSASHA256 => (MessageDigest::sha256(), 1024 / 8),
                    SecAlg::RSASHA512 => (MessageDigest::sha512(), 1024 / 8),
                    _ => unreachable!(),
                };

                // The key isn't available in either PEM or DER, so use the
                // direct RSA verifier.
                let (e, n) = rsa_exponent_modulus(dnskey, min_bytes)?;
                let e = BigNum::from_slice(&e)
                    .map_err(|_| AlgorithmError::InvalidData)?;
                let n = BigNum::from_slice(&n)
                    .map_err(|_| AlgorithmError::InvalidData)?;
                let public_key = Rsa::from_public_components(n, e)
                    .map_err(|_| AlgorithmError::InvalidData)?;
                let public_key = PKey::from_rsa(public_key)
                    .map_err(|_| AlgorithmError::InvalidData)?;
                Ok(PublicKey::Default(
                    digest_algorithm,
                    public_key,
                    dnskey.flags(),
                ))
            }
            SecAlg::ECDSAP256SHA256 | SecAlg::ECDSAP384SHA384 => {
                let (digest_algorithm, group_id) = match sec_alg {
                    SecAlg::ECDSAP256SHA256 => {
                        (MessageDigest::sha256(), Nid::X9_62_PRIME256V1)
                    }
                    SecAlg::ECDSAP384SHA384 => {
                        (MessageDigest::sha384(), Nid::SECP384R1)
                    }
                    _ => unreachable!(),
                };

                let group = EcGroup::from_curve_name(group_id)
                    .expect("should not fail");
                let mut ctx = BigNumContext::new().expect("should not fail");

                // Add 0x4 identifier to the ECDSA pubkey as expected by openssl.
                let public_key = dnskey.public_key().as_ref();
                let mut key = Vec::with_capacity(public_key.len() + 1);
                key.push(0x4);
                key.extend_from_slice(public_key);
                let point = EcPoint::from_bytes(&group, &key, &mut ctx)
                    .map_err(|_| AlgorithmError::InvalidData)?;
                let public_key = EcKey::from_public_key(&group, &point)
                    .map_err(|_| AlgorithmError::InvalidData)?;
                public_key
                    .check_key()
                    .map_err(|_| AlgorithmError::InvalidData)?;

                Ok(PublicKey::EcDsa(
                    digest_algorithm,
                    public_key,
                    dnskey.flags(),
                ))
            }
            SecAlg::ED25519 => {
                let public_key = PKey::public_key_from_raw_bytes(
                    dnskey.public_key().as_ref(),
                    Id::ED25519,
                )
                .map_err(|_| AlgorithmError::InvalidData)?;
                Ok(PublicKey::NoDigest(public_key, dnskey.flags()))
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
        let valid = match self {
            PublicKey::Default(digest_algorithm, public_key, _) => {
                let mut verifier =
                    Verifier::new(*digest_algorithm, public_key.as_ref())
                        .map_err(|_| AlgorithmError::InvalidData)?;
                verifier
                    .verify_oneshot(signature, signed_data)
                    .map_err(|_| AlgorithmError::InvalidData)?
            }
            PublicKey::NoDigest(public_key, _) => {
                let mut verifier =
                    Verifier::new_without_digest(public_key.as_ref())
                        .map_err(|_| AlgorithmError::InvalidData)?;
                verifier
                    .verify_oneshot(signature, signed_data)
                    .map_err(|_| AlgorithmError::InvalidData)?
            }
            PublicKey::EcDsa(digest_algorithm, public_key, _) => {
                let half_len = signature.len() / 2;
                let mut hasher = Hasher::new(*digest_algorithm)
                    .map_err(|_| AlgorithmError::InvalidData)?;
                hasher
                    .update(signed_data)
                    .map_err(|_| AlgorithmError::InvalidData)?;
                let hash = hasher
                    .finish()
                    .map_err(|_| AlgorithmError::InvalidData)?;
                let r = BigNum::from_slice(&signature[0..half_len])
                    .map_err(|_| AlgorithmError::InvalidData)?;
                let s = BigNum::from_slice(&signature[half_len..])
                    .map_err(|_| AlgorithmError::InvalidData)?;
                let ecdsa_sig = EcdsaSig::from_private_components(r, s)
                    .map_err(|_| AlgorithmError::InvalidData)?;
                ecdsa_sig
                    .verify(hash.as_ref(), public_key)
                    .map_err(|_| AlgorithmError::InvalidData)?
            }
        };
        if valid {
            Ok(())
        } else {
            Err(AlgorithmError::BadSig)
        }
    }

    /// Convert to a [`Dnskey`].
    pub fn dnskey(&self) -> Dnskey<Vec<u8>> {
        match self {
            PublicKey::Default(message_digest, public_key, flags) => {
                let alg = if *message_digest == MessageDigest::sha256() {
                    SecAlg::RSASHA256
                } else {
                    unreachable!();
                };
                let rsa = public_key.rsa().expect("should not fail");
                let e = rsa.e().to_vec();
                let n = rsa.n().to_vec();

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

                key.extend(&*e);
                key.extend(&*n);

                Dnskey::new(*flags, 3, alg, key).expect("should not fail")
            }
            PublicKey::NoDigest(public_key, flags) => {
                let alg = match public_key.id() {
                    Id::ED25519 => SecAlg::ED25519,
                    Id::ED448 => SecAlg::ED448,
                    _ => todo!(),
                };

                let key =
                    public_key.raw_public_key().expect("should not fail");
                Dnskey::new(*flags, 3, alg, key).expect("should not fail")
            }
            PublicKey::EcDsa(message_digest, public_key, flags) => {
                let alg = if *message_digest == MessageDigest::sha256() {
                    SecAlg::ECDSAP256SHA256
                } else if *message_digest == MessageDigest::sha384() {
                    SecAlg::ECDSAP384SHA384
                } else {
                    unreachable!();
                };

                let key = public_key.public_key();
                let group = public_key.group();
                let mut ctx = BigNumContext::new().expect("should not fail");
                let key = key
                    .to_bytes(
                        group,
                        PointConversionForm::UNCOMPRESSED,
                        &mut ctx,
                    )
                    .expect("should not fail");

                // Openssl has an extra byte with the value 4 in front.
                let key = key[1..].to_vec();

                Dnskey::new(*flags, 3, alg, key).expect("should not fail")
            }
        }
    }
}

#[cfg(feature = "unstable-crypto-sign")]
/// Submodule for private keys and signing.
pub mod sign {
    use std::boxed::Box;
    use std::vec::Vec;

    use crate::base::iana::SecAlg;
    use crate::crypto::sign::{
        GenerateParams, RsaSecretKeyBytes, SecretKeyBytes, SignError,
        SignRaw, Signature,
    };
    use crate::rdata::Dnskey;

    use super::{FromBytesError, GenerateError, PublicKey};

    use openssl::bn::BigNum;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::ecdsa::EcdsaSig;
    use openssl::error::ErrorStack;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{self, Id, PKey, Private};
    use openssl::rsa::Rsa;

    use secrecy::ExposeSecret;

    //----------- KeyPair ----------------------------------------------------

    /// A key pair backed by OpenSSL.
    #[derive(Clone, Debug)]
    pub struct KeyPair {
        /// The algorithm used by the key.
        algorithm: SecAlg,

        flags: u16,

        /// The private key.
        pkey: PKey<Private>,
    }

    //--- Conversion to and from bytes

    impl KeyPair {
        /// Import a key pair from bytes into OpenSSL.
        pub fn from_bytes<Octs>(
            secret: &SecretKeyBytes,
            public: &Dnskey<Octs>,
        ) -> Result<Self, FromBytesError>
        where
            Octs: AsRef<[u8]>,
        {
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

            let pkey = match secret {
                SecretKeyBytes::RsaSha256(s) => {
                    let n = num(&s.n)?;
                    let e = num(&s.e)?;

                    // Ensure that the public and private key match.
                    let rsa_public = Rsa::from_public_components(
                        n.to_owned().expect("should not fail"),
                        e.to_owned().expect("should not fail"),
                    )
                    .expect("should not fail");
                    let rsa_public =
                        PKey::from_rsa(rsa_public).expect("should not fail");
                    let p = PublicKey::Default(
                        MessageDigest::sha256(),
                        rsa_public,
                        public.flags(),
                    )
                    .dnskey();
                    if p != *public {
                        return Err(FromBytesError::InvalidKey);
                    }

                    let d = secure_num(s.d.expose_secret())?;
                    let p = secure_num(s.p.expose_secret())?;
                    let q = secure_num(s.q.expose_secret())?;
                    let d_p = secure_num(s.d_p.expose_secret())?;
                    let d_q = secure_num(s.d_q.expose_secret())?;
                    let q_i = secure_num(s.q_i.expose_secret())?;

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

                SecretKeyBytes::EcdsaP256Sha256(s) => {
                    use openssl::{ec, nid};

                    let group = nid::Nid::X9_62_PRIME256V1;
                    let group = ec::EcGroup::from_curve_name(group)?;
                    let n = secure_num(s.expose_secret().as_slice())?;

                    let public_key = PublicKey::from_dnskey(public)
                        .map_err(|_| FromBytesError::InvalidKey)?;
                    let PublicKey::EcDsa(_, eckey, _) = public_key else {
                        return Err(FromBytesError::InvalidKey);
                    };
                    let p = eckey.public_key();

                    let k =
                        ec::EcKey::from_private_components(&group, &n, p)?;
                    k.check_key().map_err(|_| FromBytesError::InvalidKey)?;
                    PKey::from_ec_key(k)?
                }

                SecretKeyBytes::EcdsaP384Sha384(s) => {
                    use openssl::{ec, nid};

                    let group = nid::Nid::SECP384R1;
                    let group = ec::EcGroup::from_curve_name(group)?;
                    let n = secure_num(s.expose_secret().as_slice())?;

                    let public_key = PublicKey::from_dnskey(public)
                        .map_err(|_| FromBytesError::InvalidKey)?;
                    let PublicKey::EcDsa(_, eckey, _) = public_key else {
                        return Err(FromBytesError::InvalidKey);
                    };
                    let p = eckey.public_key();

                    let k =
                        ec::EcKey::from_private_components(&group, &n, p)?;
                    k.check_key().map_err(|_| FromBytesError::InvalidKey)?;
                    PKey::from_ec_key(k)?
                }

                SecretKeyBytes::Ed25519(s) => {
                    use openssl::memcmp;

                    let id = pkey::Id::ED25519;
                    let s = s.expose_secret();
                    let k = PKey::private_key_from_raw_bytes(s, id)?;
                    if memcmp::eq(
                        &k.raw_public_key().expect("should not fail"),
                        public.public_key().as_ref(),
                    ) {
                        k
                    } else {
                        return Err(FromBytesError::InvalidKey);
                    }
                }

                SecretKeyBytes::Ed448(s) => {
                    use openssl::memcmp;

                    let id = pkey::Id::ED448;
                    let s = s.expose_secret();
                    let k = PKey::private_key_from_raw_bytes(s, id)?;
                    if memcmp::eq(
                        &k.raw_public_key().expect("should not fail"),
                        public.public_key().as_ref(),
                    ) {
                        k
                    } else {
                        return Err(FromBytesError::InvalidKey);
                    }
                }
            };

            Ok(Self {
                algorithm: secret.algorithm(),
                flags: public.flags(),
                pkey,
            })
        }

        /// Export the secret key into bytes.
        ///
        /// # Panics
        ///
        /// Panics if OpenSSL fails or if memory could not be allocated.
        pub fn to_bytes(&self) -> SecretKeyBytes {
            // TODO: Consider security implications of secret data in 'Vec's.
            match self.algorithm {
                SecAlg::RSASHA256 => {
                    let key = self.pkey.rsa().unwrap();
                    SecretKeyBytes::RsaSha256(RsaSecretKeyBytes {
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
                    let key: Box<[u8; 32]> = key.try_into().unwrap();
                    SecretKeyBytes::EcdsaP256Sha256(key.into())
                }
                SecAlg::ECDSAP384SHA384 => {
                    let key = self.pkey.ec_key().unwrap();
                    let key = key.private_key().to_vec_padded(48).unwrap();
                    let key: Box<[u8; 48]> = key.try_into().unwrap();
                    SecretKeyBytes::EcdsaP384Sha384(key.into())
                }
                SecAlg::ED25519 => {
                    let key = self.pkey.raw_private_key().unwrap();
                    let key: Box<[u8; 32]> = key.try_into().unwrap();
                    SecretKeyBytes::Ed25519(key.into())
                }
                SecAlg::ED448 => {
                    let key = self.pkey.raw_private_key().unwrap();
                    let key: Box<[u8; 57]> = key.try_into().unwrap();
                    SecretKeyBytes::Ed448(key.into())
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
                    let mut s =
                        Signer::new(MessageDigest::sha256(), &self.pkey)?;
                    s.set_rsa_padding(openssl::rsa::Padding::PKCS1)?;
                    s.sign_oneshot_to_vec(data)
                }

                SecAlg::ECDSAP256SHA256 => {
                    let mut s =
                        Signer::new(MessageDigest::sha256(), &self.pkey)?;
                    let signature = s.sign_oneshot_to_vec(data)?;
                    // Convert from DER to the fixed representation.
                    let signature = EcdsaSig::from_der(&signature)?;
                    let mut r = signature.r().to_vec_padded(32)?;
                    let mut s = signature.s().to_vec_padded(32)?;
                    r.append(&mut s);
                    Ok(r)
                }
                SecAlg::ECDSAP384SHA384 => {
                    let mut s =
                        Signer::new(MessageDigest::sha384(), &self.pkey)?;
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

        fn dnskey(&self) -> Dnskey<Vec<u8>> {
            match self.algorithm {
                SecAlg::RSASHA256 => {
                    let key = self.pkey.rsa().expect("should not fail");
                    let n = key.n().to_owned().expect("should not fail");
                    let e = key.e().to_owned().expect("should not fail");
                    let key = Rsa::from_public_components(n, e)
                        .expect("should not fail");
                    let key = PKey::from_rsa(key).expect("should not fail");
                    let public = PublicKey::Default(
                        MessageDigest::sha256(),
                        key,
                        self.flags,
                    );
                    public.dnskey()
                }
                SecAlg::ECDSAP256SHA256 | SecAlg::ECDSAP384SHA384 => {
                    let (digest_algorithm, group_id) = match self.algorithm {
                        SecAlg::ECDSAP256SHA256 => {
                            (MessageDigest::sha256(), Nid::X9_62_PRIME256V1)
                        }
                        SecAlg::ECDSAP384SHA384 => {
                            (MessageDigest::sha384(), Nid::SECP384R1)
                        }
                        _ => unreachable!(),
                    };

                    let key = self.pkey.ec_key().expect("should not fail");
                    let key = key.public_key();
                    let group = EcGroup::from_curve_name(group_id)
                        .expect("should not fail");
                    let public_key = EcKey::from_public_key(&group, key)
                        .expect("should not fail");
                    public_key.check_key().expect("should not fail");
                    let public = PublicKey::EcDsa(
                        digest_algorithm,
                        public_key,
                        self.flags,
                    );
                    public.dnskey()
                }
                SecAlg::ED25519 | SecAlg::ED448 => {
                    let id = match self.algorithm {
                        SecAlg::ED25519 => Id::ED25519,
                        SecAlg::ED448 => Id::ED448,
                        _ => unreachable!(),
                    };

                    let key =
                        self.pkey.raw_public_key().expect("should not fail");
                    let key = PKey::public_key_from_raw_bytes(&key, id)
                        .expect("shoul not fail");
                    let public = PublicKey::NoDigest(key, self.flags);
                    public.dnskey()
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

    //----------- generate() -------------------------------------------------

    /// Generate a new secret key for the given algorithm.
    pub fn generate(
        params: GenerateParams,
        flags: u16,
    ) -> Result<KeyPair, GenerateError> {
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

        Ok(KeyPair {
            algorithm,
            flags,
            pkey,
        })
    }

    #[cfg(test)]
    mod tests {
        use crate::base::iana::SecAlg;
        use crate::crypto::sign::{GenerateParams, SignRaw};

        use super::KeyPair;

        const KEYS: &[(SecAlg, u16)] = &[
            (SecAlg::RSASHA256, 60616),
            (SecAlg::ECDSAP256SHA256, 42253),
            (SecAlg::ECDSAP384SHA384, 33566),
            (SecAlg::ED25519, 56037),
            (SecAlg::ED448, 7379),
        ];

        #[test]
        fn generated_roundtrip() {
            for &(algorithm, _) in KEYS {
                let params = match algorithm {
                    SecAlg::RSASHA256 => {
                        GenerateParams::RsaSha256 { bits: 3072 }
                    }
                    SecAlg::ECDSAP256SHA256 => {
                        GenerateParams::EcdsaP256Sha256
                    }
                    SecAlg::ECDSAP384SHA384 => {
                        GenerateParams::EcdsaP384Sha384
                    }
                    SecAlg::ED25519 => GenerateParams::Ed25519,
                    SecAlg::ED448 => GenerateParams::Ed448,
                    _ => unreachable!(),
                };

                let key = super::generate(params, 256).unwrap();
                let gen_key = key.to_bytes();
                let pub_key = key.dnskey();
                let equiv = KeyPair::from_bytes(&gen_key, &pub_key).unwrap();
                assert!(key.pkey.public_eq(&equiv.pkey));
            }
        }
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use crate::base::iana::SecAlg;
    use crate::crypto::sign::{GenerateParams, SecretKeyBytes, SignRaw};
    use crate::dnssec::common::parse_from_bind;

    use super::sign::KeyPair;

    use std::string::ToString;
    use std::vec::Vec;

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

            let _ = super::sign::generate(params, 0).unwrap();
        }
    }

    #[test]
    fn imported_roundtrip() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = parse_from_bind::<Vec<u8>>(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let gen_key = SecretKeyBytes::parse_from_bind(&data).unwrap();

            let key = KeyPair::from_bytes(&gen_key, pub_key.data()).unwrap();
            let same = key.to_bytes().display_as_bind().to_string();

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
            let gen_key = SecretKeyBytes::parse_from_bind(&data).unwrap();

            let path = format!("test-data/dnssec-keys/K{}.key", name);
            let data = std::fs::read_to_string(path).unwrap();
            let pub_key = parse_from_bind::<Vec<u8>>(&data).unwrap();

            let key = KeyPair::from_bytes(&gen_key, pub_key.data()).unwrap();

            assert_eq!(key.dnskey(), *pub_key.data());
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

            let key = KeyPair::from_bytes(&gen_key, pub_key.data()).unwrap();

            let _ = key.sign_raw(b"Hello, World!").unwrap();
        }
    }
}
