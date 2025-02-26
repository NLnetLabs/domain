//! DNSSEC signing using built-in backends.
//!
//! This backend supports all the algorithms supported by Ring and OpenSSL,
//! depending on whether the respective crate features are enabled.  See the
//! documentation for each backend for more information.

use core::fmt;
use std::error;
use std::sync::Arc;
use std::vec::Vec;

use ::ring::rand::SystemRandom;

use super::misc::{SignRaw, Signature};
use crate::base::iana::SecAlg;
use crate::dnssec::sign::error::{FromBytesError, GenerateError, SignError};
use crate::dnssec::sign::SecretKeyBytes;
use crate::rdata::Dnskey;

#[cfg(feature = "openssl")]
use super::openssl;

#[cfg(feature = "ring")]
use super::ring;

//----------- KeyPair --------------------------------------------------------

/// A key pair based on a built-in backend.
///
/// This supports any built-in backend (currently, that is OpenSSL and Ring,
/// if their respective feature flags are enabled).  Wherever possible, it
/// will prefer the Ring backend over OpenSSL -- but for more uncommon or
/// insecure algorithms, that Ring does not support, OpenSSL must be used.
#[derive(Debug)]
// Note: ring does not implement Clone for KeyPair.
pub enum KeyPair {
    /// A key backed by Ring.
    #[cfg(feature = "ring")]
    Ring(ring::KeyPair),

    /// A key backed by OpenSSL.
    #[cfg(feature = "openssl")]
    OpenSSL(openssl::KeyPair),
}

//--- Conversion to and from bytes

impl KeyPair {
    /// Import a key pair from bytes.
    pub fn from_bytes<Octs>(
        secret: &SecretKeyBytes,
        public: &Dnskey<Octs>,
    ) -> Result<Self, FromBytesError>
    where
        Octs: AsRef<[u8]>,
    {
        // Prefer Ring if it is available.
        #[cfg(feature = "ring")]
        let fallback_to_openssl = match public.algorithm() {
            SecAlg::RSASHA1
            | SecAlg::RSASHA1_NSEC3_SHA1
            | SecAlg::RSASHA256
            | SecAlg::RSASHA512 => {
                ring::PublicKey::from_dnskey(public)
                    .map_err(|_| FromBytesError::InvalidKey)?
                    .key_size()
                    < 2048
            }
            _ => false,
        };

        if !fallback_to_openssl {
            let rng = Arc::new(SystemRandom::new());
            let key = ring::KeyPair::from_bytes(secret, public, rng)?;
            return Ok(Self::Ring(key));
        }

        // Fall back to OpenSSL.
        #[cfg(feature = "openssl")]
        return Ok(Self::OpenSSL(openssl::KeyPair::from_bytes(
            secret, public,
        )?));

        // Otherwise fail.
        #[allow(unreachable_code)]
        Err(FromBytesError::UnsupportedAlgorithm)
    }
}

//--- SignRaw

impl SignRaw for KeyPair {
    fn algorithm(&self) -> SecAlg {
        match self {
            #[cfg(feature = "ring")]
            Self::Ring(key) => key.algorithm(),
            #[cfg(feature = "openssl")]
            Self::OpenSSL(key) => key.algorithm(),
        }
    }

    fn dnskey(&self) -> Dnskey<Vec<u8>> {
        match self {
            #[cfg(feature = "ring")]
            Self::Ring(key) => key.dnskey(),
            #[cfg(feature = "openssl")]
            Self::OpenSSL(key) => key.dnskey(),
        }
    }

    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError> {
        match self {
            #[cfg(feature = "ring")]
            Self::Ring(key) => key.sign_raw(data),
            #[cfg(feature = "openssl")]
            Self::OpenSSL(key) => key.sign_raw(data),
        }
    }
}

//----------- GenerateParams -------------------------------------------------

/// Parameters for generating a secret key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GenerateParams {
    /// Generate an RSA/SHA-256 keypair.
    RsaSha256 {
        /// The number of bits in the public modulus.
        ///
        /// A ~3000-bit key corresponds to a 128-bit security level.  However,
        /// RSA is mostly used with 2048-bit keys.  Some backends (like Ring)
        /// do not support smaller key sizes than that.
        ///
        /// For more information about security levels, see [NIST SP 800-57
        /// part 1 revision 5], page 54, table 2.
        ///
        /// [NIST SP 800-57 part 1 revision 5]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
        bits: u32,
    },

    /// Generate an ECDSA P-256/SHA-256 keypair.
    EcdsaP256Sha256,

    /// Generate an ECDSA P-384/SHA-384 keypair.
    EcdsaP384Sha384,

    /// Generate an Ed25519 keypair.
    Ed25519,

    /// An Ed448 keypair.
    Ed448,
}

//--- Inspection

impl GenerateParams {
    /// The algorithm of the generated key.
    pub fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha256 { .. } => SecAlg::RSASHA256,
            Self::EcdsaP256Sha256 => SecAlg::ECDSAP256SHA256,
            Self::EcdsaP384Sha384 => SecAlg::ECDSAP384SHA384,
            Self::Ed25519 => SecAlg::ED25519,
            Self::Ed448 => SecAlg::ED448,
        }
    }
}

//----------- generate() -----------------------------------------------------

/// Generate a new secret key for the given algorithm.
pub fn generate(
    params: GenerateParams,
    flags: u16,
) -> Result<(SecretKeyBytes, Dnskey<Vec<u8>>), GenerateError> {
    // Use Ring if it is available.
    #[cfg(feature = "ring")]
    if matches!(
        &params,
        GenerateParams::EcdsaP256Sha256
            | GenerateParams::EcdsaP384Sha384
            | GenerateParams::Ed25519
    ) {
        let rng = ::ring::rand::SystemRandom::new();
        return Ok(ring::generate(params, flags, &rng)?);
    }

    // Fall back to OpenSSL.
    #[cfg(feature = "openssl")]
    {
        let key = openssl::generate(params, flags)?;
        return Ok((key.to_bytes(), key.dnskey()));
    }

    // Otherwise fail.
    #[allow(unreachable_code)]
    Err(GenerateError::UnsupportedAlgorithm)
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

//----------- DigestType -----------------------------------------------------

pub enum DigestType {
    Sha1,
    Sha256,
    Sha384,
}

//----------- DigestContext --------------------------------------------------

pub enum DigestContext {
    #[cfg(feature = "ring")]
    Ring(ring::DigestContext),
    #[cfg(feature = "openssl")]
    Openssl(openssl::DigestContext),
}

impl DigestContext {
    #[allow(unreachable_code)]
    pub fn new(digest_type: DigestType) -> Self {
        #[cfg(feature = "ring")]
        return Self::Ring(ring::DigestContext::new(digest_type));

        #[cfg(feature = "openssl")]
        return Self::Openssl(openssl::DigestContext::new(digest_type));

        #[cfg(not(any(feature = "ring", feature = "openssl")))]
        compile_error!("Either feature \"ring\" or \"openssl\" must be enabled for this crate.");
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            #[cfg(feature = "ring")]
            DigestContext::Ring(digest_context) => {
                digest_context.update(data)
            }
            #[cfg(feature = "openssl")]
            DigestContext::Openssl(digest_context) => {
                digest_context.update(data)
            }
        }
    }

    pub fn finish(self) -> Digest {
        match self {
            #[cfg(feature = "ring")]
            DigestContext::Ring(digest_context) => {
                Digest::Ring(digest_context.finish())
            }
            #[cfg(feature = "openssl")]
            DigestContext::Openssl(digest_context) => {
                Digest::Openssl(digest_context.finish())
            }
        }
    }
}

//----------- Digest ---------------------------------------------------------

pub enum Digest {
    #[cfg(feature = "ring")]
    Ring(ring::Digest),
    #[cfg(feature = "openssl")]
    Openssl(openssl::Digest),
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        match self {
            #[cfg(feature = "ring")]
            Digest::Ring(digest) => digest.as_ref(),
            #[cfg(feature = "openssl")]
            Digest::Openssl(digest) => digest.as_ref(),
        }
    }
}

//----------- PublicKey ------------------------------------------------------

pub enum PublicKey {
    #[cfg(feature = "ring")]
    Ring(ring::PublicKey),

    #[cfg(feature = "openssl")]
    Openssl(openssl::PublicKey),
}

impl PublicKey {
    #[allow(unreachable_code)]
    pub fn from_dnskey(
        dnskey: &Dnskey<impl AsRef<[u8]>>,
    ) -> Result<Self, AlgorithmError> {
        #[cfg(feature = "ring")]
        return Ok(Self::Ring(ring::PublicKey::from_dnskey(dnskey)?));

        #[cfg(feature = "openssl")]
        return Ok(Self::Openssl(openssl::PublicKey::from_dnskey(dnskey)?));

        #[cfg(not(any(feature = "ring", feature = "openssl")))]
        compile_error!("Either feature \"ring\" or \"openssl\" must be enabled for this crate.");
    }

    pub fn verify(
        &self,
        signed_data: &[u8],
        signature: &[u8],
    ) -> Result<(), AlgorithmError> {
        match self {
            #[cfg(feature = "ring")]
            PublicKey::Ring(public_key) => {
                public_key.verify(signed_data, signature)
            }
            #[cfg(feature = "openssl")]
            PublicKey::Openssl(public_key) => {
                public_key.verify(signed_data, signature)
            }
        }
    }
}

/// Return the RSA exponent and modulus components from DNSKEY record data.
pub fn rsa_exponent_modulus(
    dnskey: &Dnskey<impl AsRef<[u8]>>,
    min_len: usize,
) -> Result<(Vec<u8>, Vec<u8>), AlgorithmError> {
    let public_key = dnskey.public_key().as_ref();
    if public_key.len() <= 3 {
        return Err(AlgorithmError::InvalidData);
    }

    let (pos, exp_len) = match public_key[0] {
        0 => (
            3,
            (usize::from(public_key[1]) << 8) | usize::from(public_key[2]),
        ),
        len => (1, usize::from(len)),
    };

    // Check if there's enough space for exponent and modulus.
    if public_key[pos..].len() < pos + exp_len {
        return Err(AlgorithmError::InvalidData);
    };

    // Check for minimum supported key size
    if public_key[pos..].len() < min_len {
        return Err(AlgorithmError::Unsupported);
    }

    let (e, n) = public_key[pos..].split_at(exp_len);
    Ok((e.to_vec(), n.to_vec()))
}

//------------ AlgorithmError ------------------------------------------------

/// An algorithm error during verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlgorithmError {
    /// Unsupported algorithm.
    Unsupported,

    /// Bad signature.
    BadSig,

    /// Invalid data.
    InvalidData,
}

//--- Display, Error

impl fmt::Display for AlgorithmError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            AlgorithmError::Unsupported => "unsupported algorithm",
            AlgorithmError::BadSig => "bad signature",
            AlgorithmError::InvalidData => "invalid data",
        })
    }
}

impl error::Error for AlgorithmError {}
