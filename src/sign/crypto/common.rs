//! DNSSEC signing using built-in backends.
//!
//! This backend supports all the algorithms supported by Ring and OpenSSL,
//! depending on whether the respective crate features are enabled.  See the
//! documentation for each backend for more information.

use core::fmt;
use std::sync::Arc;

use ::ring::rand::SystemRandom;

use crate::base::iana::SecAlg;
use crate::sign::error::{FromBytesError, GenerateError, SignError};
use crate::sign::{SecretKeyBytes, SignRaw};
use crate::validate::{PublicKeyBytes, Signature};

#[cfg(feature = "openssl")]
use crate::sign::crypto::openssl;

#[cfg(feature = "ring")]
use crate::sign::crypto::ring;

//----------- KeyPair --------------------------------------------------------

/// A key pair based on a built-in backend.
///
/// This supports any built-in backend (currently, that is OpenSSL and Ring,
/// if their respective feature flags are enabled).  Wherever possible, it
/// will prefer the Ring backend over OpenSSL -- but for more uncommon or
/// insecure algorithms, that Ring does not support, OpenSSL must be used.
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
    pub fn from_bytes(
        secret: &SecretKeyBytes,
        public: &PublicKeyBytes,
    ) -> Result<Self, FromBytesError> {
        // Prefer Ring if it is available.
        #[cfg(feature = "ring")]
        match public {
            PublicKeyBytes::RsaSha1(k)
            | PublicKeyBytes::RsaSha1Nsec3Sha1(k)
            | PublicKeyBytes::RsaSha256(k)
            | PublicKeyBytes::RsaSha512(k)
                if k.n.len() >= 2048 / 8 =>
            {
                let rng = Arc::new(SystemRandom::new());
                let key = ring::KeyPair::from_bytes(secret, public, rng)?;
                return Ok(Self::Ring(key));
            }

            PublicKeyBytes::EcdsaP256Sha256(_)
            | PublicKeyBytes::EcdsaP384Sha384(_) => {
                let rng = Arc::new(SystemRandom::new());
                let key = ring::KeyPair::from_bytes(secret, public, rng)?;
                return Ok(Self::Ring(key));
            }

            PublicKeyBytes::Ed25519(_) => {
                let rng = Arc::new(SystemRandom::new());
                let key = ring::KeyPair::from_bytes(secret, public, rng)?;
                return Ok(Self::Ring(key));
            }

            _ => {}
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

    fn raw_public_key(&self) -> PublicKeyBytes {
        match self {
            #[cfg(feature = "ring")]
            Self::Ring(key) => key.raw_public_key(),
            #[cfg(feature = "openssl")]
            Self::OpenSSL(key) => key.raw_public_key(),
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
) -> Result<(SecretKeyBytes, PublicKeyBytes), GenerateError> {
    // Use Ring if it is available.
    #[cfg(feature = "ring")]
    if matches!(
        &params,
        GenerateParams::EcdsaP256Sha256
            | GenerateParams::EcdsaP384Sha384
            | GenerateParams::Ed25519
    ) {
        let rng = ::ring::rand::SystemRandom::new();
        return Ok(ring::generate(params, &rng)?);
    }

    // Fall back to OpenSSL.
    #[cfg(feature = "openssl")]
    {
        let key = openssl::generate(params)?;
        return Ok((key.to_bytes(), key.raw_public_key()));
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
