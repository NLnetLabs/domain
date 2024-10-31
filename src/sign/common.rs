//! DNSSEC signing using built-in backends.
//!
//! This backend supports all the algorithms supported by Ring and OpenSSL,
//! depending on whether the respective crate features are enabled.  See the
//! documentation for each backend for more information.

use core::fmt;
use std::sync::Arc;

use ::ring::rand::SystemRandom;

use crate::{
    base::iana::SecAlg,
    validate::{PublicKeyBytes, Signature},
};

use super::{GenerateParams, SecretKeyBytes, SignError, SignRaw};

#[cfg(feature = "openssl")]
use super::openssl;

#[cfg(feature = "ring")]
use super::ring;

//----------- KeyPair --------------------------------------------------------

/// A key pair based on a built-in backend.
///
/// This supports any built-in backend (currently, that is OpenSSL and Ring).
/// Wherever possible, the Ring backend is preferred over OpenSSL -- but for
/// more uncommon or insecure algorithms, that Ring does not support, OpenSSL
/// must be used.
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

//============ Error Types ===================================================

//----------- FromBytesError -----------------------------------------------

/// An error in importing a key pair from bytes.
#[derive(Clone, Debug)]
pub enum FromBytesError {
    /// The requested algorithm was not supported.
    UnsupportedAlgorithm,

    /// The key's parameters were invalid.
    InvalidKey,

    /// The implementation does not allow such weak keys.
    WeakKey,

    /// An implementation failure occurred.
    ///
    /// This includes memory allocation failures.
    Implementation,
}

//--- Conversions

#[cfg(feature = "ring")]
impl From<ring::FromBytesError> for FromBytesError {
    fn from(value: ring::FromBytesError) -> Self {
        match value {
            ring::FromBytesError::UnsupportedAlgorithm => {
                Self::UnsupportedAlgorithm
            }
            ring::FromBytesError::InvalidKey => Self::InvalidKey,
            ring::FromBytesError::WeakKey => Self::WeakKey,
        }
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::FromBytesError> for FromBytesError {
    fn from(value: openssl::FromBytesError) -> Self {
        match value {
            openssl::FromBytesError::UnsupportedAlgorithm => {
                Self::UnsupportedAlgorithm
            }
            openssl::FromBytesError::InvalidKey => Self::InvalidKey,
            openssl::FromBytesError::Implementation => Self::Implementation,
        }
    }
}

//--- Formatting

impl fmt::Display for FromBytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "algorithm not supported",
            Self::InvalidKey => "malformed or insecure private key",
            Self::WeakKey => "key too weak to be supported",
            Self::Implementation => "an internal error occurred",
        })
    }
}

//--- Error

impl std::error::Error for FromBytesError {}

//----------- GenerateError --------------------------------------------------

/// An error in generating a key pair.
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

#[cfg(feature = "ring")]
impl From<ring::GenerateError> for GenerateError {
    fn from(value: ring::GenerateError) -> Self {
        match value {
            ring::GenerateError::UnsupportedAlgorithm => {
                Self::UnsupportedAlgorithm
            }
            ring::GenerateError::Implementation => Self::Implementation,
        }
    }
}

#[cfg(feature = "openssl")]
impl From<openssl::GenerateError> for GenerateError {
    fn from(value: openssl::GenerateError) -> Self {
        match value {
            openssl::GenerateError::UnsupportedAlgorithm => {
                Self::UnsupportedAlgorithm
            }
            openssl::GenerateError::Implementation => Self::Implementation,
        }
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
