//! DNSSEC message digests and signature verification using built-in backends.
//!
//! This backend supports all the algorithms supported by Ring and OpenSSL,
//! depending on whether the respective crate features are enabled.  See the
//! documentation for each backend for more information.

use core::fmt;
use std::error;
use std::vec::Vec;

use crate::rdata::Dnskey;

#[cfg(feature = "openssl")]
use super::openssl;

#[cfg(feature = "ring")]
use super::ring;

//----------- DigestType -----------------------------------------------------

/// Type of message digest to compute.
pub enum DigestType {
    /// [FIPS Secure Hash Standard] Section 6.1.
    ///
    /// [FIPS Secure Hash Standard]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    Sha1,

    /// [FIPS Secure Hash Standard] Section 6.2.
    ///
    /// [FIPS Secure Hash Standard]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    Sha256,

    /// [FIPS Secure Hash Standard] Section 6.5.
    ///
    /// [FIPS Secure Hash Standard]: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    Sha384,
}

//----------- DigestContext --------------------------------------------------

/// Context for computing a message digest.
pub enum DigestContext {
    #[cfg(feature = "ring")]
    /// Use ring to compute the message digest.
    Ring(ring::DigestContext),
    #[cfg(feature = "openssl")]
    /// Use openssl to compute the message digest.
    Openssl(openssl::DigestContext),
}

impl DigestContext {
    #[allow(unreachable_code)]
    /// Create a new context for a specified digest type.
    pub fn new(digest_type: DigestType) -> Self {
        #[cfg(feature = "ring")]
        return Self::Ring(ring::DigestContext::new(digest_type));

        #[cfg(feature = "openssl")]
        return Self::Openssl(openssl::DigestContext::new(digest_type));

        #[cfg(not(any(feature = "ring", feature = "openssl")))]
        compile_error!("Either feature \"ring\" or \"openssl\" must be enabled for this crate.");
    }

    /// Add input to the digest computation.
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

    /// Finish computing the digest.
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

/// A message digest.
pub enum Digest {
    #[cfg(feature = "ring")]
    /// A message digest computed using ring.
    Ring(ring::Digest),
    #[cfg(feature = "openssl")]
    /// A message digest computed using openssl.
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

/// A public key for verifying a signature.
pub enum PublicKey {
    #[cfg(feature = "ring")]
    /// A public key implemented using ring.
    Ring(ring::PublicKey),

    #[cfg(feature = "openssl")]
    /// A public key implemented using openssl.
    Openssl(openssl::PublicKey),
}

impl PublicKey {
    #[allow(unreachable_code)]
    /// Create a public key from a [`Dnskey`].
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

    /// Verify a signature.
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

//----------- FromDnskeyError ------------------------------------------------

/// An error in reading a DNSKEY record.
#[derive(Clone, Debug)]
pub enum FromDnskeyError {
    /// The key's algorithm is not supported.
    UnsupportedAlgorithm,

    /// The key's protocol is not supported.
    UnsupportedProtocol,

    /// The key is not valid.
    InvalidKey,
}

//--- Display, Error

impl fmt::Display for FromDnskeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "unsupported algorithm",
            Self::UnsupportedProtocol => "unsupported protocol",
            Self::InvalidKey => "malformed key",
        })
    }
}

impl error::Error for FromDnskeyError {}
