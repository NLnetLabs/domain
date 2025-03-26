//! DNSSEC message digests and signature verification using built-in backends.
//!
//! This backend supports all the algorithms supported by Ring and OpenSSL,
//! depending on whether the respective crate features are enabled.  See the
//! documentation for each backend for more information.

#![cfg(any(feature = "ring", feature = "openssl"))]
#![cfg_attr(docsrs, doc(cfg(any(feature = "ring", feature = "openssl"))))]

use core::fmt;
use std::error;
use std::vec::Vec;

use crate::rdata::Dnskey;

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
#[cfg(feature = "ring")]
pub type DigestContext = super::ring::DigestContext;
#[cfg(all(feature = "openssl", not(feature = "ring")))]
pub type DigestContext = super::openssl::DigestContext;

//----------- Digest ---------------------------------------------------------

/// Context for computing a message digest.
#[cfg(feature = "ring")]
pub type Digest = super::ring::Digest;
#[cfg(all(feature = "openssl", not(feature = "ring")))]
pub type Digest = super::openssl::Digest;

//----------- PublicKey ------------------------------------------------------

/// Context for computing a message digest.
#[cfg(feature = "ring")]
pub type PublicKey = super::ring::PublicKey;
#[cfg(all(feature = "openssl", not(feature = "ring")))]
pub type PublicKey = super::openssl::PublicKey;

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
