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

//----------- DigestBuilder --------------------------------------------------

/// Builder for computing a message digest.
pub enum DigestBuilder {
    /// Use ring to compute the message digest.
    #[cfg(feature = "ring")]
    Ring(ring::DigestBuilder),
    /// Use openssl to compute the message digest.
    #[cfg(feature = "openssl")]
    Openssl(openssl::DigestBuilder),
}

impl DigestBuilder {
    /// Create a new context for a specified digest type.
    #[allow(unreachable_code)]
    pub fn new(digest_type: DigestType) -> Self {
        #[cfg(feature = "ring")]
        return Self::Ring(ring::DigestBuilder::new(digest_type));

        #[cfg(feature = "openssl")]
        return Self::Openssl(openssl::DigestBuilder::new(digest_type));
    }

    /// Add input to the digest computation.
    pub fn update(&mut self, data: &[u8]) {
        match self {
            #[cfg(feature = "ring")]
            DigestBuilder::Ring(digest_context) => {
                digest_context.update(data)
            }
            #[cfg(feature = "openssl")]
            DigestBuilder::Openssl(digest_context) => {
                digest_context.update(data)
            }
        }
    }

    /// Finish computing the digest.
    pub fn finish(self) -> Digest {
        match self {
            #[cfg(feature = "ring")]
            DigestBuilder::Ring(digest_context) => {
                Digest::Ring(digest_context.finish())
            }
            #[cfg(feature = "openssl")]
            DigestBuilder::Openssl(digest_context) => {
                Digest::Openssl(digest_context.finish())
            }
        }
    }
}

//----------- Digest ---------------------------------------------------------

/// A message digest.
pub enum Digest {
    /// A message digest computed using ring.
    #[cfg(feature = "ring")]
    Ring(ring::Digest),
    /// A message digest computed using openssl.
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

/// A public key for verifying a signature.
pub enum PublicKey {
    /// A public key implemented using ring.
    #[cfg(feature = "ring")]
    Ring(ring::PublicKey),

    /// A public key implemented using openssl.
    #[cfg(feature = "openssl")]
    Openssl(openssl::PublicKey),
}

impl PublicKey {
    /// Create a public key from a [`Dnskey`].
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
    let public_key: &[u8] = dnskey.public_key().as_ref();

    // Determine the exponent length.
    let (exp_len, rest) = match *public_key {
        [exp_len @ 1..=255, ref rest @ ..] => (exp_len as usize, rest),

        [0, hi @ 1..=255, lo, ref rest @ ..] => {
            let exp_len = u16::from_be_bytes([hi, lo]);
            (exp_len as usize, rest)
        }

        _ => return Err(AlgorithmError::InvalidData),
    };

    // Split the exponent and the modulus.
    if rest.len() < exp_len {
        return Err(AlgorithmError::InvalidData);
    }
    let (exp, num) = rest.split_at(exp_len);

    // Validate the exponent and modulus.
    for i in [exp, num] {
        // [RFC 3110, section 2](https://www.rfc-editor.org/rfc/rfc3110#section-2):
        //
        // > For interoperability, the exponent and modulus are each limited
        // > to 4096 bits in length.
        //
        // > Leading zero octets are prohibited in the exponent and modulus.
        if !(1..=512).contains(&i.len()) || i[0] == 0 {
            return Err(AlgorithmError::InvalidData);
        }
    }

    // Check that the modulus is big enough for the caller.
    if num.len() < min_len {
        return Err(AlgorithmError::Unsupported);
    }

    Ok((exp.to_vec(), num.to_vec()))
}

/// Encode the RSA exponent and modulus components in DNSKEY record data
/// format.
pub fn rsa_encode(e: &[u8], n: &[u8]) -> Vec<u8> {
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
        unreachable!("RSA exponents are (much) shorter than 64KiB")
    }

    key.extend(e);
    key.extend(n);

    key
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
