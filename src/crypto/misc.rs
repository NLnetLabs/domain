use crate::base::iana::SecAlg;
use crate::dnssec::sign::error::SignError;
use crate::rdata::Dnskey;

use std::boxed::Box;
use std::vec::Vec;
use std::{error, fmt};

//----------- SignRaw --------------------------------------------------------

/// Low-level signing functionality.
///
/// Types that implement this trait own a private key and can sign arbitrary
/// information (in the form of slices of bytes).
///
/// Implementing types should validate keys during construction, so that
/// signing does not fail due to invalid keys.  If the implementing type
/// allows [`sign_raw()`] to be called on unvalidated keys, it will have to
/// check the validity of the key for every signature; this is unnecessary
/// overhead when many signatures have to be generated.
///
/// [`sign_raw()`]: SignRaw::sign_raw()
pub trait SignRaw {
    /// The signature algorithm used.
    ///
    /// See [RFC 8624, section 3.1] for IETF implementation recommendations.
    ///
    /// [RFC 8624, section 3.1]: https://datatracker.ietf.org/doc/html/rfc8624#section-3.1
    fn algorithm(&self) -> SecAlg;

    /// The public key.
    ///
    /// This can be used to verify produced signatures.  It must use the same
    /// algorithm as returned by [`algorithm()`].
    ///
    /// [`algorithm()`]: Self::algorithm()
    fn dnskey(&self) -> Dnskey<Vec<u8>>;

    /// Sign the given bytes.
    ///
    /// # Errors
    ///
    /// See [`SignError`] for a discussion of possible failure cases.  To the
    /// greatest extent possible, the implementation should check for failure
    /// cases beforehand and prevent them (e.g. when the keypair is created).
    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError>;
}

//----------- Signature ------------------------------------------------------

/// A cryptographic signature.
///
/// The format of the signature varies depending on the underlying algorithm:
///
/// - RSA: the signature is a single integer `s`, which is less than the key's
///   public modulus `n`.  `s` is encoded as bytes and ordered from most
///   significant to least significant digits.  It must be at least 64 bytes
///   long and at most 512 bytes long.  Leading zero bytes can be inserted for
///   padding.
///
///   See [RFC 3110](https://datatracker.ietf.org/doc/html/rfc3110).
///
/// - ECDSA: the signature has a fixed length (64 bytes for P-256, 96 for
///   P-384).  It is the concatenation of two fixed-length integers (`r` and
///   `s`, each of equal size).
///
///   See [RFC 6605](https://datatracker.ietf.org/doc/html/rfc6605) and [SEC 1
///   v2.0](https://www.secg.org/sec1-v2.pdf).
///
/// - EdDSA: the signature has a fixed length (64 bytes for ED25519, 114 bytes
///   for ED448).  It is the concatenation of two curve points (`R` and `S`)
///   that are encoded into bytes.
///
/// Signatures are too big to pass by value, so they are placed on the heap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    RsaSha1(Box<[u8]>),
    RsaSha1Nsec3Sha1(Box<[u8]>),
    RsaSha256(Box<[u8]>),
    RsaSha512(Box<[u8]>),
    EcdsaP256Sha256(Box<[u8; 64]>),
    EcdsaP384Sha384(Box<[u8; 96]>),
    Ed25519(Box<[u8; 64]>),
    Ed448(Box<[u8; 114]>),
}

impl Signature {
    /// The algorithm used to make the signature.
    pub fn algorithm(&self) -> SecAlg {
        match self {
            Self::RsaSha1(_) => SecAlg::RSASHA1,
            Self::RsaSha1Nsec3Sha1(_) => SecAlg::RSASHA1_NSEC3_SHA1,
            Self::RsaSha256(_) => SecAlg::RSASHA256,
            Self::RsaSha512(_) => SecAlg::RSASHA512,
            Self::EcdsaP256Sha256(_) => SecAlg::ECDSAP256SHA256,
            Self::EcdsaP384Sha384(_) => SecAlg::ECDSAP384SHA384,
            Self::Ed25519(_) => SecAlg::ED25519,
            Self::Ed448(_) => SecAlg::ED448,
        }
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::RsaSha1(s)
            | Self::RsaSha1Nsec3Sha1(s)
            | Self::RsaSha256(s)
            | Self::RsaSha512(s) => s,
            Self::EcdsaP256Sha256(s) => &**s,
            Self::EcdsaP384Sha384(s) => &**s,
            Self::Ed25519(s) => &**s,
            Self::Ed448(s) => &**s,
        }
    }
}

impl From<Signature> for Box<[u8]> {
    fn from(value: Signature) -> Self {
        match value {
            Signature::RsaSha1(s)
            | Signature::RsaSha1Nsec3Sha1(s)
            | Signature::RsaSha256(s)
            | Signature::RsaSha512(s) => s,
            Signature::EcdsaP256Sha256(s) => s as _,
            Signature::EcdsaP384Sha384(s) => s as _,
            Signature::Ed25519(s) => s as _,
            Signature::Ed448(s) => s as _,
        }
    }
}

//============ Error Types ===================================================

//----------- DigestError ----------------------------------------------------

/// An error when computing a digest.
#[derive(Clone, Debug)]
pub enum DigestError {
    UnsupportedAlgorithm,
}

//--- Display, Error

impl fmt::Display for DigestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedAlgorithm => "unsupported algorithm",
        })
    }
}

impl error::Error for DigestError {}

//----------- FromDnskeyError ------------------------------------------------

/// An error in reading a DNSKEY record.
#[derive(Clone, Debug)]
pub enum FromDnskeyError {
    UnsupportedAlgorithm,
    UnsupportedProtocol,
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

//----------- ParseDnskeyTextError -------------------------------------------

#[derive(Clone, Debug)]
pub enum ParseDnskeyTextError {
    Misformatted,
    FromDnskey(FromDnskeyError),
}

//--- Display, Error

impl fmt::Display for ParseDnskeyTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Misformatted => "misformatted DNSKEY record",
            Self::FromDnskey(e) => return e.fmt(f),
        })
    }
}

impl error::Error for ParseDnskeyTextError {}
