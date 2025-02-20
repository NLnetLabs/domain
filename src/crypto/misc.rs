use crate::base::iana::SecAlg;
use crate::dnssec::sign::error::SignError;

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

    /// The raw public key.
    ///
    /// This can be used to verify produced signatures.  It must use the same
    /// algorithm as returned by [`algorithm()`].
    ///
    /// [`algorithm()`]: Self::algorithm()
    fn raw_public_key(&self) -> PublicKeyBytes;

    /// Sign the given bytes.
    ///
    /// # Errors
    ///
    /// See [`SignError`] for a discussion of possible failure cases.  To the
    /// greatest extent possible, the implementation should check for failure
    /// cases beforehand and prevent them (e.g. when the keypair is created).
    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError>;
}

//----------- PublicKeyBytes -------------------------------------------------

/// A low-level public key.
#[derive(Clone, Debug)]
pub enum PublicKeyBytes {
    /// An RSA/SHA-1 public key.
    RsaSha1(RsaPublicKeyBytes),

    /// An RSA/SHA-1 with NSEC3 public key.
    RsaSha1Nsec3Sha1(RsaPublicKeyBytes),

    /// An RSA/SHA-256 public key.
    RsaSha256(RsaPublicKeyBytes),

    /// An RSA/SHA-512 public key.
    RsaSha512(RsaPublicKeyBytes),

    /// An ECDSA P-256/SHA-256 public key.
    ///
    /// The public key is stored in uncompressed format:
    ///
    /// - A single byte containing the value 0x04.
    /// - The encoding of the `x` coordinate (32 bytes).
    /// - The encoding of the `y` coordinate (32 bytes).
    EcdsaP256Sha256(Box<[u8; 65]>),

    /// An ECDSA P-384/SHA-384 public key.
    ///
    /// The public key is stored in uncompressed format:
    ///
    /// - A single byte containing the value 0x04.
    /// - The encoding of the `x` coordinate (48 bytes).
    /// - The encoding of the `y` coordinate (48 bytes).
    EcdsaP384Sha384(Box<[u8; 97]>),

    /// An Ed25519 public key.
    ///
    /// The public key is a 32-byte encoding of the public point.
    Ed25519(Box<[u8; 32]>),

    /// An Ed448 public key.
    ///
    /// The public key is a 57-byte encoding of the public point.
    Ed448(Box<[u8; 57]>),
}

//--- Inspection

impl PublicKeyBytes {
    /// The algorithm used by this key.
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

    /// The size of this key, in bits.
    ///
    /// For RSA keys, this measures the size of the public modulus.  For all
    /// other algorithms, it is the size of the fixed-width public key.
    pub fn key_size(&self) -> usize {
        match self {
            Self::RsaSha1(k)
            | Self::RsaSha1Nsec3Sha1(k)
            | Self::RsaSha256(k)
            | Self::RsaSha512(k) => k.key_size(),

            // ECDSA public keys have a marker byte and two points.
            Self::EcdsaP256Sha256(k) => (k.len() - 1) / 2 * 8,
            Self::EcdsaP384Sha384(k) => (k.len() - 1) / 2 * 8,

            // EdDSA public key sizes are measured in encoded form.
            Self::Ed25519(k) => k.len() * 8,
            Self::Ed448(k) => k.len() * 8,
        }
    }
}

//--- Conversion to and from DNSKEYs

impl PublicKeyBytes {
    /// Parse a public key as stored in a DNSKEY record.
    pub fn from_dnskey_format(
        algorithm: SecAlg,
        data: &[u8],
    ) -> Result<Self, FromDnskeyError> {
        match algorithm {
            SecAlg::RSASHA1 => {
                RsaPublicKeyBytes::from_dnskey_format(data).map(Self::RsaSha1)
            }
            SecAlg::RSASHA1_NSEC3_SHA1 => {
                RsaPublicKeyBytes::from_dnskey_format(data)
                    .map(Self::RsaSha1Nsec3Sha1)
            }
            SecAlg::RSASHA256 => RsaPublicKeyBytes::from_dnskey_format(data)
                .map(Self::RsaSha256),
            SecAlg::RSASHA512 => RsaPublicKeyBytes::from_dnskey_format(data)
                .map(Self::RsaSha512),

            SecAlg::ECDSAP256SHA256 => {
                let mut key = Box::new([0u8; 65]);
                if key.len() == 1 + data.len() {
                    key[0] = 0x04;
                    key[1..].copy_from_slice(data);
                    Ok(Self::EcdsaP256Sha256(key))
                } else {
                    Err(FromDnskeyError::InvalidKey)
                }
            }
            SecAlg::ECDSAP384SHA384 => {
                let mut key = Box::new([0u8; 97]);
                if key.len() == 1 + data.len() {
                    key[0] = 0x04;
                    key[1..].copy_from_slice(data);
                    Ok(Self::EcdsaP384Sha384(key))
                } else {
                    Err(FromDnskeyError::InvalidKey)
                }
            }

            SecAlg::ED25519 => Box::<[u8]>::from(data)
                .try_into()
                .map(Self::Ed25519)
                .map_err(|_| FromDnskeyError::InvalidKey),
            SecAlg::ED448 => Box::<[u8]>::from(data)
                .try_into()
                .map(Self::Ed448)
                .map_err(|_| FromDnskeyError::InvalidKey),

            _ => Err(FromDnskeyError::UnsupportedAlgorithm),
        }
    }

    /// Serialize this public key as stored in a DNSKEY record.
    pub fn to_dnskey_format(&self) -> Box<[u8]> {
        match self {
            Self::RsaSha1(k)
            | Self::RsaSha1Nsec3Sha1(k)
            | Self::RsaSha256(k)
            | Self::RsaSha512(k) => k.to_dnskey_format(),

            // From my reading of RFC 6605, the marker byte is not included.
            Self::EcdsaP256Sha256(k) => k[1..].into(),
            Self::EcdsaP384Sha384(k) => k[1..].into(),

            Self::Ed25519(k) => k.as_slice().into(),
            Self::Ed448(k) => k.as_slice().into(),
        }
    }
}

//--- Comparison

impl PartialEq for PublicKeyBytes {
    fn eq(&self, other: &Self) -> bool {
        use ::ring::constant_time::verify_slices_are_equal;

        match (self, other) {
            (Self::RsaSha1(a), Self::RsaSha1(b)) => a == b,
            (Self::RsaSha1Nsec3Sha1(a), Self::RsaSha1Nsec3Sha1(b)) => a == b,
            (Self::RsaSha256(a), Self::RsaSha256(b)) => a == b,
            (Self::RsaSha512(a), Self::RsaSha512(b)) => a == b,
            (Self::EcdsaP256Sha256(a), Self::EcdsaP256Sha256(b)) => {
                verify_slices_are_equal(&**a, &**b).is_ok()
            }
            (Self::EcdsaP384Sha384(a), Self::EcdsaP384Sha384(b)) => {
                verify_slices_are_equal(&**a, &**b).is_ok()
            }
            (Self::Ed25519(a), Self::Ed25519(b)) => {
                verify_slices_are_equal(&**a, &**b).is_ok()
            }
            (Self::Ed448(a), Self::Ed448(b)) => {
                verify_slices_are_equal(&**a, &**b).is_ok()
            }
            _ => false,
        }
    }
}

impl Eq for PublicKeyBytes {}

//----------- RsaPublicKeyBytes ----------------------------------------------

/// A generic RSA public key.
///
/// All fields here are arbitrary-precision integers in big-endian format,
/// without any leading zero bytes.
#[derive(Clone, Debug)]
pub struct RsaPublicKeyBytes {
    /// The public modulus.
    pub n: Box<[u8]>,

    /// The public exponent.
    pub e: Box<[u8]>,
}

//--- Inspection

impl RsaPublicKeyBytes {
    /// The size of the public modulus, in bits.
    pub fn key_size(&self) -> usize {
        self.n.len() * 8 - self.n[0].leading_zeros() as usize
    }
}

//--- Conversion to and from DNSKEYs

impl RsaPublicKeyBytes {
    /// Parse an RSA public key as stored in a DNSKEY record.
    pub fn from_dnskey_format(data: &[u8]) -> Result<Self, FromDnskeyError> {
        if data.len() < 3 {
            return Err(FromDnskeyError::InvalidKey);
        }

        // The exponent length is encoded as 1 or 3 bytes.
        let (exp_len, off) = if data[0] != 0 {
            (data[0] as usize, 1)
        } else if data[1..3] != [0, 0] {
            // NOTE: Even though this is the extended encoding of the length,
            // a user could choose to put a length less than 256 over here.
            let exp_len = u16::from_be_bytes(data[1..3].try_into().unwrap());
            (exp_len as usize, 3)
        } else {
            // The extended encoding of the length just held a zero value.
            return Err(FromDnskeyError::InvalidKey);
        };

        // NOTE: off <= 3 so is safe to index up to.
        let e: Box<[u8]> = data[off..]
            .get(..exp_len)
            .ok_or(FromDnskeyError::InvalidKey)?
            .into();

        // NOTE: The previous statement indexed up to 'exp_len'.
        let n: Box<[u8]> = data[off + exp_len..].into();

        // Empty values and leading zeros are not allowed.
        if e.is_empty() || n.is_empty() || e[0] == 0 || n[0] == 0 {
            return Err(FromDnskeyError::InvalidKey);
        }

        Ok(Self { n, e })
    }

    /// Serialize this public key as stored in a DNSKEY record.
    pub fn to_dnskey_format(&self) -> Box<[u8]> {
        let mut key = Vec::new();

        // Encode the exponent length.
        if let Ok(exp_len) = u8::try_from(self.e.len()) {
            key.reserve_exact(1 + self.e.len() + self.n.len());
            key.push(exp_len);
        } else if let Ok(exp_len) = u16::try_from(self.e.len()) {
            key.reserve_exact(3 + self.e.len() + self.n.len());
            key.push(0u8);
            key.extend(&exp_len.to_be_bytes());
        } else {
            unreachable!("RSA exponents are (much) shorter than 64KiB")
        }

        key.extend(&*self.e);
        key.extend(&*self.n);
        key.into_boxed_slice()
    }
}

//--- Comparison

impl PartialEq for RsaPublicKeyBytes {
    fn eq(&self, other: &Self) -> bool {
        use ::ring::constant_time::verify_slices_are_equal;

        verify_slices_are_equal(&self.n, &other.n).is_ok()
            && verify_slices_are_equal(&self.e, &other.e).is_ok()
    }
}

impl Eq for RsaPublicKeyBytes {}

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
