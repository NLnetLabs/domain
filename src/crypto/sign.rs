//! DNSSEC signing using built-in backends.
//!
//! This backend supports all the algorithms supported by Ring and OpenSSL,
//! depending on whether the respective crate features are enabled.  See the
//! documentation for each backend for more information.
//!
//! The [`SecretKeyBytes`] type is a generic representation of a secret key as
//! a byte slice.  While it does not offer any cryptographic functionality, it
//! is useful to transfer secret keys stored in memory, independent of any
//! cryptographic backend.
//!
//! [`SecretKeyBytes`] also supports importing and exporting keys from and to
//! the conventional private-key format popularized by BIND.  This format is
//! used by a variety of tools for storing DNSSEC keys on disk.  See the
//! type-level documentation for a specification of the format.
//!
//! # Importing keys
//!
//! Keys can be imported from files stored on disk in the conventional BIND
//! format.
//!
//! ```
//! # use domain::base::iana::SecurityAlgorithm;
//! # use domain::crypto::sign::{KeyPair, self, SecretKeyBytes, SignRaw};
//! # use domain::dnssec::common::parse_from_bind;
//! // Load an Ed25519 key named 'Ktest.+015+56037'.
//! let base = "test-data/dnssec-keys/Ktest.+015+56037";
//! let sec_text = std::fs::read_to_string(format!("{base}.private")).unwrap();
//! let sec_bytes = SecretKeyBytes::parse_from_bind(&sec_text).unwrap();
//! let pub_text = std::fs::read_to_string(format!("{base}.key")).unwrap();
//! let pub_key = parse_from_bind::<Vec<u8>>(&pub_text).unwrap();
//!
//! // Parse the key into Ring or OpenSSL.
//! let key_pair = KeyPair::from_bytes(&sec_bytes, pub_key.data())
//!     .unwrap();
//!
//! // Check that the owner, algorithm, and key tag matched expectations.
//! assert_eq!(key_pair.algorithm(), SecurityAlgorithm::ED25519);
//! assert_eq!(key_pair.dnskey().key_tag(), 56037);
//! ```
//!
//! # Generating keys
//!
//! Keys can also be generated.
//!
//! ```
//! # use domain::base::Name;
//! # use domain::crypto::common;
//! # use domain::crypto::sign::{generate, GenerateParams, KeyPair};
//! // Generate a new Ed25519 key.
//! let params = GenerateParams::Ed25519;
//! let (sec_bytes, pub_key) = generate(params, 257).unwrap();
//!
//! // Parse the key into Ring or OpenSSL.
//! let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_key).unwrap();
//!
//! // Access the public key (with metadata).
//! println!("{:?}", pub_key);
//! ```
//!
//! # Signing data
//!
//! Given some data and a key, the data can be signed with the key.
//!
//! ```
//! # use domain::base::Name;
//! # use domain::crypto::common;
//! # use domain::crypto::sign::{generate, GenerateParams, KeyPair, SignRaw};
//! # let (sec_bytes, pub_bytes) = generate(
//!        GenerateParams::Ed25519,
//!        256).unwrap();
//! # let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//! // Sign arbitrary byte sequences with the key.
//! let sig = key_pair.sign_raw(b"Hello, World!").unwrap();
//! println!("{:?}", sig);
//! ```
//!

#![cfg(feature = "unstable-crypto-sign")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-crypto-sign")))]

use std::boxed::Box;
use std::fmt;
use std::vec::Vec;

use secrecy::{ExposeSecret, SecretBox};

use crate::base::iana::SecurityAlgorithm;
use crate::rdata::Dnskey;
use crate::utils::base64;

#[cfg(feature = "openssl")]
use super::openssl;

#[cfg(feature = "ring")]
use super::ring;

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
    pub fn algorithm(&self) -> SecurityAlgorithm {
        match self {
            Self::RsaSha256 { .. } => SecurityAlgorithm::RSASHA256,
            Self::EcdsaP256Sha256 => SecurityAlgorithm::ECDSAP256SHA256,
            Self::EcdsaP384Sha384 => SecurityAlgorithm::ECDSAP384SHA384,
            Self::Ed25519 => SecurityAlgorithm::ED25519,
            Self::Ed448 => SecurityAlgorithm::ED448,
        }
    }
}

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
    fn algorithm(&self) -> SecurityAlgorithm;

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
    /// Signature using RSA and SHA-1.
    RsaSha1(Box<[u8]>),

    /// Signature using RSA and SHA-1. This also signals support for NSEC3.
    RsaSha1Nsec3Sha1(Box<[u8]>),

    /// Signature using RSA and SHA-256.
    RsaSha256(Box<[u8]>),

    /// Signature using RSA and SHA-512.
    RsaSha512(Box<[u8]>),

    /// Signature using ECDSA and SHA-256.
    EcdsaP256Sha256(Box<[u8; 64]>),

    /// Signature using ECDSA and SHA-384.
    EcdsaP384Sha384(Box<[u8; 96]>),

    /// Signature using Ed25519.
    Ed25519(Box<[u8; 64]>),

    /// Signature using Ed448.
    Ed448(Box<[u8; 114]>),
}

impl Signature {
    /// The algorithm used to make the signature.
    pub fn algorithm(&self) -> SecurityAlgorithm {
        match self {
            Self::RsaSha1(_) => SecurityAlgorithm::RSASHA1,
            Self::RsaSha1Nsec3Sha1(_) => {
                SecurityAlgorithm::RSASHA1_NSEC3_SHA1
            }
            Self::RsaSha256(_) => SecurityAlgorithm::RSASHA256,
            Self::RsaSha512(_) => SecurityAlgorithm::RSASHA512,
            Self::EcdsaP256Sha256(_) => SecurityAlgorithm::ECDSAP256SHA256,
            Self::EcdsaP384Sha384(_) => SecurityAlgorithm::ECDSAP384SHA384,
            Self::Ed25519(_) => SecurityAlgorithm::ED25519,
            Self::Ed448(_) => SecurityAlgorithm::ED448,
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
    Ring(ring::sign::KeyPair),

    /// A key backed by OpenSSL.
    #[cfg(feature = "openssl")]
    OpenSSL(openssl::sign::KeyPair),
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
        {
            let fallback_to_openssl = match public.algorithm() {
                SecurityAlgorithm::RSASHA1
                | SecurityAlgorithm::RSASHA1_NSEC3_SHA1
                | SecurityAlgorithm::RSASHA256
                | SecurityAlgorithm::RSASHA512 => {
                    ring::PublicKey::from_dnskey(public)
                        .map_err(|_| FromBytesError::InvalidKey)?
                        .key_size()
                        < 2048
                }
                _ => false,
            };

            if !fallback_to_openssl {
                let key = ring::sign::KeyPair::from_bytes(secret, public)?;
                return Ok(Self::Ring(key));
            }
        }

        // Fall back to OpenSSL.
        #[cfg(feature = "openssl")]
        return Ok(Self::OpenSSL(openssl::sign::KeyPair::from_bytes(
            secret, public,
        )?));

        // Otherwise fail.
        #[allow(unreachable_code)]
        Err(FromBytesError::UnsupportedAlgorithm)
    }
}

//--- SignRaw

impl SignRaw for KeyPair {
    fn algorithm(&self) -> SecurityAlgorithm {
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
        return Ok(ring::sign::generate(params, flags, &rng)?);
    }

    // Fall back to OpenSSL.
    #[cfg(feature = "openssl")]
    {
        let key = openssl::sign::generate(params, flags)?;
        return Ok((key.to_bytes(), key.dnskey()));
    }

    // Otherwise fail.
    #[allow(unreachable_code)]
    Err(GenerateError::UnsupportedAlgorithm)
}

//----------- SecretKeyBytes -------------------------------------------------

/// A secret key expressed as raw bytes.
///
/// This is a low-level generic representation of a secret key from any one of
/// the commonly supported signature algorithms.  It is useful for abstracting
/// over most cryptographic implementations, and it provides functionality for
/// importing and exporting keys from and to the disk.
///
/// # Serialization
///
/// This type can be used to interact with private keys stored in the format
/// popularized by BIND.  The format is rather under-specified, but examples
/// of it are available in [RFC 5702], [RFC 6605], and [RFC 8080].
///
/// [RFC 5702]: https://www.rfc-editor.org/rfc/rfc5702
/// [RFC 6605]: https://www.rfc-editor.org/rfc/rfc6605
/// [RFC 8080]: https://www.rfc-editor.org/rfc/rfc8080
///
/// In this format, a private key is a line-oriented text file.  Each line is
/// either blank (having only whitespace) or a key-value entry.  Entries have
/// three components: a key, an ASCII colon, and a value.  Keys contain ASCII
/// text (except for colons) and values contain any data up to the end of the
/// line.  Whitespace at either end of the key and the value will be ignored.
///
/// Every file begins with two entries:
///
/// - `Private-key-format` specifies the format of the file.  The RFC examples
///   above use version 1.2 (serialised `v1.2`), but recent versions of BIND
///   have defined a new version 1.3 (serialized `v1.3`).
///
///   This value should be treated akin to Semantic Versioning principles.  If
///   the major version (the first number) is unknown to a parser, it should
///   fail, since it does not know the layout of the following fields.  If the
///   minor version is greater than what a parser is expecting, it should
///   ignore any following fields it did not expect.
///
/// - `Algorithm` specifies the signing algorithm used by the private key.
///   This can affect the format of later fields.  The value consists of two
///   whitespace-separated words: the first is the ASCII decimal number of the
///   algorithm (see [`SecurityAlgorithm`]); the second is the name of the algorithm in
///   ASCII parentheses (with no whitespace inside).  Valid combinations are:
///
///   - `8 (RSASHA256)`: RSA with the SHA-256 digest.
///   - `10 (RSASHA512)`: RSA with the SHA-512 digest.
///   - `13 (ECDSAP256SHA256)`: ECDSA with the P-256 curve and SHA-256 digest.
///   - `14 (ECDSAP384SHA384)`: ECDSA with the P-384 curve and SHA-384 digest.
///   - `15 (ED25519)`: Ed25519.
///   - `16 (ED448)`: Ed448.
///
/// The value of every following entry is a Base64-encoded string of variable
/// length, using the RFC 4648 variant (i.e. with `+` and `/`, and `=` for
/// padding).  It is unclear whether padding is required or optional.
///
/// In the case of RSA, the following fields are defined (their conventional
/// symbolic names are also provided):
///
/// - `Modulus` (n)
/// - `PublicExponent` (e)
/// - `PrivateExponent` (d)
/// - `Prime1` (p)
/// - `Prime2` (q)
/// - `Exponent1` (d_p)
/// - `Exponent2` (d_q)
/// - `Coefficient` (q_inv)
///
/// For all other algorithms, there is a single `PrivateKey` field, whose
/// contents should be interpreted as:
///
/// - For ECDSA, the private scalar of the key, as a fixed-width byte string
///   interpreted as a big-endian integer.
///
/// - For EdDSA, the private scalar of the key, as a fixed-width byte string.
#[derive(Debug)]
pub enum SecretKeyBytes {
    /// An RSA/SHA-256 keypair.
    RsaSha256(RsaSecretKeyBytes),

    /// An ECDSA P-256/SHA-256 keypair.
    ///
    /// The private key is a single 32-byte big-endian integer.
    EcdsaP256Sha256(SecretBox<[u8; 32]>),

    /// An ECDSA P-384/SHA-384 keypair.
    ///
    /// The private key is a single 48-byte big-endian integer.
    EcdsaP384Sha384(SecretBox<[u8; 48]>),

    /// An Ed25519 keypair.
    ///
    /// The private key is a single 32-byte string.
    Ed25519(SecretBox<[u8; 32]>),

    /// An Ed448 keypair.
    ///
    /// The private key is a single 57-byte string.
    Ed448(SecretBox<[u8; 57]>),
}

//--- Inspection

impl SecretKeyBytes {
    /// The algorithm used by this key.
    pub fn algorithm(&self) -> SecurityAlgorithm {
        match self {
            Self::RsaSha256(_) => SecurityAlgorithm::RSASHA256,
            Self::EcdsaP256Sha256(_) => SecurityAlgorithm::ECDSAP256SHA256,
            Self::EcdsaP384Sha384(_) => SecurityAlgorithm::ECDSAP384SHA384,
            Self::Ed25519(_) => SecurityAlgorithm::ED25519,
            Self::Ed448(_) => SecurityAlgorithm::ED448,
        }
    }
}

//--- Converting to and from the BIND format

impl SecretKeyBytes {
    /// Serialize this secret key in the conventional format used by BIND.
    ///
    /// The key is formatted in the private key v1.2 format and written to the
    /// given formatter.  See the type-level documentation for a description
    /// of this format.
    pub fn format_as_bind(&self, mut w: impl fmt::Write) -> fmt::Result {
        writeln!(w, "Private-key-format: v1.2")?;
        match self {
            Self::RsaSha256(k) => {
                writeln!(w, "Algorithm: 8 (RSASHA256)")?;
                k.format_as_bind(w)
            }

            Self::EcdsaP256Sha256(s) => {
                let s = s.expose_secret();
                writeln!(w, "Algorithm: 13 (ECDSAP256SHA256)")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }

            Self::EcdsaP384Sha384(s) => {
                let s = s.expose_secret();
                writeln!(w, "Algorithm: 14 (ECDSAP384SHA384)")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }

            Self::Ed25519(s) => {
                let s = s.expose_secret();
                writeln!(w, "Algorithm: 15 (ED25519)")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }

            Self::Ed448(s) => {
                let s = s.expose_secret();
                writeln!(w, "Algorithm: 16 (ED448)")?;
                writeln!(w, "PrivateKey: {}", base64::encode_display(s))
            }
        }
    }

    /// Display this secret key in the conventional format used by BIND.
    ///
    /// This is a simple wrapper around [`Self::format_as_bind()`].
    pub fn display_as_bind(&self) -> impl fmt::Display + '_ {
        /// Display type to return from this function.
        struct Display<'a>(&'a SecretKeyBytes);
        impl fmt::Display for Display<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.format_as_bind(f)
            }
        }
        Display(self)
    }

    /// Parse a secret key from the conventional format used by BIND.
    ///
    /// This parser supports the private key v1.2 format, but it should be
    /// compatible with any future v1.x key.  See the type-level documentation
    /// for a description of this format.
    pub fn parse_from_bind(data: &str) -> Result<Self, BindFormatError> {
        /// Parse private keys for most algorithms (except RSA).
        fn parse_pkey<const N: usize>(
            mut data: &str,
        ) -> Result<SecretBox<[u8; N]>, BindFormatError> {
            // Look for the 'PrivateKey' field.
            while let Some((key, val, rest)) = parse_bind_entry(data)? {
                data = rest;

                if key != "PrivateKey" {
                    continue;
                }

                // TODO: Evaluate security of 'base64::decode()'.
                let val: Vec<u8> = base64::decode(val)
                    .map_err(|_| BindFormatError::Misformatted)?;
                let val: Box<[u8]> = val.into_boxed_slice();
                let val: Box<[u8; N]> = val
                    .try_into()
                    .map_err(|_| BindFormatError::Misformatted)?;

                return Ok(val.into());
            }

            // The 'PrivateKey' field was not found.
            Err(BindFormatError::Misformatted)
        }

        // The first line should specify the key format.
        let (_, _, data) = parse_bind_entry(data)?
            .filter(|&(k, v, _)| {
                k == "Private-key-format"
                    && v.strip_prefix("v1.")
                        .and_then(|minor| minor.parse::<u8>().ok())
                        .is_some_and(|minor| minor >= 2)
            })
            .ok_or(BindFormatError::UnsupportedFormat)?;

        // The second line should specify the algorithm.
        let (_, val, data) = parse_bind_entry(data)?
            .filter(|&(k, _, _)| k == "Algorithm")
            .ok_or(BindFormatError::Misformatted)?;

        // Parse the algorithm.
        let mut words = val.split_whitespace();
        let code = words
            .next()
            .and_then(|code| code.parse::<u8>().ok())
            .ok_or(BindFormatError::Misformatted)?;
        let name = words.next().ok_or(BindFormatError::Misformatted)?;
        if words.next().is_some() {
            return Err(BindFormatError::Misformatted);
        }

        match (code, name) {
            (8, "(RSASHA256)") => {
                RsaSecretKeyBytes::parse_from_bind(data).map(Self::RsaSha256)
            }
            (13, "(ECDSAP256SHA256)") => {
                parse_pkey(data).map(Self::EcdsaP256Sha256)
            }
            (14, "(ECDSAP384SHA384)") => {
                parse_pkey(data).map(Self::EcdsaP384Sha384)
            }
            (15, "(ED25519)") => parse_pkey(data).map(Self::Ed25519),
            (16, "(ED448)") => parse_pkey(data).map(Self::Ed448),
            _ => Err(BindFormatError::UnsupportedAlgorithm),
        }
    }
}

//----------- Helpers for parsing the BIND format ----------------------------

/// Extract the next key-value pair in a BIND-format private key file.
pub(crate) fn parse_bind_entry(
    data: &str,
) -> Result<Option<(&str, &str, &str)>, BindFormatError> {
    // TODO: Use 'trim_ascii_start()' etc. once they pass the MSRV.

    // Trim any pending newlines.
    let data = data.trim_start();

    // Stop if there's no more data.
    if data.is_empty() {
        return Ok(None);
    }

    // Get the first line (NOTE: CR LF is handled later).
    let (line, rest) = data.split_once('\n').unwrap_or((data, ""));

    // Split the line by a colon.
    let (key, val) =
        line.split_once(':').ok_or(BindFormatError::Misformatted)?;

    // Trim the key and value (incl. for CR LFs).
    Ok(Some((key.trim(), val.trim(), rest)))
}

//----------- RsaSecretKeyBytes ----------------------------------------------

/// An RSA secret key expressed as raw bytes.
///
/// All fields here are arbitrary-precision integers in big-endian format.
/// The public values, `n` and `e`, must not have leading zeros; the remaining
/// values may be padded with leading zeros.
#[derive(Debug)]
pub struct RsaSecretKeyBytes {
    /// The public modulus.
    pub n: Box<[u8]>,

    /// The public exponent.
    pub e: Box<[u8]>,

    /// The private exponent.
    pub d: SecretBox<[u8]>,

    /// The first prime factor of `d`.
    pub p: SecretBox<[u8]>,

    /// The second prime factor of `d`.
    pub q: SecretBox<[u8]>,

    /// The exponent corresponding to the first prime factor of `d`.
    pub d_p: SecretBox<[u8]>,

    /// The exponent corresponding to the second prime factor of `d`.
    pub d_q: SecretBox<[u8]>,

    /// The inverse of the second prime factor modulo the first.
    pub q_i: SecretBox<[u8]>,
}

//--- Conversion to and from the BIND format

impl RsaSecretKeyBytes {
    /// Serialize this secret key in the conventional format used by BIND.
    ///
    /// The key is formatted in the private key v1.2 format and written to the
    /// given formatter.  Note that the header and algorithm lines are not
    /// written.  See the type-level documentation of [`SecretKeyBytes`] for a
    /// description of this format.
    pub fn format_as_bind(&self, mut w: impl fmt::Write) -> fmt::Result {
        w.write_str("Modulus: ")?;
        writeln!(w, "{}", base64::encode_display(&self.n))?;
        w.write_str("PublicExponent: ")?;
        writeln!(w, "{}", base64::encode_display(&self.e))?;
        w.write_str("PrivateExponent: ")?;
        writeln!(w, "{}", base64::encode_display(&self.d.expose_secret()))?;
        w.write_str("Prime1: ")?;
        writeln!(w, "{}", base64::encode_display(&self.p.expose_secret()))?;
        w.write_str("Prime2: ")?;
        writeln!(w, "{}", base64::encode_display(&self.q.expose_secret()))?;
        w.write_str("Exponent1: ")?;
        writeln!(w, "{}", base64::encode_display(&self.d_p.expose_secret()))?;
        w.write_str("Exponent2: ")?;
        writeln!(w, "{}", base64::encode_display(&self.d_q.expose_secret()))?;
        w.write_str("Coefficient: ")?;
        writeln!(w, "{}", base64::encode_display(&self.q_i.expose_secret()))?;
        Ok(())
    }

    /// Display this secret key in the conventional format used by BIND.
    ///
    /// This is a simple wrapper around [`Self::format_as_bind()`].
    pub fn display_as_bind(&self) -> impl fmt::Display + '_ {
        /// Display type to return from this function.
        struct Display<'a>(&'a RsaSecretKeyBytes);
        impl fmt::Display for Display<'_> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.format_as_bind(f)
            }
        }
        Display(self)
    }

    /// Parse a secret key from the conventional format used by BIND.
    ///
    /// This parser supports the private key v1.2 format, but it should be
    /// compatible with any future v1.x key.  Note that the header and
    /// algorithm lines are ignored.  See the type-level documentation of
    /// [`SecretKeyBytes`] for a description of this format.
    pub fn parse_from_bind(mut data: &str) -> Result<Self, BindFormatError> {
        let mut n = None;
        let mut e = None;
        let mut d = None;
        let mut p = None;
        let mut q = None;
        let mut d_p = None;
        let mut d_q = None;
        let mut q_i = None;

        while let Some((key, val, rest)) = parse_bind_entry(data)? {
            let field = match key {
                "Modulus" => &mut n,
                "PublicExponent" => &mut e,
                "PrivateExponent" => &mut d,
                "Prime1" => &mut p,
                "Prime2" => &mut q,
                "Exponent1" => &mut d_p,
                "Exponent2" => &mut d_q,
                "Coefficient" => &mut q_i,
                _ => {
                    data = rest;
                    continue;
                }
            };

            if field.is_some() {
                // This field has already been filled.
                return Err(BindFormatError::Misformatted);
            }

            let buffer: Vec<u8> = base64::decode(val)
                .map_err(|_| BindFormatError::Misformatted)?;

            *field = Some(buffer.into_boxed_slice());
            data = rest;
        }

        for field in [&n, &e, &d, &p, &q, &d_p, &d_q, &q_i] {
            if field.is_none() {
                // A field was missing.
                return Err(BindFormatError::Misformatted);
            }
        }

        Ok(Self {
            n: n.unwrap(),
            e: e.unwrap(),
            d: d.unwrap().into(),
            p: p.unwrap().into(),
            q: q.unwrap().into(),
            d_p: d_p.unwrap().into(),
            d_q: d_q.unwrap().into(),
            q_i: q_i.unwrap().into(),
        })
    }
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

//----------- SignError ------------------------------------------------------

/// A signature failure.
///
/// In case such an error occurs, callers should stop using the key pair they
/// attempted to sign with.  If such an error occurs with every key pair they
/// have available, or if such an error occurs with a freshly-generated key
/// pair, they should use a different cryptographic implementation.  If that
/// is not possible, they must forego signing entirely.
///
/// # Failure Cases
///
/// Signing should be an infallible process.  There are three considerable
/// failure cases for it:
///
/// - The secret key was invalid (e.g. its parameters were inconsistent).
///
///   Such a failure would mean that all future signing (with this key) will
///   also fail.  In any case, the implementations provided by this crate try
///   to verify the key (e.g. by checking the consistency of the private and
///   public components) before any signing occurs, largely ruling this class
///   of errors out.
///
/// - Not enough randomness could be obtained.  This applies to signature
///   algorithms which use randomization (e.g. RSA and ECDSA).
///
///   On the vast majority of platforms, randomness can always be obtained.
///   The [`getrandom` crate documentation][getrandom] notes:
///
///   > If an error does occur, then it is likely that it will occur on every
///   > call to getrandom, hence after the first successful call one can be
///   > reasonably confident that no errors will occur.
///
///   [getrandom]: https://docs.rs/getrandom
///
///   Thus, in case such a failure occurs, all future signing will probably
///   also fail.
///
/// - Not enough memory could be allocated.
///
///   Signature algorithms have a small memory overhead, so an out-of-memory
///   condition means that the program is nearly out of allocatable space.
///
///   Callers who do not expect allocations to fail (i.e. who are using the
///   standard memory allocation routines, not their `try_` variants) will
///   likely panic shortly after such an error.
///
///   Callers who are aware of their memory usage will likely restrict it far
///   before they get to this point.  Systems running at near-maximum load
///   tend to quickly become unresponsive and staggeringly slow.  If memory
///   usage is an important consideration, programs will likely cap it before
///   the system reaches e.g. 90% memory use.
///
///   As such, memory allocation failure should never really occur.  It is far
///   more likely that one of the other errors has occurred.
///
/// It may be reasonable to panic in any such situation, since each kind of
/// error is essentially unrecoverable.  However, applications where signing
/// is an optional step, or where crashing is prohibited, may wish to recover
/// from such an error differently (e.g. by foregoing signatures or informing
/// an operator).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SignError;

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("could not create a cryptographic signature")
    }
}

impl std::error::Error for SignError {}

//----------- BindFormatError ------------------------------------------------

/// An error in loading a [`SecretKeyBytes`] from the conventional DNS format.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum BindFormatError {
    /// The key file uses an unsupported version of the format.
    UnsupportedFormat,

    /// The key file did not follow the DNS format correctly.
    Misformatted,

    /// The key file used an unsupported algorithm.
    UnsupportedAlgorithm,
}

//--- Display

impl fmt::Display for BindFormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnsupportedFormat => "unsupported format",
            Self::Misformatted => "misformatted key file",
            Self::UnsupportedAlgorithm => "unsupported algorithm",
        })
    }
}

//--- Error

impl std::error::Error for BindFormatError {}

//============ Tests =========================================================

#[cfg(test)]
mod tests {
    use std::string::ToString;
    use std::vec::Vec;

    use crate::base::iana::SecurityAlgorithm;
    use crate::crypto::sign::SecretKeyBytes;

    const KEYS: &[(SecurityAlgorithm, u16)] = &[
        (SecurityAlgorithm::RSASHA256, 60616),
        (SecurityAlgorithm::ECDSAP256SHA256, 42253),
        (SecurityAlgorithm::ECDSAP384SHA384, 33566),
        (SecurityAlgorithm::ED25519, 56037),
        (SecurityAlgorithm::ED448, 7379),
    ];

    #[test]
    fn secret_from_dns() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);
            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = SecretKeyBytes::parse_from_bind(&data).unwrap();
            assert_eq!(key.algorithm(), algorithm);
        }
    }

    #[test]
    fn secret_roundtrip() {
        for &(algorithm, key_tag) in KEYS {
            let name =
                format!("test.+{:03}+{:05}", algorithm.to_int(), key_tag);
            let path = format!("test-data/dnssec-keys/K{}.private", name);
            let data = std::fs::read_to_string(path).unwrap();
            let key = SecretKeyBytes::parse_from_bind(&data).unwrap();
            let same = key.display_as_bind().to_string();
            let data = data.lines().collect::<Vec<_>>();
            let same = same.lines().collect::<Vec<_>>();
            assert_eq!(data, same);
        }
    }
}
