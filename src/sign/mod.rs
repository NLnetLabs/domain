//! DNSSEC signing.
//!
//! **This module is experimental and likely to change significantly.**
//!
//! This module provides support for DNSSEC signing of zones.
//!
//! DNSSEC signed zones consist of configuration data such as DNSKEY and
//! NSEC3PARAM records, NSEC(3) chains used to provably deny the existence of
//! records, and signatures that authenticate the authoritative content of the
//! zone.
//!
//! # Overview
//!
//! This module provides support for working with DNSSEC signing keys and
//! using them to DNSSEC sign sorted [`Record`] collections via the traits
//! [`SignableZone`], [`SignableZoneInPlace`] and [`Signable`].
//!
//! <div class="warning">
//!
//! This module does **NOT** yet support signing of records stored in a
//! [`Zone`].
//!
//! </div>
//!
//! Signatures can be generated using a [`SigningKey`], which combines
//! cryptographic key material with additional information that defines how
//! the key should be used.  [`SigningKey`] relies on a cryptographic backend
//! to provide the underlying signing operation (e.g.
//! [`keys::keypair::KeyPair`]).
//!
//! While all records in a zone can be signed with a single key, it is useful
//! to use one key, a Key Signing Key (KSK), "to sign the apex DNSKEY RRset in
//! a zone" and another key, a Zone Signing Key (ZSK), "to sign all the RRsets
//! in a zone that require signatures, other than the apex DNSKEY RRset" (see
//! [RFC 6781 section 3.1]).
//!
//! Cryptographically there is no difference between these key types, they are
//! assigned by the operator to signal their intended usage. This module
//! provides the [`DnssecSigningKey`] wrapper type around a [`SigningKey`] to
//! allow the intended usage of the key to be signalled by the operator, and
//! [`SigningKeyUsageStrategy`] to allow different key usage strategies to be
//! defined and selected to influence how the different types of key affect
//! signing.
//!
//! # Importing keys
//!
//! Keys can be imported from files stored on disk in the conventional BIND
//! format.
//!
//! ```
//! # use domain::base::iana::SecAlg;
//! # use domain::{sign::*, validate};
//! // Load an Ed25519 key named 'Ktest.+015+56037'.
//! let base = "test-data/dnssec-keys/Ktest.+015+56037";
//! let sec_text = std::fs::read_to_string(format!("{base}.private")).unwrap();
//! let sec_bytes = SecretKeyBytes::parse_from_bind(&sec_text).unwrap();
//! let pub_text = std::fs::read_to_string(format!("{base}.key")).unwrap();
//! let pub_key = validate::Key::<Vec<u8>>::parse_from_bind(&pub_text).unwrap();
//!
//! // Parse the key into Ring or OpenSSL.
//! let key_pair = keys::keypair::KeyPair::from_bytes(&sec_bytes, pub_key.raw_public_key()).unwrap();
//!
//! // Associate the key with important metadata.
//! let key = SigningKey::new(pub_key.owner().clone(), pub_key.flags(), key_pair);
//!
//! // Check that the owner, algorithm, and key tag matched expectations.
//! assert_eq!(key.owner().to_string(), "test");
//! assert_eq!(key.algorithm(), SecAlg::ED25519);
//! assert_eq!(key.public_key().key_tag(), 56037);
//! ```
//!
//! # Generating keys
//!
//! Keys can also be generated.
//!
//! ```
//! # use domain::base::Name;
//! # use domain::sign::*;
//! // Generate a new Ed25519 key.
//! let params = GenerateParams::Ed25519;
//! let (sec_bytes, pub_bytes) = keys::keypair::generate(params).unwrap();
//!
//! // Parse the key into Ring or OpenSSL.
//! let key_pair = keys::keypair::KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//!
//! // Associate the key with important metadata.
//! let owner: Name<Vec<u8>> = "www.example.org.".parse().unwrap();
//! let flags = 257; // key signing key
//! let key = SigningKey::new(owner, flags, key_pair);
//!
//! // Access the public key (with metadata).
//! let pub_key = key.public_key();
//! println!("{:?}", pub_key);
//! ```
//!
//! # Low level signing
//!
//! Given some data and a key, the data can be signed with the key.
//!
//! ```
//! # use domain::base::Name;
//! # use domain::sign::*;
//! # let (sec_bytes, pub_bytes) = keys::keypair::generate(GenerateParams::Ed25519).unwrap();
//! # let key_pair = keys::keypair::KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//! # let key = SigningKey::new(Name::<Vec<u8>>::root(), 257, key_pair);
//! // Sign arbitrary byte sequences with the key.
//! let sig = key.raw_secret_key().sign_raw(b"Hello, World!").unwrap();
//! println!("{:?}", sig);
//! ```
//!
//! # High level signing
//!
//! Given a type for which [`SignableZone`] or [`SignableZoneInPlace`] is
//! implemented, invoke `sign_zone()` on the type.
//!
//! <div class="warning">
//!
//! Currently there is no support for re-signing a zone, i.e. ensuring
//! that any changes to the authoritative records in the zone are reflected
//! by updating the NSEC(3) chain and generating additional signatures or
//! regenerating existing ones that have expired.
//!
//! </div>
//!
//! ```
//! # use domain::base::{*, iana::Class};
//! # use domain::sign::*;
//! # let (sec_bytes, pub_bytes) = keys::keypair::generate(GenerateParams::Ed25519).unwrap();
//! # let key_pair = keys::keypair::KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//! # let root = Name::<Vec<u8>>::root();
//! # let key = SigningKey::new(root.clone(), 257, key_pair);
//! use domain::rdata::{rfc1035::Soa, ZoneRecordData};
//! use domain::rdata::dnssec::Timestamp;
//! use domain::sign::keys::keymeta::{DnssecSigningKey, DesignatedSigningKey};
//! use domain::sign::records::{DefaultSorter, SortedRecords};
//! use domain::sign::signing::config::SigningConfig;
//! use domain::sign::signing::traits::SignableZoneInPlace;
//!
//! // Create a sorted collection of records.
//! let mut records = SortedRecords::default();
//!
//! // Insert records into the collection. Just a dummy SOA for this example.
//! let soa = Soa::new(
//!     root.clone(),
//!     root.clone(),
//!     Serial::now(),
//!     Ttl::ZERO,
//!     Ttl::ZERO,
//!     Ttl::ZERO,
//!     Ttl::ZERO);
//! records.insert(Record::new(root, Class::IN, Ttl::ZERO, ZoneRecordData::Soa(soa)));
//!
//! // Generate or import signing keys (see above).
//!
//! // Assign signature validity period and operator intent to the keys.
//! let key = key.with_validity(Timestamp::now(), Timestamp::now());
//! let dnssec_signing_key = DnssecSigningKey::new_csk(key);
//! let keys = [&dnssec_signing_key as &dyn DesignatedSigningKey<_, _>];
//!
//! // Create a signing configuration.
//! let mut signing_config = SigningConfig::default();
//!
//! // Then sign the zone in place.
//! records.sign_zone(&mut signing_config, &keys).unwrap();
//! ```
//!
//! If needed, individual RRsets can also be signed:``
//!
//! ```
//! # use domain::base::Name;
//! # use domain::base::iana::Class;
//! # use domain::sign::*;
//! # use domain::sign::keys::keymeta::{DesignatedSigningKey, DnssecSigningKey};
//! # let (sec_bytes, pub_bytes) = keys::keypair::generate(GenerateParams::Ed25519).unwrap();
//! # let key_pair = keys::keypair::KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//! # let root = Name::<Vec<u8>>::root();
//! # let key = SigningKey::new(root, 257, key_pair);
//! # let dnssec_signing_key = DnssecSigningKey::new_csk(key);
//! # let keys = [&dnssec_signing_key as &dyn DesignatedSigningKey<_, _>];
//! # let mut records = records::SortedRecords::<_, _, domain::sign::records::DefaultSorter>::new();
//! use domain::sign::signing::traits::Signable;
//! use domain::sign::signing::strategy::DefaultSigningKeyUsageStrategy as KeyStrat;
//! let apex = records::FamilyName::new(Name::<Vec<u8>>::root(), Class::IN);
//! let rrset = records::Rrset::new(&records);
//! let generated_records = rrset.sign::<KeyStrat>(&apex, &keys).unwrap();
//! ```
//!
//! [`DnssecSigningKey`]: crate::sign::keys::keymeta::DnssecSigningKey
//! [`Record`]: crate::base::record::Record
//! [RFC 6871 section 3.1]: https://rfc-editor.org/rfc/rfc6781#section-3.1
//! [`SigningKeyUsageStrategy`]:
//!     crate::sign::signing::strategy::SigningKeyUsageStrategy
//! [`Signable`]: crate::sign::signing::traits::Signable
//! [`SignableZone`]: crate::sign::signing::traits::SignableZone
//! [`SignableZoneInPlace`]: crate::sign::signing::traits::SignableZoneInPlace
//! [`SortedRecords`]: crate::sign::SortedRecords
//! [`Zone`]: crate::zonetree::Zone
//!
//! # Cryptography
//!
//! This crate supports OpenSSL and Ring for performing cryptography.  These
//! cryptographic backends are gated on the `openssl` and `ring` features,
//! respectively.  They offer mostly equivalent functionality, but OpenSSL
//! supports a larger set of signing algorithms (and, for RSA keys, supports
//! weaker key sizes).  A [`common`] backend is provided for users that wish
//! to use either or both backends at runtime.
//!
//! Each backend module (`openssl`, `ring`, and `common`) exposes a `KeyPair`
//! type, representing a cryptographic key that can be used for signing, and a
//! `generate()` function for creating new keys.
//!
//! Users can choose to bring their own cryptography by providing their own
//! `KeyPair` type that implements [`SignRaw`].  Note that `async` signing
//! (useful for interacting with cryptographic hardware like HSMs) is not
//! currently supported.
//!
//! While each cryptographic backend can support a limited number of signature
//! algorithms, even the types independent of a cryptographic backend (e.g.
//! [`SecretKeyBytes`] and [`GenerateParams`]) support a limited number of
//! algorithms.  Even with custom cryptographic backends, this module can only
//! support these algorithms.
//!
//! # Importing and Exporting
//!
//! The [`SecretKeyBytes`] type is a generic representation of a secret key as
//! a byte slice.  While it does not offer any cryptographic functionality, it
//! is useful to transfer secret keys stored in memory, independent of any
//! cryptographic backend.
//!
//! The `KeyPair` types of the cryptographic backends in this module each
//! support a `from_bytes()` function that parses the generic representation
//! into a functional cryptographic key.  Importantly, these functions require
//! both the public and private keys to be provided -- the pair are verified
//! for consistency.  In some cases, it may also be possible to serialize an
//! existing cryptographic key back to the generic bytes representation.
//!
//! [`SecretKeyBytes`] also supports importing and exporting keys from and to
//! the conventional private-key format popularized by BIND.  This format is
//! used by a variety of tools for storing DNSSEC keys on disk.  See the
//! type-level documentation for a specification of the format.
//!
//! # Key Sets and Key Lifetime
//! The [`keyset`] module provides a way to keep track of the collection of
//! keys that are used to sign a particular zone. In addition, the lifetime of
//! keys can be maintained using key rolls that phase out old keys and
//! introduce new keys.

#![cfg(feature = "unstable-sign")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-sign")))]

use core::fmt;
use core::ops::RangeInclusive;

use crate::base::{iana::SecAlg, Name};
use crate::rdata::dnssec::Timestamp;
use crate::validate::Key;

pub use crate::validate::{PublicKeyBytes, RsaPublicKeyBytes, Signature};

pub mod crypto;
pub mod error;
pub mod hashing;
pub mod keys;
pub mod records;
pub mod signing;
pub mod zone;

pub use keys::bytes::{RsaSecretKeyBytes, SecretKeyBytes};

//----------- SigningKey -----------------------------------------------------

/// A signing key.
///
/// This associates important metadata with a raw cryptographic secret key.
pub struct SigningKey<Octs, Inner: SignRaw> {
    /// The owner of the key.
    owner: Name<Octs>,

    /// The flags associated with the key.
    ///
    /// These flags are stored in the DNSKEY record.
    flags: u16,

    /// The raw private key.
    inner: Inner,

    /// The validity period to assign to any DNSSEC signatures created using
    /// this key.
    ///
    /// The range spans from the inception timestamp up to and including the
    /// expiration timestamp.
    signature_validity_period: Option<RangeInclusive<Timestamp>>,
}

//--- Construction

impl<Octs, Inner: SignRaw> SigningKey<Octs, Inner> {
    /// Construct a new signing key manually.
    pub fn new(owner: Name<Octs>, flags: u16, inner: Inner) -> Self {
        Self {
            owner,
            flags,
            inner,
            signature_validity_period: None,
        }
    }

    pub fn with_validity(
        mut self,
        inception: Timestamp,
        expiration: Timestamp,
    ) -> Self {
        self.signature_validity_period =
            Some(RangeInclusive::new(inception, expiration));
        self
    }

    pub fn signature_validity_period(
        &self,
    ) -> Option<RangeInclusive<Timestamp>> {
        self.signature_validity_period.clone()
    }
}

//--- Inspection

impl<Octs, Inner: SignRaw> SigningKey<Octs, Inner> {
    /// The owner name attached to the key.
    pub fn owner(&self) -> &Name<Octs> {
        &self.owner
    }

    /// The flags attached to the key.
    pub fn flags(&self) -> u16 {
        self.flags
    }

    /// The raw secret key.
    pub fn raw_secret_key(&self) -> &Inner {
        &self.inner
    }

    /// Whether this is a zone signing key.
    ///
    /// From [RFC 4034, section 2.1.1]:
    ///
    /// > Bit 7 of the Flags field is the Zone Key flag.  If bit 7 has value
    /// > 1, then the DNSKEY record holds a DNS zone key, and the DNSKEY RR's
    /// > owner name MUST be the name of a zone.  If bit 7 has value 0, then
    /// > the DNSKEY record holds some other type of DNS public key and MUST
    /// > NOT be used to verify RRSIGs that cover RRsets.
    ///
    /// [RFC 4034, section 2.1.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1
    pub fn is_zone_signing_key(&self) -> bool {
        self.flags & (1 << 8) != 0
    }

    /// Whether this key has been revoked.
    ///
    /// From [RFC 5011, section 3]:
    ///
    /// > Bit 8 of the DNSKEY Flags field is designated as the 'REVOKE' flag.
    /// > If this bit is set to '1', AND the resolver sees an RRSIG(DNSKEY)
    /// > signed by the associated key, then the resolver MUST consider this
    /// > key permanently invalid for all purposes except for validating the
    /// > revocation.
    ///
    /// [RFC 5011, section 3]: https://datatracker.ietf.org/doc/html/rfc5011#section-3
    pub fn is_revoked(&self) -> bool {
        self.flags & (1 << 7) != 0
    }

    /// Whether this is a secure entry point.
    ///
    /// From [RFC 4034, section 2.1.1]:
    ///
    /// > Bit 15 of the Flags field is the Secure Entry Point flag, described
    /// > in [RFC3757].  If bit 15 has value 1, then the DNSKEY record holds a
    /// > key intended for use as a secure entry point.  This flag is only
    /// > intended to be a hint to zone signing or debugging software as to
    /// > the intended use of this DNSKEY record; validators MUST NOT alter
    /// > their behavior during the signature validation process in any way
    /// > based on the setting of this bit.  This also means that a DNSKEY RR
    /// > with the SEP bit set would also need the Zone Key flag set in order
    /// > to be able to generate signatures legally.  A DNSKEY RR with the SEP
    /// > set and the Zone Key flag not set MUST NOT be used to verify RRSIGs
    /// > that cover RRsets.
    ///
    /// [RFC 4034, section 2.1.1]: https://datatracker.ietf.org/doc/html/rfc4034#section-2.1.1
    /// [RFC3757]: https://datatracker.ietf.org/doc/html/rfc3757
    pub fn is_secure_entry_point(&self) -> bool {
        self.flags & 1 != 0
    }

    /// The signing algorithm used.
    pub fn algorithm(&self) -> SecAlg {
        self.inner.algorithm()
    }

    /// The associated public key.
    pub fn public_key(&self) -> Key<&Octs>
    where
        Octs: AsRef<[u8]>,
    {
        let owner = Name::from_octets(self.owner.as_octets()).unwrap();
        Key::new(owner, self.flags, self.inner.raw_public_key())
    }

    /// The associated raw public key.
    pub fn raw_public_key(&self) -> PublicKeyBytes {
        self.inner.raw_public_key()
    }
}

// TODO: Conversion to and from key files

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

//============ Error Types ===================================================

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
#[derive(Clone, Debug)]
pub struct SignError;

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("could not create a cryptographic signature")
    }
}

impl std::error::Error for SignError {}
