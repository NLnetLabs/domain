//! Cryptographic backends, key generation and import.
//!
//! This crate supports OpenSSL and Ring for performing cryptography.  These
//! cryptographic backends are gated on the `openssl` and `ring` features,
//! respectively.  They offer mostly equivalent functionality, but OpenSSL
//! supports a larger set of signing algorithms (and, for RSA keys, supports
//! weaker key sizes).  A [`common`] backend is provided for users that wish
//! to use either or both backends at runtime.
//!
//! Each backend module ([`openssl`], [`ring`], and [`common`]) exposes a
//! `KeyPair` type, representing a cryptographic key that can be used for
//! signing, and a `generate()` function for creating new keys.
//!
//! Users can choose to bring their own cryptography by providing their own
//! `KeyPair` type that implements the [`SignRaw`] trait.
//!
//! While each cryptographic backend can support a limited number of signature
//! algorithms, even the types independent of a cryptographic backend (e.g.
//! [`SecretKeyBytes`] and [`GenerateParams`]) support a limited number of
//! algorithms.  Even with custom cryptographic backends, this module can only
//! support these algorithms.
//!
//! # Importing keys
//!
//! Keys can be imported from files stored on disk in the conventional BIND
//! format.
//!
//! ```
//! # use domain::base::iana::SecAlg;
//! # use domain::crypto::misc::{self, SecretKeyBytes};
//! # use domain::crypto::common::sign::KeyPair;
//! # use domain::dnssec::common::parse_from_bind;
//! # use domain::crypto::misc::SignRaw;
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
//! assert_eq!(key_pair.algorithm(), SecAlg::ED25519);
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
//! # use domain::crypto::common::GenerateParams;
//! # use domain::crypto::common::sign::KeyPair;
//! // Generate a new Ed25519 key.
//! let params = GenerateParams::Ed25519;
//! let (sec_bytes, pub_key) = common::sign::generate(params, 257).unwrap();
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
//! # use domain::crypto::common::GenerateParams;
//! # use domain::crypto::common::sign::KeyPair;
//! # use domain::crypto::misc::SignRaw;
//! # let (sec_bytes, pub_bytes) = common::sign::generate(
//!        GenerateParams::Ed25519,
//!        256).unwrap();
//! # let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//! // Sign arbitrary byte sequences with the key.
//! let sig = key_pair.sign_raw(b"Hello, World!").unwrap();
//! println!("{:?}", sig);
//! ```
//!
//! [`SignRaw`]: crate::sign::traits::SignRaw
//! [`GenerateParams`]: crate::sign::crypto::common::GenerateParams
//! [`SecretKeyBytes`]: crate::sign::keys::SecretKeyBytes

// misc requires unstable-crypto-sign.
#[cfg(feature = "unstable-crypto-sign")]
pub mod misc;

// common requires either ring or openssl.
#[cfg(any(feature = "ring", feature = "openssl"))]
pub mod common;

pub mod openssl;
pub mod ring;
