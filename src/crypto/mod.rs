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
//! # use domain::crypto::misc;
//! # use domain::crypto::common::KeyPair;
//! # use domain::dnssec::sign::keys::{SecretKeyBytes, SigningKey};
//! // Load an Ed25519 key named 'Ktest.+015+56037'.
//! let base = "test-data/dnssec-keys/Ktest.+015+56037";
//! let sec_text = std::fs::read_to_string(format!("{base}.private")).unwrap();
//! let sec_bytes = SecretKeyBytes::parse_from_bind(&sec_text).unwrap();
//! let pub_text = std::fs::read_to_string(format!("{base}.key")).unwrap();
//! let pub_key = misc::Key::<Vec<u8>>::parse_from_bind(&pub_text).unwrap();
//!
//! // Parse the key into Ring or OpenSSL.
//! let key_pair = KeyPair::from_bytes(&sec_bytes, pub_key.raw_public_key()).unwrap();
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
//! # use domain::crypto::common;
//! # use domain::crypto::common::GenerateParams;
//! # use domain::crypto::common::KeyPair;
//! # use domain::dnssec::sign::keys::SigningKey;
//! // Generate a new Ed25519 key.
//! let params = GenerateParams::Ed25519;
//! let (sec_bytes, pub_bytes) = common::generate(params).unwrap();
//!
//! // Parse the key into Ring or OpenSSL.
//! let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
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
//! # Signing data
//!
//! Given some data and a key, the data can be signed with the key.
//!
//! ```
//! # use domain::base::Name;
//! # use domain::crypto::common;
//! # use domain::crypto::common::GenerateParams;
//! # use domain::crypto::common::KeyPair;
//! # use domain::dnssec::sign::keys::SigningKey;
//! # use domain::crypto::misc::SignRaw;
//! # let (sec_bytes, pub_bytes) = common::generate(GenerateParams::Ed25519).unwrap();
//! # let key_pair = KeyPair::from_bytes(&sec_bytes, &pub_bytes).unwrap();
//! # let key = SigningKey::new(Name::<Vec<u8>>::root(), 257, key_pair);
//! // Sign arbitrary byte sequences with the key.
//! let sig = key.raw_secret_key().sign_raw(b"Hello, World!").unwrap();
//! println!("{:?}", sig);
//! ```
//!
//! [`SignRaw`]: crate::sign::traits::SignRaw
//! [`GenerateParams`]: crate::sign::crypto::common::GenerateParams
//! [`SecretKeyBytes`]: crate::sign::keys::SecretKeyBytes
pub mod common;
pub mod misc;
pub mod openssl;
pub mod ring;
pub mod validate;
