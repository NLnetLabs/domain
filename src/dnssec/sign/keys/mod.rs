//! Types for working with DNSSEC signing keys.
//!
//! # Importing and Exporting
//!
//! The `KeyPair` types of the cryptographic backends in this module each
//! support a `from_bytes()` function that parses the generic representation
//! into a functional cryptographic key.  Importantly, these functions require
//! both the public and private keys to be provided -- the pair are verified
//! for consistency.  In some cases, it may also be possible to serialize an
//! existing cryptographic key back to the generic bytes representation.
//!
//! # Key Sets and Key Lifetime
//!
//! The [`keyset`] module provides a way to keep track of the collection of
//! keys that are used to sign a particular zone. In addition, the lifetime of
//! keys can be maintained using key rolls that phase out old keys and
//! introduce new keys.
//!
//! # Signing keys
//!
//!

pub mod keyset;
pub mod signingkey;

pub use self::signingkey::SigningKey;
