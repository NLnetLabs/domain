//! Cryptographic backends, key generation and import.
//!
//! This module is enabled by the `unstable-crypto` or `unstable-crypto-sign`
//! feature flags. The `unstable-crypto` enables all features except for
//! private key operations such as generation and signing. All features of
//! this module are enabled with the `unstable-crypto-sign` feature flag.
//!
//! This crate supports OpenSSL and Ring for performing cryptography.  These
//! cryptographic backends are gated on the `openssl` and `ring` features,
//! respectively.  They offer mostly equivalent functionality, but OpenSSL
//! supports a larger set of signing algorithms (and, for RSA keys, supports
//! weaker key sizes).  A
#![cfg_attr(feature = "unstable-crypto-sign", doc = "[`sign`]")]
#![cfg_attr(not(feature = "unstable-crypto-sign"), doc = "`sign`")]
//! backend is provided for users that wish
//! to use either or both backends at runtime.
//!
//! Each backend module (
#![cfg_attr(
    all(feature = "unstable-crypto-sign", feature = "openssl"),
    doc = "[`openssl::sign`]"
)]
#![cfg_attr(
    not(all(feature = "unstable-crypto-sign", feature = "openssl")),
    doc = "`openssl::sign`"
)]
//! ,
#![cfg_attr(
    all(feature = "unstable-crypto-sign", feature = "ring"),
    doc = "[`ring::sign`]"
)]
#![cfg_attr(
    not(all(feature = "unstable-crypto-sign", feature = "ring")),
    doc = "`ring::sign`"
)]
//! , and
#![cfg_attr(feature = "unstable-crypto-sign", doc = "[`sign`]")]
#![cfg_attr(not(feature = "unstable-crypto-sign"), doc = "`sign`")]
//! )
//! exposes a
//! `KeyPair` type, representing a cryptographic key that can be used for
//! signing, and a `generate()` function for creating new keys.
//!
//! Users can choose to bring their own cryptography by providing their own
//! `KeyPair` type that implements the
#![cfg_attr(feature = "unstable-crypto-sign", doc = "[`sign::SignRaw`]")]
#![cfg_attr(not(feature = "unstable-crypto-sign"), doc = "`sign::SignRaw`")]
//! trait.
//!
//! While each cryptographic backend can support a limited number of signature
//! algorithms, even the types independent of a cryptographic backend (e.g.
#![cfg_attr(
    feature = "unstable-crypto-sign",
    doc = "[`sign::SecretKeyBytes`]"
)]
#![cfg_attr(
    not(feature = "unstable-crypto-sign"),
    doc = "`sign::SecretKeyBytes`"
)]
//! and
#![cfg_attr(
    feature = "unstable-crypto-sign",
    doc = "[`sign::GenerateParams`]"
)]
#![cfg_attr(
    not(feature = "unstable-crypto-sign"),
    doc = "`sign::GenerateParams`"
)]
//! ) support a limited
//! number of algorithms.  Even with custom cryptographic backends,
//! this module can only
//! support these algorithms.
//!
//! In addition to private key operations, this module provides the
#![cfg_attr(
    any(feature = "ring", feature = "openssl"),
    doc = "[`common::PublicKey`]"
)]
#![cfg_attr(
    not(any(feature = "ring", feature = "openssl")),
    doc = "`common::PublicKey`"
)]
//! type for signature verification.
//!
//! The module also support computing message digests using the
#![cfg_attr(
    any(feature = "ring", feature = "openssl"),
    doc = "[`common::DigestBuilder`]"
)]
#![cfg_attr(
    not(any(feature = "ring", feature = "openssl")),
    doc = "`common::DigestBuilder`"
)]
//! type.
//!
//! # Message digests
//!
//! Given some data compute a message digest.
//!
//! ```
//! use domain::crypto::common::{DigestBuilder, DigestType};
//!
//! let input = "Hello World!";
//! let mut ctx = DigestBuilder::new(DigestType::Sha256);
//! ctx.update(input.as_bytes());
//! ctx.finish().as_ref();
//! ```
//!
//! # Signature verification
//!
//! Given some data, a signature, and a DNSKEY, the signature can be verified.
//!
//! ```norun
//! use domain::rdata::Dnskey;
//! use domain::crypto::common::PublicKey;
//! use domain::base::iana::SecAlg;
//!
//! let keyraw = [0u8; 16];
//! let input = "Hello World!";
//! let bad_sig = [0u8; 16];
//! let dnskey = Dnskey::new(256, 3, SecAlg::ED25519, keyraw).unwrap();
//! let public_key = PublicKey::from_dnskey(&dnskey).unwrap();
//! let res = public_key.verify(input.as_bytes(), &bad_sig);
//! println!("verify result: {res:?}");
//! ```

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

pub mod common;
pub mod openssl;
pub mod ring;
pub mod sign;
