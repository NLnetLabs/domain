//! DNSSEC signing.
//!
//! **This module is experimental and likely to change significantly.**
//!
//! Signatures are at the heart of DNSSEC -- they confirm the authenticity of
//! a DNS record served by a security-aware name server.  Signatures can be
//! made "online" (in an authoritative name server while it is running) or
//! "offline" (outside of a name server).  Once generated, signatures can be
//! serialized as DNS records and stored alongside the authenticated records.

#![cfg(feature = "unstable-sign")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-sign")))]

use crate::{
    base::iana::SecAlg,
    validate::{RawPublicKey, Signature},
};

pub mod generic;
pub mod openssl;
pub mod ring;

/// Low-level signing functionality.
///
/// Types that implement this trait own a private key and can sign arbitrary
/// information (for zone signing keys, DNS records; for key signing keys,
/// subsidiary public keys).
///
/// Before a key can be used for signing, it should be validated.  If the
/// implementing type allows [`sign_raw()`] to be called on unvalidated keys,
/// it will have to check the validity of the key for every signature; this is
/// unnecessary overhead when many signatures have to be generated.
///
/// [`sign_raw()`]: SignRaw::sign_raw()
pub trait SignRaw {
    /// The signature algorithm used.
    ///
    /// The following algorithms are known to this crate.  Recommendations
    /// toward or against usage are based on published RFCs, not the crate
    /// authors' opinion.  Implementing types may choose to support some of
    /// the prohibited algorithms anyway.
    ///
    /// - [`SecAlg::RSAMD5`] (highly insecure, do not use)
    /// - [`SecAlg::DSA`] (highly insecure, do not use)
    /// - [`SecAlg::RSASHA1`] (insecure, not recommended)
    /// - [`SecAlg::DSA_NSEC3_SHA1`] (highly insecure, do not use)
    /// - [`SecAlg::RSASHA1_NSEC3_SHA1`] (insecure, not recommended)
    /// - [`SecAlg::RSASHA256`]
    /// - [`SecAlg::RSASHA512`] (not recommended)
    /// - [`SecAlg::ECC_GOST`] (do not use)
    /// - [`SecAlg::ECDSAP256SHA256`]
    /// - [`SecAlg::ECDSAP384SHA384`]
    /// - [`SecAlg::ED25519`]
    /// - [`SecAlg::ED448`]
    fn algorithm(&self) -> SecAlg;

    /// The raw public key.
    ///
    /// This can be used to verify produced signatures.  It must use the same
    /// algorithm as returned by [`algorithm()`].
    ///
    /// [`algorithm()`]: Self::algorithm()
    fn raw_public_key(&self) -> RawPublicKey;

    /// Sign the given bytes.
    ///
    /// # Errors
    ///
    /// There are three expected failure cases for this function:
    ///
    /// - The secret key was invalid.  The implementing type is responsible
    ///   for validating the secret key during initialization, so that this
    ///   kind of error does not occur.
    ///
    /// - Not enough randomness could be obtained.  This applies to signature
    ///   algorithms which use randomization (primarily ECDSA).  On common
    ///   platforms like Linux, Mac OS, and Windows, cryptographically secure
    ///   pseudo-random number generation is provided by the OS, so this is
    ///   highly unlikely.
    ///
    /// - Not enough memory could be obtained.  Signature generation does not
    ///   require significant memory and an out-of-memory condition means that
    ///   the application will probably panic soon.
    ///
    /// None of these are considered likely or recoverable, so panicking is
    /// the simplest and most ergonomic solution.
    fn sign_raw(&self, data: &[u8]) -> Signature;
}
