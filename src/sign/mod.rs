//! DNSSEC signing.
//!
//! **This module is experimental and likely to change significantly.**
//!
//! Signatures are at the heart of DNSSEC -- they confirm the authenticity of a
//! DNS record served by a secure-aware name server.  But name servers are not
//! usually creating those signatures themselves.  Within a DNS zone, it is the
//! zone administrator's responsibility to sign zone records (when the record's
//! time-to-live expires and/or when it changes).  Those signatures are stored
//! as regular DNS data and automatically served by name servers.

#![cfg(feature = "sign")]
#![cfg_attr(docsrs, doc(cfg(feature = "sign")))]

use crate::base::iana::SecAlg;

pub mod generic;
pub mod key;
pub mod openssl;
pub mod records;
pub mod ring;

/// Signing DNS records.
///
/// Implementors of this trait own a private key and sign DNS records for a zone
/// with that key.  Signing is a synchronous operation performed on the current
/// thread; this rules out implementations like HSMs, where I/O communication is
/// necessary.
pub trait Sign<Buffer> {
    /// An error in constructing a signature.
    type Error;

    /// The signature algorithm used.
    ///
    /// The following algorithms can be used:
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

    /// Compute a signature.
    ///
    /// A regular signature of the given byte sequence is computed and is turned
    /// into the selected buffer type.  This provides a lot of flexibility in
    /// how buffers are constructed; they may be heap-allocated or have a static
    /// size.
    fn sign(&self, data: &[u8]) -> Result<Buffer, Self::Error>;
}
