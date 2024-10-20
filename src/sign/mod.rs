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
    base::{iana::SecAlg, Name},
    validate::{self, RawPublicKey, Signature},
};

pub mod generic;
pub mod openssl;
pub mod ring;

//----------- SigningKey -----------------------------------------------------

/// A signing key.
///
/// This associates important metadata with a raw cryptographic secret key.
pub struct SigningKey<Octs, Inner> {
    /// The owner of the key.
    owner: Name<Octs>,

    /// The flags associated with the key.
    ///
    /// These flags are stored in the DNSKEY record.
    flags: u16,

    /// The raw private key.
    inner: Inner,
}

//--- Construction

impl<Octs, Inner> SigningKey<Octs, Inner> {
    /// Construct a new signing key manually.
    pub fn new(owner: Name<Octs>, flags: u16, inner: Inner) -> Self {
        Self {
            owner,
            flags,
            inner,
        }
    }
}

//--- Inspection

impl<Octs, Inner> SigningKey<Octs, Inner> {
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
    pub fn algorithm(&self) -> SecAlg
    where
        Inner: SignRaw,
    {
        self.inner.algorithm()
    }

    /// The associated public key.
    pub fn public_key(&self) -> validate::Key<&Octs>
    where
        Octs: AsRef<[u8]>,
        Inner: SignRaw,
    {
        let owner = Name::from_octets(self.owner.as_octets()).unwrap();
        validate::Key::new(owner, self.flags, self.inner.raw_public_key())
    }

    /// The associated raw public key.
    pub fn raw_public_key(&self) -> RawPublicKey
    where
        Inner: SignRaw,
    {
        self.inner.raw_public_key()
    }
}

// TODO: Conversion to and from key files

//----------- SignRaw --------------------------------------------------------

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
