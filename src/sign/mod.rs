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

use core::fmt;

use crate::{
    base::{iana::SecAlg, Name},
    validate::{self, RawPublicKey, Signature},
};

pub mod common;
pub mod generic;
pub mod openssl;
pub mod records;
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
    fn raw_public_key(&self) -> RawPublicKey;

    /// Sign the given bytes.
    ///
    /// # Errors
    ///
    /// See [`SignError`] for a discussion of possible failure cases.  To the
    /// greatest extent possible, the implementation should check for failure
    /// cases beforehand and prevent them (e.g. when the keypair is created).
    fn sign_raw(&self, data: &[u8]) -> Result<Signature, SignError>;
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
