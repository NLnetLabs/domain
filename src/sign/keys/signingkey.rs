use core::ops::RangeInclusive;

use crate::base::iana::SecAlg;
use crate::base::Name;
use crate::rdata::dnssec::Timestamp;
use crate::sign::{PublicKeyBytes, SignRaw};
use crate::validate::Key;

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
