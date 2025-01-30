use core::convert::From;
use core::marker::PhantomData;
use core::ops::Deref;

use std::fmt::Display;

use crate::sign::keys::signingkey::SigningKey;
use crate::sign::SignRaw;

//------------ DesignatedSigningKey ------------------------------------------

pub trait DesignatedSigningKey<Octs, Inner>
where
    Octs: AsRef<[u8]>,
    Inner: SignRaw,
{
    /// Should this key be used to "sign one or more other authentication keys
    /// for a given zone" (RFC 4033 section 2 "Key Signing Key (KSK)").
    fn signs_keys(&self) -> bool;

    /// Should this key be used to "sign a zone" (RFC 4033 section 2 "Zone
    /// Signing Key (ZSK)").
    fn signs_zone_data(&self) -> bool;

    fn signing_key(&self) -> &SigningKey<Octs, Inner>;
}

impl<Octs, Inner, T> DesignatedSigningKey<Octs, Inner> for &T
where
    Octs: AsRef<[u8]>,
    Inner: SignRaw,
    T: DesignatedSigningKey<Octs, Inner>,
{
    fn signs_keys(&self) -> bool {
        (**self).signs_keys()
    }

    fn signs_zone_data(&self) -> bool {
        (**self).signs_zone_data()
    }

    fn signing_key(&self) -> &SigningKey<Octs, Inner> {
        (**self).signing_key()
    }
}

//------------ IntendedKeyPurpose --------------------------------------------

/// The purpose of a DNSSEC key from the perspective of an operator.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IntendedKeyPurpose {
    /// A key that signs DNSKEY RRSETs.
    ///
    /// RFC9499 DNS Terminology:
    /// 10. General DNSSEC
    /// Key signing key (KSK): DNSSEC keys that "only sign the apex DNSKEY
    ///   RRset in a zone." (Quoted from RFC6781, Section 3.1)
    KSK,

    /// A key that signs non-DNSKEY RRSETs.
    ///
    /// RFC9499 DNS Terminology:
    /// 10. General DNSSEC
    /// Zone signing key (ZSK): "DNSSEC keys that can be used to sign all the
    /// RRsets in a zone that require signatures, other than the apex DNSKEY
    /// RRset." (Quoted from RFC6781, Section 3.1) Also note that a ZSK is
    /// sometimes used to sign the apex DNSKEY RRset.
    ZSK,

    /// A key that signs both DNSKEY and other RRSETs.
    ///
    /// RFC 9499 DNS Terminology:
    /// 10. General DNSSEC
    /// Combined signing key (CSK): In cases where the differentiation between
    /// the KSK and ZSK is not made, i.e., where keys have the role of both
    /// KSK and ZSK, we talk about a Single-Type Signing Scheme." (Quoted from
    /// [RFC6781], Section 3.1) This is sometimes called a "combined signing
    /// key" or "CSK". It is operational practice, not protocol, that
    /// determines whether a particular key is a ZSK, a KSK, or a CSK.
    CSK,

    /// A key that is not currently used for signing.
    ///
    /// This key should be added to the zone but not used to sign any RRSETs.
    Inactive,
}

//--- impl Display

impl Display for IntendedKeyPurpose {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IntendedKeyPurpose::KSK => f.write_str("KSK"),
            IntendedKeyPurpose::ZSK => f.write_str("ZSK"),
            IntendedKeyPurpose::CSK => f.write_str("CSK"),
            IntendedKeyPurpose::Inactive => f.write_str("Inactive"),
        }
    }
}

//------------ DnssecSigningKey ----------------------------------------------

/// A key that can be used for DNSSEC signing.
///
/// This type carries metadata that signals to a DNSSEC signer how this key
/// should impact the zone to be signed.
pub struct DnssecSigningKey<Octs, Inner: SignRaw> {
    /// The key to use to make DNSSEC signatures.
    key: SigningKey<Octs, Inner>,

    /// The purpose for which the operator intends the key to be used.
    ///
    /// Defines explicitly the purpose of the key which should be used instead
    /// of attempting to infer the purpose of the key (to sign keys and/or to
    /// sign other records) by examining the setting of the Secure Entry Point
    /// and Zone Key flags on the key (i.e. whether the key is a KSK or ZSK or
    /// something else).
    purpose: IntendedKeyPurpose,

    _phantom: PhantomData<(Octs, Inner)>,
}

impl<Octs, Inner: SignRaw> DnssecSigningKey<Octs, Inner> {
    /// Create a new [`DnssecSigningKey`] by assocating intent with a
    /// reference to an existing key.
    pub fn new(
        key: SigningKey<Octs, Inner>,
        purpose: IntendedKeyPurpose,
    ) -> Self {
        Self {
            key,
            purpose,
            _phantom: Default::default(),
        }
    }

    pub fn new_ksk(key: SigningKey<Octs, Inner>) -> Self {
        Self {
            key,
            purpose: IntendedKeyPurpose::KSK,
            _phantom: Default::default(),
        }
    }

    pub fn new_zsk(key: SigningKey<Octs, Inner>) -> Self {
        Self {
            key,
            purpose: IntendedKeyPurpose::ZSK,
            _phantom: Default::default(),
        }
    }

    pub fn new_csk(key: SigningKey<Octs, Inner>) -> Self {
        Self {
            key,
            purpose: IntendedKeyPurpose::CSK,
            _phantom: Default::default(),
        }
    }

    pub fn new_inactive_key(key: SigningKey<Octs, Inner>) -> Self {
        Self {
            key,
            purpose: IntendedKeyPurpose::Inactive,
            _phantom: Default::default(),
        }
    }
}

impl<Octs, Inner> DnssecSigningKey<Octs, Inner>
where
    Octs: AsRef<[u8]>,
    Inner: SignRaw,
{
    pub fn purpose(&self) -> IntendedKeyPurpose {
        self.purpose
    }

    pub fn set_purpose(&mut self, purpose: IntendedKeyPurpose) {
        self.purpose = purpose;
    }
    pub fn into_inner(self) -> SigningKey<Octs, Inner> {
        self.key
    }
}

//--- impl Deref

impl<Octs, Inner> Deref for DnssecSigningKey<Octs, Inner>
where
    Octs: AsRef<[u8]>,
    Inner: SignRaw,
{
    type Target = SigningKey<Octs, Inner>;

    fn deref(&self) -> &Self::Target {
        &self.key
    }
}

//--- impl From

impl<Octs, Inner> From<SigningKey<Octs, Inner>>
    for DnssecSigningKey<Octs, Inner>
where
    Octs: AsRef<[u8]>,
    Inner: SignRaw,
{
    fn from(key: SigningKey<Octs, Inner>) -> Self {
        let public_key = key.public_key();
        match (
            public_key.is_secure_entry_point(),
            public_key.is_zone_signing_key(),
        ) {
            (true, _) => Self::new_ksk(key),
            (false, true) => Self::new_zsk(key),
            (false, false) => Self::new_inactive_key(key),
        }
    }
}

//--- impl DesignatedSigningKey

impl<Octs, Inner> DesignatedSigningKey<Octs, Inner>
    for DnssecSigningKey<Octs, Inner>
where
    Octs: AsRef<[u8]>,
    Inner: SignRaw,
{
    fn signs_keys(&self) -> bool {
        matches!(
            self.purpose,
            IntendedKeyPurpose::KSK | IntendedKeyPurpose::CSK
        )
    }

    fn signs_zone_data(&self) -> bool {
        matches!(
            self.purpose,
            IntendedKeyPurpose::ZSK | IntendedKeyPurpose::CSK
        )
    }

    fn signing_key(&self) -> &SigningKey<Octs, Inner> {
        &self.key
    }
}
