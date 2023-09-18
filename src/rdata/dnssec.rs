//! Record data from [RFC 4034]: DS, DNSKEY, RRSIG, and NSEC records.
//!
//! This RFC defines the record types for DNSSEC.
//!
//! [RFC 4034]: https://tools.ietf.org/html/rfc4034

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{DigestAlg, Rtype, SecAlg};
use crate::base::name::{Dname, ParsedDname, PushError, ToDname};
use crate::base::rdata::{
    ComposeRecordData, LongRecordData, ParseRecordData, RecordData,
};
use crate::base::Ttl;
use crate::base::scan::{Scan, Scanner, ScannerError};
use crate::base::serial::Serial;
use crate::base::wire::{Compose, Composer, FormError, Parse, ParseError};
use crate::utils::{base16, base64};
use core::cmp::Ordering;
use core::convert::TryInto;
use core::{fmt, hash, ptr};
use octseq::builder::{
    EmptyBuilder, FreezeBuilder, FromBuilder, OctetsBuilder, Truncate,
};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;
#[cfg(feature = "serde")]
use octseq::serde::{DeserializeOctets, SerializeOctets};
#[cfg(feature = "std")]
use std::vec::Vec;

//------------ Dnskey --------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: octseq::serde::SerializeOctets + AsRef<[u8]>
        ",
        deserialize = "
            Octs: FromBuilder + octseq::serde::DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder:
                OctetsBuilder + EmptyBuilder,
        ",
    ))
)]
pub struct Dnskey<Octs> {
    flags: u16,
    protocol: u8,
    algorithm: SecAlg,
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::utils::base64::serde")
    )]
    public_key: Octs,
}

impl<Octs> Dnskey<Octs> {
    pub fn new(
        flags: u16,
        protocol: u8,
        algorithm: SecAlg,
        public_key: Octs,
    ) -> Result<Self, LongRecordData>
    where
        Octs: AsRef<[u8]>,
    {
        LongRecordData::check_len(
            usize::from(
                u16::COMPOSE_LEN + u8::COMPOSE_LEN + SecAlg::COMPOSE_LEN,
            )
            .checked_add(public_key.as_ref().len())
            .expect("long key"),
        )?;
        Ok(Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }

    /// Creates new DNSKEY record data without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to ensure that wire format representation of the
    /// record data is at most 65,535 octets long.
    pub unsafe fn new_unchecked(
        flags: u16,
        protocol: u8,
        algorithm: SecAlg,
        public_key: Octs,
    ) -> Self {
        Dnskey {
            flags,
            protocol,
            algorithm,
            public_key,
        }
    }

    pub fn flags(&self) -> u16 {
        self.flags
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn algorithm(&self) -> SecAlg {
        self.algorithm
    }

    pub fn public_key(&self) -> &Octs {
        &self.public_key
    }

    pub fn into_public_key(self) -> Octs {
        self.public_key
    }

    pub fn convert<Other: From<Octs>>(self) -> Dnskey<Other> {
        Dnskey {
            flags: self.flags,
            protocol: self.protocol,
            algorithm: self.algorithm,
            public_key: self.public_key.into(),
        }
    }

    /// Returns whether the Revoke flag is set.
    ///
    /// See [RFC 5011, Section 3].
    ///
    /// [RFC 5011, Section 3]: https://tools.ietf.org/html/rfc5011#section-3
    pub fn is_revoked(&self) -> bool {
        self.flags() & 0b0000_0000_1000_0000 != 0
    }

    /// Returns whether the the Secure Entry Point (SEP) flag is set.
    ///
    /// See [RFC 4034, Section 2.1.1]:
    ///
    /// > This flag is only intended to be a hint to zone signing or
    /// > debugging software as to the intended use of this DNSKEY record;
    /// > validators MUST NOT alter their behavior during the signature
    /// > validation process in any way based on the setting of this bit.
    ///
    /// [RFC 4034, Section 2.1.1]: https://tools.ietf.org/html/rfc4034#section-2.1.1
    pub fn is_secure_entry_point(&self) -> bool {
        self.flags() & 0b0000_0000_0000_0001 != 0
    }

    /// Returns whether the Zone Key flag is set.
    ///
    /// If the flag is not set, the key MUST NOT be used to verify RRSIGs that
    /// cover RRSETs. See [RFC 4034, Section 2.1.1].
    ///
    /// [RFC 4034, Section 2.1.1]: https://tools.ietf.org/html/rfc4034#section-2.1.1
    pub fn is_zsk(&self) -> bool {
        self.flags() & 0b0000_0001_0000_0000 != 0
    }

    /// Returns the key tag for this DNSKEY data.
    #[allow(clippy::while_let_loop)] // I find this clearer with a loop.
    pub fn key_tag(&self) -> u16
    where
        Octs: AsRef<[u8]>,
    {
        if self.algorithm == SecAlg::RsaMd5 {
            // The key tag is third-to-last and second-to-last octets of the
            // key as a big-endian u16. If we don’t have enough octets in the
            // key, we return 0.
            let len = self.public_key.as_ref().len();
            if len > 2 {
                u16::from_be_bytes(
                    self.public_key.as_ref()[len - 3..len - 1]
                        .try_into()
                        .unwrap(),
                )
            } else {
                0
            }
        } else {
            // Treat record data as a octet sequence. Add octets at odd
            // indexes as they are, add octets at even indexes shifted left
            // by 8 bits.
            let mut res = u32::from(self.flags);
            res += u32::from(self.protocol) << 8;
            res += u32::from(self.algorithm.to_int());
            let mut iter = self.public_key().as_ref().iter();
            loop {
                match iter.next() {
                    Some(&x) => res += u32::from(x) << 8,
                    None => break,
                }
                match iter.next() {
                    Some(&x) => res += u32::from(x),
                    None => break,
                }
            }
            res += (res >> 16) & 0xFFFF;
            (res & 0xFFFF) as u16
        }
    }

    pub(super) fn convert_octets<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Dnskey<Target>, Target::Error> {
        Ok(unsafe {
            Dnskey::new_unchecked(
                self.flags,
                self.protocol,
                self.algorithm,
                self.public_key.try_octets_into()?,
            )
        })
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let len = match parser.remaining().checked_sub(4) {
            Some(len) => len,
            None => return Err(ParseError::ShortInput),
        };
        Ok(unsafe {
            Self::new_unchecked(
                u16::parse(parser)?,
                u8::parse(parser)?,
                SecAlg::parse(parser)?,
                parser.parse_octets(len)?,
            )
        })
    }

    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error>
    where
        Octs: AsRef<[u8]>,
    {
        Self::new(
            u16::scan(scanner)?,
            u8::scan(scanner)?,
            SecAlg::scan(scanner)?,
            scanner.convert_entry(base64::SymbolConverter::new())?,
        )
        .map_err(|err| S::Error::custom(err.as_str()))
    }
}

impl<SrcOcts> Dnskey<SrcOcts> {
    pub fn flatten_into<Octs>(self) -> Result<Dnskey<Octs>, PushError>
    where
        Octs: OctetsFrom<SrcOcts>,
    {
        let Self {
            flags,
            protocol,
            algorithm,
            public_key,
        } = self;

        Ok(unsafe {
            Dnskey::new_unchecked(
                flags,
                protocol,
                algorithm,
                public_key.try_octets_into().map_err(Into::into)?,
            )
        })
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Dnskey<SrcOcts>> for Dnskey<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Dnskey<SrcOcts>) -> Result<Self, Self::Error> {
        Ok(unsafe {
            Dnskey::new_unchecked(
                source.flags,
                source.protocol,
                source.algorithm,
                Octs::try_octets_from(source.public_key)?,
            )
        })
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Dnskey<Other>> for Dnskey<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Dnskey<Other>) -> bool {
        self.flags == other.flags
            && self.protocol == other.protocol
            && self.algorithm == other.algorithm
            && self.public_key.as_ref() == other.public_key.as_ref()
    }
}

impl<Octs: AsRef<[u8]>> Eq for Dnskey<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Dnskey<Other>> for Dnskey<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Dnskey<Other>) -> Option<Ordering> {
        Some(self.canonical_cmp(other))
    }
}

impl<Octs, Other> CanonicalOrd<Dnskey<Other>> for Dnskey<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Dnskey<Other>) -> Ordering {
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.protocol.cmp(&other.protocol) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.algorithm.cmp(&other.algorithm) {
            Ordering::Equal => {}
            other => return other,
        }
        self.public_key.as_ref().cmp(other.public_key.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Ord for Dnskey<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for Dnskey<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.flags.hash(state);
        self.protocol.hash(state);
        self.algorithm.hash(state);
        self.public_key.as_ref().hash(state);
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs> RecordData for Dnskey<Octs> {
    fn rtype(&self) -> Rtype {
        Rtype::Dnskey
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Dnskey<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Dnskey {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Dnskey<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            u16::try_from(self.public_key.as_ref().len())
                .expect("long key")
                .checked_add(
                    u16::COMPOSE_LEN + u8::COMPOSE_LEN + SecAlg::COMPOSE_LEN,
                )
                .expect("long key"),
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.flags.compose(target)?;
        self.protocol.compose(target)?;
        self.algorithm.compose(target)?;
        target.append_slice(self.public_key.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display

impl<Octs: AsRef<[u8]>> fmt::Display for Dnskey<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.flags, self.protocol, self.algorithm)?;
        base64::display(&self.public_key, f)
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for Dnskey<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Dnskey")
            .field("flags", &self.flags)
            .field("protocol", &self.protocol)
            .field("algorithm", &self.algorithm)
            .field("public_key", &self.public_key.as_ref())
            .finish()
    }
}

//------------ ProtoRrsig ----------------------------------------------------

/// The RRSIG RDATA to be included when creating the signature.
#[derive(Clone)]
pub struct ProtoRrsig<Name> {
    type_covered: Rtype,
    algorithm: SecAlg,
    labels: u8,
    original_ttl: Ttl,
    expiration: Serial,
    inception: Serial,
    key_tag: u16,
    signer_name: Name,
}

impl<Name> ProtoRrsig<Name> {
    #[allow(clippy::too_many_arguments)] // XXX Consider changing.
    pub fn new(
        type_covered: Rtype,
        algorithm: SecAlg,
        labels: u8,
        original_ttl: Ttl,
        expiration: Serial,
        inception: Serial,
        key_tag: u16,
        signer_name: Name,
    ) -> Self {
        ProtoRrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
        }
    }

    pub fn into_rrsig<Octs: AsRef<[u8]>>(
        self,
        signature: Octs,
    ) -> Result<Rrsig<Octs, Name>, LongRecordData>
    where
        Name: ToDname,
    {
        Rrsig::new(
            self.type_covered,
            self.algorithm,
            self.labels,
            self.original_ttl,
            self.expiration,
            self.inception,
            self.key_tag,
            self.signer_name,
            signature,
        )
    }
}

impl<Octs> ProtoRrsig<ParsedDname<Octs>> {
    pub fn flatten_into<Target>(
        self,
    ) -> Result<ProtoRrsig<Dname<Target>>, PushError>
    where
        Octs: Octets,
        Target: for<'a> OctetsFrom<Octs::Range<'a>> + FromBuilder,
        <Target as FromBuilder>::Builder: EmptyBuilder,
    {
        let Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
        } = self;

        Ok(ProtoRrsig::new(
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name.flatten_into()?,
        ))
    }
}

//--- OctetsFrom

impl<Name, SrcName> OctetsFrom<ProtoRrsig<SrcName>> for ProtoRrsig<Name>
where
    Name: OctetsFrom<SrcName>,
{
    type Error = Name::Error;

    fn try_octets_from(
        source: ProtoRrsig<SrcName>,
    ) -> Result<Self, Self::Error> {
        Ok(ProtoRrsig::new(
            source.type_covered,
            source.algorithm,
            source.labels,
            source.original_ttl,
            source.expiration,
            source.inception,
            source.key_tag,
            Name::try_octets_from(source.signer_name)?,
        ))
    }
}

impl<Name: ToDname> ProtoRrsig<Name> {
    pub fn compose<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_head(target)?;
        self.signer_name.compose(target)
    }

    pub fn compose_canonical<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_head(target)?;
        self.signer_name.compose_canonical(target)
    }

    fn compose_len(&self) -> u16 {
        Rtype::COMPOSE_LEN
            + SecAlg::COMPOSE_LEN
            + u8::COMPOSE_LEN
            + u32::COMPOSE_LEN
            + Serial::COMPOSE_LEN
            + Serial::COMPOSE_LEN
            + u16::COMPOSE_LEN
            + self.signer_name.compose_len()
    }

    fn compose_head<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_len().compose(target)?;
        self.type_covered.compose(target)?;
        self.algorithm.compose(target)?;
        self.labels.compose(target)?;
        self.original_ttl.compose(target)?;
        self.expiration.compose(target)?;
        self.inception.compose(target)?;
        self.key_tag.compose(target)
    }
}

//------------ Rrsig ---------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: octseq::serde::SerializeOctets + AsRef<[u8]>,
            Name: serde::Serialize,
        ",
        deserialize = "
            Octs: FromBuilder + octseq::serde::DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder:
                OctetsBuilder + EmptyBuilder,
            Name: serde::Deserialize<'de>,
        ",
    ))
)]
pub struct Rrsig<Octs, Name> {
    type_covered: Rtype,
    algorithm: SecAlg,
    labels: u8,
    original_ttl: Ttl,
    expiration: Serial,
    inception: Serial,
    key_tag: u16,
    signer_name: Name,
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::utils::base64::serde")
    )]
    signature: Octs,
}

impl<Octs, Name> Rrsig<Octs, Name> {
    #[allow(clippy::too_many_arguments)] // XXX Consider changing.
    pub fn new(
        type_covered: Rtype,
        algorithm: SecAlg,
        labels: u8,
        original_ttl: Ttl,
        expiration: Serial,
        inception: Serial,
        key_tag: u16,
        signer_name: Name,
        signature: Octs,
    ) -> Result<Self, LongRecordData>
    where
        Octs: AsRef<[u8]>,
        Name: ToDname,
    {
        LongRecordData::check_len(
            usize::from(
                Rtype::COMPOSE_LEN
                    + SecAlg::COMPOSE_LEN
                    + u8::COMPOSE_LEN
                    + u32::COMPOSE_LEN
                    + Serial::COMPOSE_LEN
                    + Serial::COMPOSE_LEN
                    + u16::COMPOSE_LEN
                    + signer_name.compose_len(),
            )
            .checked_add(signature.as_ref().len())
            .expect("long signature"),
        )?;
        Ok(unsafe {
            Rrsig::new_unchecked(
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name,
                signature,
            )
        })
    }

    /// Creates new RRSIG record data without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to ensure that wire format representation of the
    /// record data is at most 65,535 octets long.
    #[allow(clippy::too_many_arguments)] // XXX Consider changing.
    pub unsafe fn new_unchecked(
        type_covered: Rtype,
        algorithm: SecAlg,
        labels: u8,
        original_ttl: Ttl,
        expiration: Serial,
        inception: Serial,
        key_tag: u16,
        signer_name: Name,
        signature: Octs,
    ) -> Self {
        Rrsig {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        }
    }

    pub fn type_covered(&self) -> Rtype {
        self.type_covered
    }

    pub fn algorithm(&self) -> SecAlg {
        self.algorithm
    }

    pub fn labels(&self) -> u8 {
        self.labels
    }

    pub fn original_ttl(&self) -> Ttl {
        self.original_ttl
    }

    pub fn expiration(&self) -> Serial {
        self.expiration
    }

    pub fn inception(&self) -> Serial {
        self.inception
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn signer_name(&self) -> &Name {
        &self.signer_name
    }

    pub fn signature(&self) -> &Octs {
        &self.signature
    }

    pub fn set_signature(&mut self, signature: Octs) {
        self.signature = signature
    }

    pub(super) fn convert_octets<TOcts, TName>(
        self,
    ) -> Result<Rrsig<TOcts, TName>, TOcts::Error>
    where
        TOcts: OctetsFrom<Octs>,
        TName: OctetsFrom<Name, Error = TOcts::Error>,
    {
        Ok(unsafe {
            Rrsig::new_unchecked(
                self.type_covered,
                self.algorithm,
                self.labels,
                self.original_ttl,
                self.expiration,
                self.inception,
                self.key_tag,
                TName::try_octets_from(self.signer_name)?,
                TOcts::try_octets_from(self.signature)?,
            )
        })
    }

    pub fn scan<S: Scanner<Octets = Octs, Dname = Name>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error>
    where
        Octs: AsRef<[u8]>,
        Name: ToDname,
    {
        Self::new(
            Rtype::scan(scanner)?,
            SecAlg::scan(scanner)?,
            u8::scan(scanner)?,
            Ttl::scan(scanner)?,
            Serial::scan_rrsig(scanner)?,
            Serial::scan_rrsig(scanner)?,
            u16::scan(scanner)?,
            scanner.scan_dname()?,
            scanner.convert_entry(base64::SymbolConverter::new())?,
        )
        .map_err(|err| S::Error::custom(err.as_str()))
    }
}

impl<Octs, NOcts> Rrsig<Octs, ParsedDname<NOcts>> {
    pub fn flatten_into<Target>(
        self,
    ) -> Result<Rrsig<Target, Dname<Target>>, PushError>
    where
        NOcts: Octets,
        Target: OctetsFrom<Octs>
            + for<'a> OctetsFrom<NOcts::Range<'a>>
            + FromBuilder,
        <Target as FromBuilder>::Builder: EmptyBuilder,
    {
        let Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            expiration,
            inception,
            key_tag,
            signer_name,
            signature,
        } = self;

        Ok(unsafe {
            Rrsig::new_unchecked(
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name.flatten_into()?,
                Target::try_octets_from(signature).map_err(Into::into)?,
            )
        })
    }
}

impl<Octs> Rrsig<Octs, ParsedDname<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let type_covered = Rtype::parse(parser)?;
        let algorithm = SecAlg::parse(parser)?;
        let labels = u8::parse(parser)?;
        let original_ttl = Ttl::parse(parser)?;
        let expiration = Serial::parse(parser)?;
        let inception = Serial::parse(parser)?;
        let key_tag = u16::parse(parser)?;
        let signer_name = ParsedDname::parse(parser)?;
        let len = parser.remaining();
        let signature = parser.parse_octets(len)?;
        Ok(unsafe {
            Self::new_unchecked(
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer_name,
                signature,
            )
        })
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts, Name, SrcName> OctetsFrom<Rrsig<SrcOcts, SrcName>>
    for Rrsig<Octs, Name>
where
    Octs: OctetsFrom<SrcOcts>,
    Name: OctetsFrom<SrcName>,
    Octs::Error: From<Name::Error>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: Rrsig<SrcOcts, SrcName>,
    ) -> Result<Self, Self::Error> {
        Ok(unsafe {
            Rrsig::new_unchecked(
                source.type_covered,
                source.algorithm,
                source.labels,
                source.original_ttl,
                source.expiration,
                source.inception,
                source.key_tag,
                Name::try_octets_from(source.signer_name)?,
                Octs::try_octets_from(source.signature)?,
            )
        })
    }
}

//--- PartialEq and Eq

impl<N, NN, O, OO> PartialEq<Rrsig<OO, NN>> for Rrsig<O, N>
where
    N: ToDname,
    NN: ToDname,
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
{
    fn eq(&self, other: &Rrsig<OO, NN>) -> bool {
        self.type_covered == other.type_covered
            && self.algorithm == other.algorithm
            && self.labels == other.labels
            && self.original_ttl == other.original_ttl
            && self.expiration.into_int() == other.expiration.into_int()
            && self.inception.into_int() == other.inception.into_int()
            && self.key_tag == other.key_tag
            && self.signer_name.name_eq(&other.signer_name)
            && self.signature.as_ref() == other.signature.as_ref()
    }
}

impl<Octs, Name> Eq for Rrsig<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: ToDname,
{
}

//--- PartialOrd, CanonicalOrd, and Ord

impl<N, NN, O, OO> PartialOrd<Rrsig<OO, NN>> for Rrsig<O, N>
where
    N: ToDname,
    NN: ToDname,
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Rrsig<OO, NN>) -> Option<Ordering> {
        match self.type_covered.partial_cmp(&other.type_covered) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.algorithm.partial_cmp(&other.algorithm) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.labels.partial_cmp(&other.labels) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.original_ttl.partial_cmp(&other.original_ttl) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.expiration.partial_cmp(&other.expiration) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.inception.partial_cmp(&other.inception) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.key_tag.partial_cmp(&other.key_tag) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.signer_name.name_cmp(&other.signer_name) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        self.signature
            .as_ref()
            .partial_cmp(other.signature.as_ref())
    }
}

impl<N, NN, O, OO> CanonicalOrd<Rrsig<OO, NN>> for Rrsig<O, N>
where
    N: ToDname,
    NN: ToDname,
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Rrsig<OO, NN>) -> Ordering {
        match self.type_covered.cmp(&other.type_covered) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.algorithm.cmp(&other.algorithm) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.labels.cmp(&other.labels) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.original_ttl.cmp(&other.original_ttl) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.expiration.canonical_cmp(&other.expiration) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.inception.canonical_cmp(&other.inception) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.key_tag.cmp(&other.key_tag) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.signer_name.lowercase_composed_cmp(&other.signer_name) {
            Ordering::Equal => {}
            other => return other,
        }
        self.signature.as_ref().cmp(other.signature.as_ref())
    }
}

impl<O: AsRef<[u8]>, N: ToDname> Ord for Rrsig<O, N> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}

//--- Hash

impl<O: AsRef<[u8]>, N: hash::Hash> hash::Hash for Rrsig<O, N> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.type_covered.hash(state);
        self.algorithm.hash(state);
        self.labels.hash(state);
        self.original_ttl.hash(state);
        self.expiration.into_int().hash(state);
        self.inception.into_int().hash(state);
        self.key_tag.hash(state);
        self.signer_name.hash(state);
        self.signature.as_ref().hash(state);
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs, Name> RecordData for Rrsig<Octs, Name> {
    fn rtype(&self) -> Rtype {
        Rtype::Rrsig
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Rrsig<Octs::Range<'a>, ParsedDname<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Rrsig {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs, Name> ComposeRecordData for Rrsig<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: ToDname,
{
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            (Rtype::COMPOSE_LEN
                + SecAlg::COMPOSE_LEN
                + u8::COMPOSE_LEN
                + u32::COMPOSE_LEN
                + Serial::COMPOSE_LEN
                + Serial::COMPOSE_LEN
                + u16::COMPOSE_LEN
                + self.signer_name.compose_len())
            .checked_add(
                u16::try_from(self.signature.as_ref().len())
                    .expect("long signature"),
            )
            .expect("long signature"),
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_head(target)?;
        self.signer_name.compose(target)?;
        target.append_slice(self.signature.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_head(target)?;
        self.signer_name.compose_canonical(target)?;
        target.append_slice(self.signature.as_ref())
    }
}

impl<Octs: AsRef<[u8]>, Name: ToDname> Rrsig<Octs, Name> {
    fn compose_head<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.type_covered.compose(target)?;
        self.algorithm.compose(target)?;
        self.labels.compose(target)?;
        self.original_ttl.compose(target)?;
        self.expiration.compose(target)?;
        self.inception.compose(target)?;
        self.key_tag.compose(target)
    }
}

//--- Display

impl<Octs, Name> fmt::Display for Rrsig<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {} {}. ",
            self.type_covered,
            self.algorithm,
            self.labels,
            self.original_ttl.as_secs(),
            self.expiration,
            self.inception,
            self.key_tag,
            self.signer_name
        )?;
        base64::display(&self.signature, f)
    }
}

//--- Debug

impl<Octs, Name> fmt::Debug for Rrsig<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Rrsig")
            .field("type_covered", &self.type_covered)
            .field("algorithm", &self.algorithm)
            .field("labels", &self.labels)
            .field("original_ttl", &self.original_ttl)
            .field("expiration", &self.expiration)
            .field("inception", &self.inception)
            .field("key_tag", &self.key_tag)
            .field("signer_name", &self.signer_name)
            .field("signature", &self.signature.as_ref())
            .finish()
    }
}

//------------ Nsec ----------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: octseq::serde::SerializeOctets + AsRef<[u8]>,
            Name: serde::Serialize,
        ",
        deserialize = "
            Octs: FromBuilder + octseq::serde::DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder:
                OctetsBuilder + EmptyBuilder + Truncate 
                + AsRef<[u8]> + AsMut<[u8]>,
            Name: serde::Deserialize<'de>,
        ",
    ))
)]
pub struct Nsec<Octs, Name> {
    next_name: Name,
    types: RtypeBitmap<Octs>,
}

impl<Octs, Name> Nsec<Octs, Name> {
    pub fn new(next_name: Name, types: RtypeBitmap<Octs>) -> Self {
        Nsec { next_name, types }
    }

    pub fn next_name(&self) -> &Name {
        &self.next_name
    }

    pub fn set_next_name(&mut self, next_name: Name) {
        self.next_name = next_name
    }

    pub fn types(&self) -> &RtypeBitmap<Octs> {
        &self.types
    }

    pub(super) fn convert_octets<TOcts, TName>(
        self,
    ) -> Result<Nsec<TOcts, TName>, TOcts::Error>
    where
        TOcts: OctetsFrom<Octs>,
        TName: OctetsFrom<Name, Error = TOcts::Error>,
    {
        Ok(Nsec::new(
            self.next_name.try_octets_into()?,
            self.types.convert_octets()?,
        ))
    }

    pub fn scan<S: Scanner<Octets = Octs, Dname = Name>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(
            scanner.scan_dname()?,
            RtypeBitmap::scan(scanner)?,
        ))
    }
}

impl<Octs, NOcts> Nsec<Octs, ParsedDname<NOcts>> {
    pub fn flatten_into<Target>(
        self,
    ) -> Result<Nsec<Target, Dname<Target>>, PushError>
    where
        NOcts: Octets,
        Target: OctetsFrom<Octs>
            + for<'a> OctetsFrom<NOcts::Range<'a>>
            + FromBuilder,
        <Target as FromBuilder>::Builder: EmptyBuilder,
    {
        let Self { next_name, types } = self;
        Ok(Nsec::new(
            next_name.flatten_into()?,
            types.try_octets_into().map_err(Into::into)?,
        ))
    }
}

impl<Octs: AsRef<[u8]>> Nsec<Octs, ParsedDname<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Nsec::new(
            ParsedDname::parse(parser)?,
            RtypeBitmap::parse(parser)?,
        ))
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts, Name, SrcName> OctetsFrom<Nsec<SrcOcts, SrcName>>
    for Nsec<Octs, Name>
where
    Octs: OctetsFrom<SrcOcts>,
    Name: OctetsFrom<SrcName, Error = Octs::Error>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: Nsec<SrcOcts, SrcName>,
    ) -> Result<Self, Self::Error> {
        Ok(Nsec::new(
            Name::try_octets_from(source.next_name)?,
            RtypeBitmap::try_octets_from(source.types)?,
        ))
    }
}

//--- PartialEq and Eq

impl<O, OO, N, NN> PartialEq<Nsec<OO, NN>> for Nsec<O, N>
where
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
    N: ToDname,
    NN: ToDname,
{
    fn eq(&self, other: &Nsec<OO, NN>) -> bool {
        self.next_name.name_eq(&other.next_name) && self.types == other.types
    }
}

impl<O: AsRef<[u8]>, N: ToDname> Eq for Nsec<O, N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<O, OO, N, NN> PartialOrd<Nsec<OO, NN>> for Nsec<O, N>
where
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
    N: ToDname,
    NN: ToDname,
{
    fn partial_cmp(&self, other: &Nsec<OO, NN>) -> Option<Ordering> {
        match self.next_name.name_cmp(&other.next_name) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        self.types.partial_cmp(&self.types)
    }
}

impl<O, OO, N, NN> CanonicalOrd<Nsec<OO, NN>> for Nsec<O, N>
where
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
    N: ToDname,
    NN: ToDname,
{
    fn canonical_cmp(&self, other: &Nsec<OO, NN>) -> Ordering {
        // RFC 6840 says that Nsec::next_name is not converted to lower case.
        match self.next_name.composed_cmp(&other.next_name) {
            Ordering::Equal => {}
            other => return other,
        }
        self.types.cmp(&self.types)
    }
}

impl<O, N> Ord for Nsec<O, N>
where
    O: AsRef<[u8]>,
    N: ToDname,
{
    fn cmp(&self, other: &Self) -> Ordering {
        match self.next_name.name_cmp(&other.next_name) {
            Ordering::Equal => {}
            other => return other,
        }
        self.types.cmp(&self.types)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>, Name: hash::Hash> hash::Hash for Nsec<Octs, Name> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.next_name.hash(state);
        self.types.hash(state);
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs, Name> RecordData for Nsec<Octs, Name> {
    fn rtype(&self) -> Rtype {
        Rtype::Nsec
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Nsec<Octs::Range<'a>, ParsedDname<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Nsec {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs, Name> ComposeRecordData for Nsec<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: ToDname,
{
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            self.next_name
                .compose_len()
                .checked_add(self.types.compose_len())
                .expect("long type bitmap"),
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.next_name.compose(target)?;
        self.types.compose(target)
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        // Deferring to compose_rdata is correct as we keep the case of the
        // next name.
        self.compose_rdata(target)
    }
}

//--- Display

impl<Octs, Name> fmt::Display for Nsec<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}. {}", self.next_name, self.types)
    }
}

//--- Debug

impl<Octs, Name> fmt::Debug for Nsec<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Nsec")
            .field("next_name", &self.next_name)
            .field("types", &self.types)
            .finish()
    }
}

//------------ Ds -----------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: octseq::serde::SerializeOctets + AsRef<[u8]>
        ",
        deserialize = "
            Octs: FromBuilder + octseq::serde::DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder:
                OctetsBuilder + EmptyBuilder,
        ",
    ))
)]
pub struct Ds<Octs> {
    key_tag: u16,
    algorithm: SecAlg,
    digest_type: DigestAlg,
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::utils::base64::serde")
    )]
    digest: Octs,
}

impl<Octs> Ds<Octs> {
    pub fn new(
        key_tag: u16,
        algorithm: SecAlg,
        digest_type: DigestAlg,
        digest: Octs,
    ) -> Result<Self, LongRecordData>
    where
        Octs: AsRef<[u8]>,
    {
        LongRecordData::check_len(
            usize::from(
                u16::COMPOSE_LEN
                    + SecAlg::COMPOSE_LEN
                    + DigestAlg::COMPOSE_LEN,
            )
            .checked_add(digest.as_ref().len())
            .expect("long digest"),
        )?;
        Ok(unsafe {
            Ds::new_unchecked(key_tag, algorithm, digest_type, digest)
        })
    }

    /// Creates new DS record data without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to ensure that wire format representation of the
    /// record data is at most 65,535 octets long.
    pub unsafe fn new_unchecked(
        key_tag: u16,
        algorithm: SecAlg,
        digest_type: DigestAlg,
        digest: Octs,
    ) -> Self {
        Ds {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }
    }

    pub fn key_tag(&self) -> u16 {
        self.key_tag
    }

    pub fn algorithm(&self) -> SecAlg {
        self.algorithm
    }

    pub fn digest_type(&self) -> DigestAlg {
        self.digest_type
    }

    pub fn digest(&self) -> &Octs {
        &self.digest
    }

    pub fn into_digest(self) -> Octs {
        self.digest
    }

    pub(super) fn convert_octets<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Ds<Target>, Target::Error> {
        Ok(unsafe {
            Ds::new_unchecked(
                self.key_tag,
                self.algorithm,
                self.digest_type,
                self.digest.try_octets_into()?,
            )
        })
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let len = match parser.remaining().checked_sub(4) {
            Some(len) => len,
            None => return Err(ParseError::ShortInput),
        };
        Ok(unsafe {
            Self::new_unchecked(
                u16::parse(parser)?,
                SecAlg::parse(parser)?,
                DigestAlg::parse(parser)?,
                parser.parse_octets(len)?,
            )
        })
    }

    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error>
    where
        Octs: AsRef<[u8]>,
    {
        Self::new(
            u16::scan(scanner)?,
            SecAlg::scan(scanner)?,
            DigestAlg::scan(scanner)?,
            scanner.convert_entry(base16::SymbolConverter::new())?,
        )
        .map_err(|err| S::Error::custom(err.as_str()))
    }
}

impl<SrcOcts> Ds<SrcOcts> {
    pub fn flatten_into<Octs>(self) -> Result<Ds<Octs>, PushError>
    where
        Octs: OctetsFrom<SrcOcts>,
    {
        let Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } = self;
        Ok(unsafe {
            Ds::new_unchecked(
                key_tag,
                algorithm,
                digest_type,
                digest.try_octets_into().map_err(Into::into)?,
            )
        })
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Ds<SrcOcts>> for Ds<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Ds<SrcOcts>) -> Result<Self, Self::Error> {
        Ok(unsafe {
            Ds::new_unchecked(
                source.key_tag,
                source.algorithm,
                source.digest_type,
                Octs::try_octets_from(source.digest)?,
            )
        })
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Ds<Other>> for Ds<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Ds<Other>) -> bool {
        self.key_tag == other.key_tag
            && self.algorithm == other.algorithm
            && self.digest_type == other.digest_type
            && self.digest.as_ref().eq(other.digest.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Eq for Ds<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Ds<Other>> for Ds<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Ds<Other>) -> Option<Ordering> {
        match self.key_tag.partial_cmp(&other.key_tag) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.algorithm.partial_cmp(&other.algorithm) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.digest_type.partial_cmp(&other.digest_type) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.digest.as_ref().partial_cmp(other.digest.as_ref())
    }
}

impl<Octs, Other> CanonicalOrd<Ds<Other>> for Ds<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Ds<Other>) -> Ordering {
        match self.key_tag.cmp(&other.key_tag) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.algorithm.cmp(&other.algorithm) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.digest_type.cmp(&other.digest_type) {
            Ordering::Equal => {}
            other => return other,
        }
        self.digest.as_ref().cmp(other.digest.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Ord for Ds<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for Ds<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.key_tag.hash(state);
        self.algorithm.hash(state);
        self.digest_type.hash(state);
        self.digest.as_ref().hash(state);
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs> RecordData for Ds<Octs> {
    fn rtype(&self) -> Rtype {
        Rtype::Ds
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Ds<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Ds {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Ds<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            u16::checked_add(
                u16::COMPOSE_LEN
                    + SecAlg::COMPOSE_LEN
                    + DigestAlg::COMPOSE_LEN,
                self.digest.as_ref().len().try_into().expect("long digest"),
            )
            .expect("long digest"),
        )
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.key_tag.compose(target)?;
        self.algorithm.compose(target)?;
        self.digest_type.compose(target)?;
        target.append_slice(self.digest.as_ref())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display

impl<Octs: AsRef<[u8]>> fmt::Display for Ds<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} ",
            self.key_tag, self.algorithm, self.digest_type
        )?;
        for ch in self.digest.as_ref() {
            write!(f, "{:02x}", ch)?
        }
        Ok(())
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for Ds<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Ds")
            .field("key_tag", &self.key_tag)
            .field("algorithm", &self.algorithm)
            .field("digest_type", &self.digest_type)
            .field("digest", &self.digest.as_ref())
            .finish()
    }
}

//------------ RtypeBitmap ---------------------------------------------------

#[derive(Clone)]
pub struct RtypeBitmap<Octs>(Octs);

impl<Octs> RtypeBitmap<Octs> {
    pub fn from_octets(octets: Octs) -> Result<Self, RtypeBitmapError>
    where
        Octs: AsRef<[u8]>,
    {
        {
            let mut data = octets.as_ref();
            while !data.is_empty() {
                // At least bitmap number and length must be present.
                if data.len() < 2 {
                    return Err(RtypeBitmapError::ShortInput);
                }

                let len = (data[1] as usize) + 2;
                // https://tools.ietf.org/html/rfc4034#section-4.1.2:
                //  Blocks with no types present MUST NOT be included.
                if len == 2 {
                    return Err(RtypeBitmapError::BadRtypeBitmap);
                }
                if len > 34 {
                    return Err(RtypeBitmapError::BadRtypeBitmap);
                }
                if data.len() < len {
                    return Err(RtypeBitmapError::ShortInput);
                }
                data = &data[len..];
            }
        }
        Ok(RtypeBitmap(octets))
    }

    pub fn builder() -> RtypeBitmapBuilder<Octs::Builder>
    where
        Octs: FromBuilder,
        <Octs as FromBuilder>::Builder: EmptyBuilder,
    {
        RtypeBitmapBuilder::new()
    }

    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        let first = Rtype::scan(scanner)?;
        let mut builder =
            RtypeBitmapBuilder::with_builder(scanner.octets_builder()?);
        builder.add(first).map_err(|_| S::Error::short_buf())?;
        while scanner.continues() {
            builder
                .add(Rtype::scan(scanner)?)
                .map_err(|_| S::Error::short_buf())?;
        }
        Ok(builder.finalize())
    }

    pub fn as_octets(&self) -> &Octs {
        &self.0
    }

    pub(super) fn convert_octets<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<RtypeBitmap<Target>, Target::Error> {
        Ok(RtypeBitmap(self.0.try_octets_into()?))
    }
}

impl<Octs: AsRef<[u8]>> RtypeBitmap<Octs> {
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_ref()
    }

    pub fn iter(&self) -> RtypeBitmapIter {
        RtypeBitmapIter::new(self.0.as_ref())
    }

    pub fn contains(&self, rtype: Rtype) -> bool {
        let (block, octet, mask) = split_rtype(rtype);
        let mut data = self.0.as_ref();
        while !data.is_empty() {
            let ((window_num, window), next_data) =
                read_window(data).unwrap();
            if window_num == block {
                return !(window.len() <= octet || window[octet] & mask == 0);
            }
            data = next_data;
        }
        false
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        let len = parser.remaining();
        RtypeBitmap::from_octets(parser.parse_octets(len)?)
            .map_err(Into::into)
    }

    pub fn compose_len(&self) -> u16 {
        u16::try_from(self.0.as_ref().len()).expect("long rtype bitmap")
    }

    pub fn compose<Target: OctetsBuilder + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.0.as_ref())
    }
}

//--- AsRef

impl<T, Octs: AsRef<T>> AsRef<T> for RtypeBitmap<Octs> {
    fn as_ref(&self) -> &T {
        self.0.as_ref()
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<RtypeBitmap<SrcOcts>> for RtypeBitmap<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: RtypeBitmap<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Octs::try_octets_from(source.0).map(RtypeBitmap)
    }
}

//--- PartialEq and Eq

impl<O, OO> PartialEq<RtypeBitmap<OO>> for RtypeBitmap<O>
where
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
{
    fn eq(&self, other: &RtypeBitmap<OO>) -> bool {
        self.0.as_ref().eq(other.0.as_ref())
    }
}

impl<O: AsRef<[u8]>> Eq for RtypeBitmap<O> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<O, OO> PartialOrd<RtypeBitmap<OO>> for RtypeBitmap<O>
where
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &RtypeBitmap<OO>) -> Option<Ordering> {
        self.0.as_ref().partial_cmp(other.0.as_ref())
    }
}

impl<O, OO> CanonicalOrd<RtypeBitmap<OO>> for RtypeBitmap<O>
where
    O: AsRef<[u8]>,
    OO: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &RtypeBitmap<OO>) -> Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

impl<O: AsRef<[u8]>> Ord for RtypeBitmap<O> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.as_ref().cmp(other.0.as_ref())
    }
}

//--- Hash

impl<O: AsRef<[u8]>> hash::Hash for RtypeBitmap<O> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.0.as_ref().hash(state)
    }
}

//--- IntoIterator

impl<'a, Octs: AsRef<[u8]>> IntoIterator for &'a RtypeBitmap<Octs> {
    type Item = Rtype;
    type IntoIter = RtypeBitmapIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//--- Display

impl<Octs: AsRef<[u8]>> fmt::Display for RtypeBitmap<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.iter();
        if let Some(rtype) = iter.next() {
            rtype.fmt(f)?;
        }
        for rtype in iter {
            write!(f, " {}", rtype)?
        }
        Ok(())
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for RtypeBitmap<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("RtypeBitmap(")?;
        fmt::Display::fmt(self, f)?;
        f.write_str(")")
    }
}

//--- Serialize and Deserialize

#[cfg(feature = "serde")]
impl<Octs> serde::Serialize for RtypeBitmap<Octs>
where
    Octs: AsRef<[u8]> + SerializeOctets,
{
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            struct Inner<'a>(&'a [u8]);

            impl<'a> serde::Serialize for Inner<'a> {
                fn serialize<S: serde::Serializer>(
                    &self,
                    serializer: S,
                ) -> Result<S::Ok, S::Error> {
                    use serde::ser::SerializeSeq;

                    let mut serializer = serializer.serialize_seq(None)?;
                    for item in RtypeBitmapIter::new(self.0) {
                        serializer.serialize_element(&item)?;
                    }
                    serializer.end()
                }
            }

            serializer.serialize_newtype_struct(
                "RtypeBitmap",
                &Inner(self.0.as_ref()),
            )
        } else {
            serializer.serialize_newtype_struct(
                "RtypeBitmap",
                &self.0.as_serialized_octets(),
            )
        }
    }
}

#[cfg(feature = "serde")]
impl<'de, Octs> serde::Deserialize<'de> for RtypeBitmap<Octs>
where
    Octs: FromBuilder + DeserializeOctets<'de>,
    <Octs as FromBuilder>::Builder:
        EmptyBuilder + Truncate + AsRef<[u8]> + AsMut<[u8]>,
{
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        use core::marker::PhantomData;

        struct InnerVisitor<'de, T: DeserializeOctets<'de>>(T::Visitor);

        impl<'de, Octs> serde::de::Visitor<'de> for InnerVisitor<'de, Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder: OctetsBuilder
                + EmptyBuilder
                + Truncate
                + AsRef<[u8]>
                + AsMut<[u8]>,
        {
            type Value = RtypeBitmap<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a record type bitmap")
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                use serde::de::Error;

                let mut builder = RtypeBitmap::<Octs>::builder();
                while let Some(element) = seq.next_element()? {
                    builder.add(element).map_err(|_| {
                        A::Error::custom(octseq::builder::ShortBuf)
                    })?;
                }

                Ok(builder.finalize())
            }

            fn visit_borrowed_bytes<E: serde::de::Error>(
                self,
                value: &'de [u8],
            ) -> Result<Self::Value, E> {
                self.0.visit_borrowed_bytes(value).and_then(|octets| {
                    RtypeBitmap::from_octets(octets).map_err(E::custom)
                })
            }

            #[cfg(feature = "std")]
            fn visit_byte_buf<E: serde::de::Error>(
                self,
                value: std::vec::Vec<u8>,
            ) -> Result<Self::Value, E> {
                self.0.visit_byte_buf(value).and_then(|octets| {
                    RtypeBitmap::from_octets(octets).map_err(E::custom)
                })
            }
        }

        struct NewtypeVisitor<T>(PhantomData<T>);

        impl<'de, Octs> serde::de::Visitor<'de> for NewtypeVisitor<Octs>
        where
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder: OctetsBuilder
                + EmptyBuilder
                + Truncate
                + AsRef<[u8]>
                + AsMut<[u8]>,
        {
            type Value = RtypeBitmap<Octs>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a record type bitmap")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                if deserializer.is_human_readable() {
                    deserializer
                        .deserialize_seq(InnerVisitor(Octs::visitor()))
                } else {
                    Octs::deserialize_with_visitor(
                        deserializer,
                        InnerVisitor(Octs::visitor()),
                    )
                }
            }
        }

        deserializer.deserialize_newtype_struct(
            "RtypeBitmap",
            NewtypeVisitor(PhantomData),
        )
    }
}

//------------ RtypeBitmapBuilder --------------------------------------------

/// A builder for a record type bitmap.
//
//  Here is how this is going to work: We keep one long Builder into which
//  we place all added types. The buffer contains a sequence of blocks
//  encoded similarly to the final format but with all 32 octets of the
//  bitmap present. Blocks are in order and are only added when needed (which
//  means we may have to insert a block in the middle). When finalizing, we
//  compress the block buffer by dropping the unncessary octets of each
//  block.
#[derive(Clone, Debug)]
pub struct RtypeBitmapBuilder<Builder> {
    buf: Builder,
}

impl<Builder: OctetsBuilder> RtypeBitmapBuilder<Builder> {
    pub fn new() -> Self
    where
        Builder: EmptyBuilder,
    {
        RtypeBitmapBuilder {
            // Start out with the capacity for one block.
            buf: Builder::with_capacity(34),
        }
    }

    pub fn with_builder(builder: Builder) -> Self {
        RtypeBitmapBuilder { buf: builder }
    }
}

#[cfg(feature = "std")]
impl RtypeBitmapBuilder<Vec<u8>> {
    pub fn new_vec() -> Self {
        Self::new()
    }
}

impl<Builder> RtypeBitmapBuilder<Builder>
where
    Builder: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>,
{
    pub fn add(&mut self, rtype: Rtype) -> Result<(), Builder::AppendError> {
        let (block, octet, bit) = split_rtype(rtype);
        let block = self.get_block(block)?;
        if (block[1] as usize) < (octet + 1) {
            block[1] = (octet + 1) as u8
        }
        block[octet + 2] |= bit;
        Ok(())
    }

    fn get_block(
        &mut self,
        block: u8,
    ) -> Result<&mut [u8], Builder::AppendError> {
        let mut pos = 0;
        while pos < self.buf.as_ref().len() {
            match self.buf.as_ref()[pos].cmp(&block) {
                Ordering::Equal => {
                    return Ok(&mut self.buf.as_mut()[pos..pos + 34])
                }
                Ordering::Greater => {
                    let len = self.buf.as_ref().len() - pos;
                    self.buf.append_slice(&[0; 34])?;
                    let buf = self.buf.as_mut();
                    unsafe {
                        ptr::copy(
                            buf.as_ptr().add(pos),
                            buf.as_mut_ptr().add(pos + 34),
                            len,
                        );
                        ptr::write_bytes(buf.as_mut_ptr().add(pos), 0, 34);
                    }
                    buf[pos] = block;
                    return Ok(&mut buf[pos..pos + 34]);
                }
                Ordering::Less => pos += 34,
            }
        }

        self.buf.append_slice(&[0; 34])?;
        self.buf.as_mut()[pos] = block;
        Ok(&mut self.buf.as_mut()[pos..pos + 34])
    }

    pub fn finalize(mut self) -> RtypeBitmap<Builder::Octets>
    where
        Builder: FreezeBuilder + Truncate,
    {
        let mut src_pos = 0;
        let mut dst_pos = 0;
        while src_pos < self.buf.as_ref().len() {
            let len = (self.buf.as_ref()[src_pos + 1] as usize) + 2;
            if src_pos != dst_pos {
                let buf = self.buf.as_mut();
                unsafe {
                    ptr::copy(
                        buf.as_ptr().add(src_pos),
                        buf.as_mut_ptr().add(dst_pos),
                        len,
                    )
                }
            }
            dst_pos += len;
            src_pos += 34;
        }
        self.buf.truncate(dst_pos);
        RtypeBitmap(self.buf.freeze())
    }
}

//--- Default

impl<Builder> Default for RtypeBitmapBuilder<Builder>
where
    Builder: OctetsBuilder + EmptyBuilder,
{
    fn default() -> Self {
        Self::new()
    }
}

//------------ RtypeBitmapIter -----------------------------------------------

pub struct RtypeBitmapIter<'a> {
    /// The data to iterate over.
    ///
    /// This starts with the octets of the current block without the block
    /// number and length.
    data: &'a [u8],

    /// The base value of the current block, i.e., its upper 8 bits.
    block: u16,

    /// The length of the current block’s data.
    len: usize,

    /// Index of the current octet in the current block.
    octet: usize,

    /// Index of the next set bit in the current octet in the current block.
    bit: u16,
}

impl<'a> RtypeBitmapIter<'a> {
    fn new(data: &'a [u8]) -> Self {
        if data.is_empty() {
            RtypeBitmapIter {
                data,
                block: 0,
                len: 0,
                octet: 0,
                bit: 0,
            }
        } else {
            let mut res = RtypeBitmapIter {
                data: &data[2..],
                block: u16::from(data[0]) << 8,
                len: usize::from(data[1]),
                octet: 0,
                bit: 0,
            };
            if res.data[0] & 0x80 == 0 {
                res.advance()
            }
            res
        }
    }

    fn advance(&mut self) {
        loop {
            self.bit += 1;
            if self.bit == 8 {
                self.bit = 0;
                self.octet += 1;
                if self.octet == self.len {
                    self.data = &self.data[self.len..];
                    if self.data.is_empty() {
                        return;
                    }
                    self.block = u16::from(self.data[0]) << 8;
                    self.len = usize::from(self.data[1]);
                    self.data = &self.data[2..];
                    self.octet = 0;
                }
            }
            if self.data[self.octet] & (0x80 >> self.bit) != 0 {
                return;
            }
        }
    }
}

impl<'a> Iterator for RtypeBitmapIter<'a> {
    type Item = Rtype;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.is_empty() {
            return None;
        }
        let res =
            Rtype::from_int(self.block | (self.octet as u16) << 3 | self.bit);
        self.advance();
        Some(res)
    }
}

//------------ RtypeBitmapError ----------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RtypeBitmapError {
    ShortInput,
    BadRtypeBitmap,
}

//--- From

impl From<RtypeBitmapError> for ParseError {
    fn from(err: RtypeBitmapError) -> ParseError {
        match err {
            RtypeBitmapError::ShortInput => ParseError::ShortInput,
            RtypeBitmapError::BadRtypeBitmap => {
                FormError::new("invalid NSEC bitmap").into()
            }
        }
    }
}

//--- Display and Error

impl fmt::Display for RtypeBitmapError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RtypeBitmapError::ShortInput => ParseError::ShortInput.fmt(f),
            RtypeBitmapError::BadRtypeBitmap => {
                f.write_str("invalid record type bitmap")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RtypeBitmapError {}

//------------ Friendly Helper Functions -------------------------------------

/// Splits an Rtype value into window number, octet number, and octet mask.
fn split_rtype(rtype: Rtype) -> (u8, usize, u8) {
    let rtype = rtype.to_int();
    (
        (rtype >> 8) as u8,
        ((rtype & 0xFF) >> 3) as usize,
        0b1000_0000 >> (rtype & 0x07),
    )
}

/// Splits the next bitmap window from the bitmap and returns None when there's no next window.
#[allow(clippy::type_complexity)]
fn read_window(data: &[u8]) -> Option<((u8, &[u8]), &[u8])> {
    data.split_first().and_then(|(n, data)| {
        data.split_first().and_then(|(l, data)| {
            if data.len() >= usize::from(*l) {
                let (window, data) = data.split_at(usize::from(*l));
                Some(((*n, window), data))
            } else {
                None
            }
        })
    })
}

//============ Test ==========================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::iana::Rtype;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use core::str::FromStr;
    use std::vec::Vec;

    //--- Dnskey

    #[test]
    fn dnskey_compose_parse_scan() {
        let rdata = Dnskey::new(10, 11, SecAlg::RsaSha1, b"key0").unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Dnskey::parse(parser));
        test_scan(&["10", "11", "RSASHA1", "a2V5MA=="], Dnskey::scan, &rdata);
    }

    //--- Rrsig

    #[test]
    fn rrsig_compose_parse_scan() {
        let rdata = Rrsig::new(
            Rtype::A,
            SecAlg::RsaSha1,
            3,
            Ttl::from_secs(12),
            Serial::from(13),
            Serial::from(14),
            15,
            Dname::<Vec<u8>>::from_str("example.com.").unwrap(),
            b"key",
        )
        .unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Rrsig::parse(parser));
        test_scan(
            &[
                "A",
                "RSASHA1",
                "3",
                "12",
                "13",
                "14",
                "15",
                "example.com.",
                "a2V5",
            ],
            Rrsig::scan,
            &rdata,
        );
    }

    //--- Nsec

    #[test]
    fn nsec_compose_parse_scan() {
        let mut rtype = RtypeBitmapBuilder::new_vec();
        rtype.add(Rtype::A).unwrap();
        rtype.add(Rtype::Srv).unwrap();
        let rdata = Nsec::new(
            Dname::<Vec<u8>>::from_str("example.com.").unwrap(),
            rtype.finalize(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Nsec::parse(parser));
        test_scan(&["example.com.", "A", "SRV"], Nsec::scan, &rdata);
    }

    //--- Ds

    #[test]
    fn ds_compose_parse_scan() {
        let rdata =
            Ds::new(10, SecAlg::RsaSha1, DigestAlg::Sha256, b"key").unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Ds::parse(parser));
        test_scan(&["10", "RSASHA1", "2", "6b6579"], Ds::scan, &rdata);
    }

    //--- RtypeBitmape

    #[test]
    fn rtype_split() {
        assert_eq!(split_rtype(Rtype::A), (0, 0, 0b01000000));
        assert_eq!(split_rtype(Rtype::Ns), (0, 0, 0b00100000));
        assert_eq!(split_rtype(Rtype::Caa), (1, 0, 0b01000000));
    }

    #[test]
    fn rtype_bitmap_read_window() {
        let mut builder = RtypeBitmapBuilder::new_vec();
        builder.add(Rtype::A).unwrap();
        builder.add(Rtype::Caa).unwrap();
        let bitmap = builder.finalize();

        let ((n, window), data) = read_window(bitmap.as_slice()).unwrap();
        assert_eq!((n, window), (0u8, b"\x40".as_ref()));
        let ((n, window), data) = read_window(data).unwrap();
        assert_eq!((n, window), (1u8, b"\x40".as_ref()));
        assert!(data.is_empty());
        assert!(read_window(data).is_none());
    }

    #[test]
    fn rtype_bitmap_builder() {
        let mut builder = RtypeBitmapBuilder::new_vec();
        builder.add(Rtype::Int(1234)).unwrap(); // 0x04D2
        builder.add(Rtype::A).unwrap(); // 0x0001
        builder.add(Rtype::Mx).unwrap(); // 0x000F
        builder.add(Rtype::Rrsig).unwrap(); // 0x002E
        builder.add(Rtype::Nsec).unwrap(); // 0x002F
        let bitmap = builder.finalize();
        assert_eq!(
            bitmap.as_slice(),
            &b"\x00\x06\x40\x01\x00\x00\x00\x03\
                     \x04\x1b\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x00\x00\x00\x00\
                     \x00\x00\x00\x00\x20"[..]
        );

        assert!(bitmap.contains(Rtype::A));
        assert!(bitmap.contains(Rtype::Mx));
        assert!(bitmap.contains(Rtype::Rrsig));
        assert!(bitmap.contains(Rtype::Nsec));
        assert!(bitmap.contains(Rtype::Int(1234)));
        assert!(!bitmap.contains(Rtype::Int(1235)));
        assert!(!bitmap.contains(Rtype::Ns));
    }

    #[test]
    fn rtype_bitmap_iter() {
        use std::vec::Vec;

        let mut builder = RtypeBitmapBuilder::new_vec();
        let types = vec![
            Rtype::Ns,
            Rtype::Soa,
            Rtype::Mx,
            Rtype::Txt,
            Rtype::Rrsig,
            Rtype::Dnskey,
            Rtype::Nsec3param,
            Rtype::Spf,
            Rtype::Caa,
        ];
        for t in types.iter() {
            builder.add(*t).unwrap();
        }

        let bitmap = builder.finalize();
        let bitmap_types: Vec<_> = bitmap.iter().collect();
        assert_eq!(types, bitmap_types);
    }

    #[test]
    fn dnskey_key_tag() {
        assert_eq!(
            Dnskey::new(
                256,
                3,
                SecAlg::RsaSha256,
                base64::decode::<Vec<u8>>(
                    "AwEAAcTQyaIe6nt3xSPOG2L/YfwBkOVTJN6mlnZ249O5Rtt3ZSRQHxQS\
                     W61AODYw6bvgxrrGq8eeOuenFjcSYgNAMcBYoEYYmKDW6e9EryW4ZaT/\
                     MCq+8Am06oR40xAA3fClOM6QjRcT85tP41Go946AicBGP8XOP/Aj1aI/\
                     oPRGzRnboUPUok/AzTNnW5npBU69+BuiIwYE7mQOiNBFePyvjQBdoiuY\
                     bmuD3Py0IyjlBxzZUXbqLsRL9gYFkCqeTY29Ik7usuzMTa+JRSLz6KGS\
                     5RSJ7CTSMjZg8aNaUbN2dvGhakJPh92HnLvMA3TefFgbKJphFNPA3BWS\
                     KLZ02cRWXqM="
                )
                .unwrap()
            ).unwrap()
            .key_tag(),
            59944
        );
        assert_eq!(
            Dnskey::new(
                257,
                3,
                SecAlg::RsaSha256,
                base64::decode::<Vec<u8>>(
                    "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTO\
                    iW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN\
                    7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5\
                    LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8\
                    efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7\
                    pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLY\
                    A4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws\
                    9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
                )
                .unwrap()
            )
            .unwrap()
            .key_tag(),
            20326
        );
        assert_eq!(
            Dnskey::new(
                257,
                3,
                SecAlg::RsaMd5,
                base64::decode::<Vec<u8>>(
                    "AwEAAcVaA4jSBIGRrSzpecoJELvKE9+OMuFnL8mmUBsY\
                    lB6epN1CqX7NzwjDpi6VySiEXr0C4uTYkU/L1uMv2mHE\
                    AljThFDJ1GuozJ6gA7jf3lnaGppRg2IoVQ9IVmLORmjw\
                    C+7Eoi12SqybMTicD3Ezwa9XbG1iPjmjhbMrLh7MSQpX"
                )
                .unwrap()
            )
            .unwrap()
            .key_tag(),
            18698
        );
    }

    #[test]
    fn dnskey_flags() {
        let dnskey =
            Dnskey::new(257, 3, SecAlg::RsaSha256, bytes::Bytes::new())
                .unwrap();
        assert!(dnskey.is_zsk());
        assert!(dnskey.is_secure_entry_point());
        assert!(!dnskey.is_revoked());
    }
}
