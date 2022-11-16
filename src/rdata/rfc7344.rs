//! Record data from [RFC 7344]: CDS and CDNSKEY records.
//!
//! [RFC 7344]: https://tools.ietf.org/html/rfc7344
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{DigestAlg, Rtype, SecAlg};
use crate::base::name::PushError;
use crate::base::octets::{
    Compose, Octets, OctetsBuilder, OctetsFrom, OctetsInto, Parse,
    ParseError, Parser, ShortBuf,
};
use crate::base::rdata::RtypeRecordData;
use crate::base::scan::{Scan, Scanner};
use crate::utils::{base16, base64};
use core::cmp::Ordering;
use core::{fmt, hash};

//------------ Cdnskey --------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: crate::base::octets::SerializeOctets + AsRef<[u8]>
        ",
        deserialize = "
            Octs:
                crate::base::octets::FromBuilder
                + crate::base::octets::DeserializeOctets<'de>,
            <Octs as crate::base::octets::FromBuilder>::Builder:
                OctetsBuilder<Octets = Octs>
                + crate::base::octets::EmptyBuilder,
        ",
    ))
)]
pub struct Cdnskey<Octs> {
    flags: u16,
    protocol: u8,
    algorithm: SecAlg,
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::utils::base64::serde")
    )]
    public_key: Octs,
}

impl<Octs> Cdnskey<Octs> {
    pub fn new(
        flags: u16,
        protocol: u8,
        algorithm: SecAlg,
        public_key: Octs,
    ) -> Self {
        Cdnskey {
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

    pub(super) fn convert_octets<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Cdnskey<Target>, Target::Error> {
        Ok(Cdnskey::new(
            self.flags,
            self.protocol,
            self.algorithm,
            self.public_key.try_octets_into()?,
        ))
    }
}

impl<SrcOcts> Cdnskey<SrcOcts> {
    pub fn flatten_into<Octs>(self) -> Result<Cdnskey<Octs>, PushError>
    where
        Octs: OctetsFrom<SrcOcts>,
        PushError: From<Octs::Error>,
    {
        let Self {
            flags,
            protocol,
            algorithm,
            public_key,
        } = self;
        Ok(Cdnskey::new(
            flags,
            protocol,
            algorithm,
            public_key.try_octets_into()?,
        ))
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Cdnskey<SrcOcts>> for Cdnskey<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: Cdnskey<SrcOcts>,
    ) -> Result<Self, Self::Error> {
        Ok(Cdnskey::new(
            source.flags,
            source.protocol,
            source.algorithm,
            Octs::try_octets_from(source.public_key)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Cdnskey<Other>> for Cdnskey<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Cdnskey<Other>) -> bool {
        self.flags == other.flags
            && self.protocol == other.protocol
            && self.algorithm == other.algorithm
            && self.public_key.as_ref() == other.public_key.as_ref()
    }
}

impl<Octs: AsRef<[u8]>> Eq for Cdnskey<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Cdnskey<Other>> for Cdnskey<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Cdnskey<Other>) -> Option<Ordering> {
        Some(self.canonical_cmp(other))
    }
}

impl<Octs, Other> CanonicalOrd<Cdnskey<Other>> for Cdnskey<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Cdnskey<Other>) -> Ordering {
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

impl<Octs: AsRef<[u8]>> Ord for Cdnskey<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for Cdnskey<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.flags.hash(state);
        self.protocol.hash(state);
        self.algorithm.hash(state);
        self.public_key.as_ref().hash(state);
    }
}

//--- ParseAll and Compose

impl<'a, Octs: Octets> Parse<'a, Octs> for Cdnskey<Octs::Range<'a>> {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let len = match parser.remaining().checked_sub(4) {
            Some(len) => len,
            None => return Err(ParseError::ShortInput),
        };
        Ok(Self::new(
            u16::parse(parser)?,
            u8::parse(parser)?,
            SecAlg::parse(parser)?,
            parser.parse_octets(len)?,
        ))
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        if parser.remaining() < 4 {
            return Err(ParseError::ShortInput);
        }
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Compose for Cdnskey<Octs> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.flags.compose(buf)?;
            self.protocol.compose(buf)?;
            self.algorithm.compose(buf)?;
            buf.append_slice(self.public_key.as_ref())
        })
    }
}

//--- Scan and Display

impl<Octs, S: Scanner<Octets = Octs>> Scan<S> for Cdnskey<Octs> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        Ok(Self::new(
            u16::scan(scanner)?,
            u8::scan(scanner)?,
            SecAlg::scan(scanner)?,
            scanner.convert_entry(base64::SymbolConverter::new())?,
        ))
    }
}

impl<Octs: AsRef<[u8]>> fmt::Display for Cdnskey<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.flags, self.protocol, self.algorithm)?;
        base64::display(&self.public_key, f)
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for Cdnskey<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Cdnskey")
            .field("flags", &self.flags)
            .field("protocol", &self.protocol)
            .field("algorithm", &self.algorithm)
            .field("public_key", &self.public_key.as_ref())
            .finish()
    }
}

//--- RecordData

impl<Octs> RtypeRecordData for Cdnskey<Octs> {
    const RTYPE: Rtype = Rtype::Cdnskey;
}

//------------ Cds -----------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: crate::base::octets::SerializeOctets + AsRef<[u8]>
        ",
        deserialize = "
            Octs:
                crate::base::octets::FromBuilder
                + crate::base::octets::DeserializeOctets<'de>,
            <Octs as crate::base::octets::FromBuilder>::Builder:
                OctetsBuilder<Octets = Octs>
                + crate::base::octets::EmptyBuilder,
        ",
    ))
)]
pub struct Cds<Octs> {
    key_tag: u16,
    algorithm: SecAlg,
    digest_type: DigestAlg,
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::utils::base64::serde")
    )]
    digest: Octs,
}

impl<Octs> Cds<Octs> {
    pub fn new(
        key_tag: u16,
        algorithm: SecAlg,
        digest_type: DigestAlg,
        digest: Octs,
    ) -> Self {
        Cds {
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
    ) -> Result<Cds<Target>, Target::Error> {
        Ok(Cds::new(
            self.key_tag,
            self.algorithm,
            self.digest_type,
            self.digest.try_octets_into()?,
        ))
    }
}

impl<SrcOcts> Cds<SrcOcts> {
    pub fn flatten_into<Octs>(self) -> Result<Cds<Octs>, PushError>
    where
        Octs: OctetsFrom<SrcOcts>,
        PushError: From<Octs::Error>,
    {
        let Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        } = self;
        Ok(Cds::new(
            key_tag,
            algorithm,
            digest_type,
            digest.try_octets_into()?,
        ))
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Cds<SrcOcts>> for Cds<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Cds<SrcOcts>) -> Result<Self, Self::Error> {
        Ok(Cds::new(
            source.key_tag,
            source.algorithm,
            source.digest_type,
            Octs::try_octets_from(source.digest)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Cds<Other>> for Cds<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Cds<Other>) -> bool {
        self.key_tag == other.key_tag
            && self.algorithm == other.algorithm
            && self.digest_type == other.digest_type
            && self.digest.as_ref().eq(other.digest.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> Eq for Cds<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Cds<Other>> for Cds<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Cds<Other>) -> Option<Ordering> {
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

impl<Octs, Other> CanonicalOrd<Cds<Other>> for Cds<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Cds<Other>) -> Ordering {
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

impl<Octs: AsRef<[u8]>> Ord for Cds<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for Cds<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.key_tag.hash(state);
        self.algorithm.hash(state);
        self.digest_type.hash(state);
        self.digest.as_ref().hash(state);
    }
}

//--- Parse and Compose

impl<'a, Octs: Octets> Parse<'a, Octs> for Cds<Octs::Range<'a>> {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let len = match parser.remaining().checked_sub(4) {
            Some(len) => len,
            None => return Err(ParseError::ShortInput),
        };
        Ok(Self::new(
            u16::parse(parser)?,
            SecAlg::parse(parser)?,
            DigestAlg::parse(parser)?,
            parser.parse_octets(len)?,
        ))
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        if parser.remaining() < 4 {
            return Err(ParseError::ShortInput);
        }
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octs: AsRef<[u8]>> Compose for Cds<Octs> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.key_tag.compose(buf)?;
            self.algorithm.compose(buf)?;
            self.digest_type.compose(buf)?;
            buf.append_slice(self.digest.as_ref())
        })
    }
}

//--- Scan and Display

impl<Octs, S: Scanner<Octets = Octs>> Scan<S> for Cds<Octs> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        Ok(Self::new(
            u16::scan(scanner)?,
            SecAlg::scan(scanner)?,
            DigestAlg::scan(scanner)?,
            scanner.convert_entry(base16::SymbolConverter::new())?,
        ))
    }
}

impl<Octs: AsRef<[u8]>> fmt::Display for Cds<Octs> {
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

impl<Octs: AsRef<[u8]>> fmt::Debug for Cds<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Cds")
            .field("key_tag", &self.key_tag)
            .field("algorithm", &self.algorithm)
            .field("digest_type", &self.digest_type)
            .field("digest", &self.digest.as_ref())
            .finish()
    }
}

//--- RtypeRecordData

impl<Octs> RtypeRecordData for Cds<Octs> {
    const RTYPE: Rtype = Rtype::Cds;
}

//------------ parsed --------------------------------------------------------

pub mod parsed {
    pub use super::{Cdnskey, Cds};
}
