//! Record data from [RFC 7344]: CDS and CDNSKEY records.
//!
//! [RFC 7344]: https://tools.ietf.org/html/rfc7344
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{DigestAlg, Rtype, SecAlg};
use crate::base::octets::{
    Compose, OctetsBuilder, OctetsFrom, OctetsRef, Parse, ParseError, Parser,
    ShortBuf,
};
use crate::base::rdata::RtypeRecordData;
use crate::base::scan::{Scan, Scanner};
#[cfg(feature = "master")]
use crate::master::scan::{self as old_scan, CharSource, ScanError};
use crate::utils::{base16, base64};
use crate::try_opt;
#[cfg(feature = "master")]
use bytes::Bytes;
use core::cmp::Ordering;
use core::{fmt, hash};

//------------ Cdnskey --------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octets: crate::base::octets::SerializeOctets + AsRef<[u8]>
        ",
        deserialize = "
            Octets:
                crate::base::octets::FromBuilder
                + crate::base::octets::DeserializeOctets<'de>,
            <Octets as crate::base::octets::FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets>
                + crate::base::octets::EmptyBuilder,
        ",
    ))
)]
pub struct Cdnskey<Octets> {
    flags: u16,
    protocol: u8,
    algorithm: SecAlg,
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::utils::base64::serde")
    )]
    public_key: Octets,
}

impl<Octets> Cdnskey<Octets> {
    pub fn new(
        flags: u16,
        protocol: u8,
        algorithm: SecAlg,
        public_key: Octets,
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

    pub fn public_key(&self) -> &Octets {
        &self.public_key
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets> OctetsFrom<Cdnskey<SrcOctets>> for Cdnskey<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: Cdnskey<SrcOctets>) -> Result<Self, ShortBuf> {
        Ok(Cdnskey::new(
            source.flags,
            source.protocol,
            source.algorithm,
            Octets::octets_from(source.public_key)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Cdnskey<Other>> for Cdnskey<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Cdnskey<Other>) -> bool {
        self.flags == other.flags
            && self.protocol == other.protocol
            && self.algorithm == other.algorithm
            && self.public_key.as_ref() == other.public_key.as_ref()
    }
}

impl<Octets: AsRef<[u8]>> Eq for Cdnskey<Octets> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Cdnskey<Other>> for Cdnskey<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Cdnskey<Other>) -> Option<Ordering> {
        Some(self.canonical_cmp(other))
    }
}

impl<Octets, Other> CanonicalOrd<Cdnskey<Other>> for Cdnskey<Octets>
where
    Octets: AsRef<[u8]>,
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

impl<Octets: AsRef<[u8]>> Ord for Cdnskey<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}

//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for Cdnskey<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.flags.hash(state);
        self.protocol.hash(state);
        self.algorithm.hash(state);
        self.public_key.as_ref().hash(state);
    }
}

//--- ParseAll and Compose

impl<Ref: OctetsRef> Parse<Ref> for Cdnskey<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
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

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        if parser.remaining() < 4 {
            return Err(ParseError::ShortInput);
        }
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for Cdnskey<Octets> {
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

impl<Octets, S: Scanner<Octets = Octets>> Scan<S> for Cdnskey<Octets> {
    fn scan_opt(scanner: &mut S) -> Result<Option<Self>, S::Error> {
        Ok(Some(Self::new(
            try_opt!(u16::scan_opt(scanner)),
            u8::scan(scanner)?,
            SecAlg::scan(scanner)?,
            scanner.convert_entry(base64::SymbolConverter::new())?,
        )))
    }
}

#[cfg(feature = "master")]
impl old_scan::Scan for Cdnskey<Bytes> {
    fn scan<C: CharSource>(
        scanner: &mut old_scan::Scanner<C>,
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            <u16 as old_scan::Scan>::scan(scanner)?,
            <u8 as old_scan::Scan>::scan(scanner)?,
            <SecAlg as old_scan::Scan>::scan(scanner)?,
            scanner.scan_base64_phrases(Ok)?,
        ))
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for Cdnskey<Octets> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} ", self.flags, self.protocol, self.algorithm)?;
        base64::display(&self.public_key, f)
    }
}

//--- Debug

impl<Octets: AsRef<[u8]>> fmt::Debug for Cdnskey<Octets> {
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

impl<Octets> RtypeRecordData for Cdnskey<Octets> {
    const RTYPE: Rtype = Rtype::Cdnskey;
}

//------------ Cds -----------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octets: crate::base::octets::SerializeOctets + AsRef<[u8]>
        ",
        deserialize = "
            Octets:
                crate::base::octets::FromBuilder
                + crate::base::octets::DeserializeOctets<'de>,
            <Octets as crate::base::octets::FromBuilder>::Builder:
                OctetsBuilder<Octets = Octets>
                + crate::base::octets::EmptyBuilder,
        ",
    ))
)]
pub struct Cds<Octets> {
    key_tag: u16,
    algorithm: SecAlg,
    digest_type: DigestAlg,
    #[cfg_attr(
        feature = "serde",
        serde(with = "crate::utils::base64::serde")
    )]
    digest: Octets,
}

impl<Octets> Cds<Octets> {
    pub fn new(
        key_tag: u16,
        algorithm: SecAlg,
        digest_type: DigestAlg,
        digest: Octets,
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

    pub fn digest(&self) -> &Octets {
        &self.digest
    }

    pub fn into_digest(self) -> Octets {
        self.digest
    }
}

//--- OctetsFrom

impl<Octets, SrcOctets> OctetsFrom<Cds<SrcOctets>> for Cds<Octets>
where
    Octets: OctetsFrom<SrcOctets>,
{
    fn octets_from(source: Cds<SrcOctets>) -> Result<Self, ShortBuf> {
        Ok(Cds::new(
            source.key_tag,
            source.algorithm,
            source.digest_type,
            Octets::octets_from(source.digest)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octets, Other> PartialEq<Cds<Other>> for Cds<Octets>
where
    Octets: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Cds<Other>) -> bool {
        self.key_tag == other.key_tag
            && self.algorithm == other.algorithm
            && self.digest_type == other.digest_type
            && self.digest.as_ref().eq(other.digest.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> Eq for Cds<Octets> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octets, Other> PartialOrd<Cds<Other>> for Cds<Octets>
where
    Octets: AsRef<[u8]>,
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

impl<Octets, Other> CanonicalOrd<Cds<Other>> for Cds<Octets>
where
    Octets: AsRef<[u8]>,
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

impl<Octets: AsRef<[u8]>> Ord for Cds<Octets> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.canonical_cmp(other)
    }
}

//--- Hash

impl<Octets: AsRef<[u8]>> hash::Hash for Cds<Octets> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.key_tag.hash(state);
        self.algorithm.hash(state);
        self.digest_type.hash(state);
        self.digest.as_ref().hash(state);
    }
}

//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Cds<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
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

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        if parser.remaining() < 4 {
            return Err(ParseError::ShortInput);
        }
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets: AsRef<[u8]>> Compose for Cds<Octets> {
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

impl<Octets, S: Scanner<Octets = Octets>> Scan<S> for Cds<Octets> {
    fn scan_opt(scanner: &mut S) -> Result<Option<Self>, S::Error> {
        Ok(Some(Self::new(
            try_opt!(u16::scan_opt(scanner)),
            SecAlg::scan(scanner)?,
            DigestAlg::scan(scanner)?,
            scanner.convert_entry(base16::SymbolConverter::new())?,
        )))
    }
}

#[cfg(feature = "master")]
impl old_scan::Scan for Cds<Bytes> {
    fn scan<C: CharSource>(
        scanner: &mut old_scan::Scanner<C>,
    ) -> Result<Self, ScanError> {
        Ok(Self::new(
            <u16 as old_scan::Scan>::scan(scanner)?,
            <SecAlg as old_scan::Scan>::scan(scanner)?,
            <DigestAlg as old_scan::Scan>::scan(scanner)?,
            scanner.scan_hex_words(Ok)?,
        ))
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for Cds<Octets> {
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

impl<Octets: AsRef<[u8]>> fmt::Debug for Cds<Octets> {
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

impl<Octets> RtypeRecordData for Cds<Octets> {
    const RTYPE: Rtype = Rtype::Cds;
}

//------------ parsed --------------------------------------------------------

pub mod parsed {
    pub use super::{Cdnskey, Cds};
}
