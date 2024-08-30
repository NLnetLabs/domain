//! Record data from [RFC 7344]: CDS and CDNSKEY records.
//!
//! [RFC 7344]: https://tools.ietf.org/html/rfc7344
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::{DigestAlg, Rtype, SecAlg};
use crate::base::rdata::{
    ComposeRecordData, LongRecordData, ParseRecordData, RecordData
};
use crate::base::scan::{Scan, Scanner, ScannerError};
use crate::base::wire::{Compose, Composer, Parse, ParseError};
use crate::utils::{base16, base64};
use crate::zonefile::present::{Present, ZoneFileFormatter};
use core::cmp::Ordering;
use core::{fmt, hash};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;

//------------ Cdnskey --------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: octseq::serde::SerializeOctets + AsRef<[u8]>
        ",
        deserialize = "
            Octs:
                octseq::builder::FromBuilder
                + octseq::serde::DeserializeOctets<'de>,
            <Octs as octseq::builder::FromBuilder>::Builder:
                octseq::builder::OctetsBuilder 
                + octseq::builder::EmptyBuilder,
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

impl Cdnskey<()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::CDNSKEY;
}

impl<Octs> Cdnskey<Octs> {
    pub fn new(
        flags: u16,
        protocol: u8,
        algorithm: SecAlg,
        public_key: Octs,
    ) -> Result<Self, LongRecordData>
    where Octs: AsRef<[u8]> {
        LongRecordData::check_len(
            usize::from(
                u16::COMPOSE_LEN + u8::COMPOSE_LEN + SecAlg::COMPOSE_LEN
            ).checked_add(public_key.as_ref().len()).expect("long key")
        )?;
        Ok(unsafe {
            Cdnskey::new_unchecked(flags, protocol, algorithm, public_key)
        })
    }

    /// Creates new CDNSKEY record data without checking.
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
        Ok(unsafe {
            Cdnskey::new_unchecked(
                self.flags,
                self.protocol,
                self.algorithm,
                self.public_key.try_octets_into()?,
            )
        })
    }

    pub(super) fn flatten<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Cdnskey<Target>, Target::Error> {
        self.convert_octets()
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
    where Octs: AsRef<[u8]> {
        Self::new(
            u16::scan(scanner)?,
            u8::scan(scanner)?,
            SecAlg::scan(scanner)?,
            scanner.convert_entry(base64::SymbolConverter::new())?,
        ).map_err(|err| S::Error::custom(err.as_str()))
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
        Ok(unsafe {
            Cdnskey::new_unchecked(
                source.flags,
                source.protocol,
                source.algorithm,
                Octs::try_octets_from(source.public_key)?,
            )
        })
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

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs> RecordData for Cdnskey<Octs> {
    fn rtype(&self) -> Rtype {
        Cdnskey::RTYPE
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Cdnskey<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Cdnskey::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Cdnskey<Octs> {
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

//--- Present

impl<Octs: AsRef<[u8]>> Present for Cdnskey<Octs> {
    fn present(&self, f: &mut ZoneFileFormatter) -> fmt::Result {
        use std::fmt::Write;
        write!(f, "{} {} ", self.flags, self.protocol)?;
        self.algorithm.present(f)?;
        f.write_char(' ')?;
        base64::display(&self.public_key, f)
    }
}

//------------ Cds -----------------------------------------------------------

#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: octseq::serde::SerializeOctets + AsRef<[u8]>
        ",
        deserialize = "
            Octs:
                octseq::builder::FromBuilder
                + octseq::serde::DeserializeOctets<'de>,
            <Octs as octseq::builder::FromBuilder>::Builder:
                octseq::builder::OctetsBuilder
                + octseq::builder::EmptyBuilder,
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

impl Cds<()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::CDS;
}

impl<Octs> Cds<Octs> {
    pub fn new(
        key_tag: u16,
        algorithm: SecAlg,
        digest_type: DigestAlg,
        digest: Octs,
    ) -> Result<Self, LongRecordData>
    where Octs: AsRef<[u8]> {
        LongRecordData::check_len(
            usize::from(
                u16::COMPOSE_LEN + SecAlg::COMPOSE_LEN + DigestAlg::COMPOSE_LEN
            ).checked_add(digest.as_ref().len()).expect("long digest")
        )?;
        Ok(unsafe {
            Cds::new_unchecked(key_tag, algorithm, digest_type, digest)
        })
    }

    /// Creates new CDS record data without checking.
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
        Ok(unsafe {
            Cds::new_unchecked(
                self.key_tag,
                self.algorithm,
                self.digest_type,
                self.digest.try_octets_into()?,
            )
        })
    }

    pub(super) fn flatten<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Cds<Target>, Target::Error> {
        self.convert_octets()
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
    where Octs: AsRef<[u8]> {
        Self::new(
            u16::scan(scanner)?,
            SecAlg::scan(scanner)?,
            DigestAlg::scan(scanner)?,
            scanner.convert_entry(base16::SymbolConverter::new())?,
        ).map_err(|err| S::Error::custom(err.as_str()))
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Cds<SrcOcts>> for Cds<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Cds<SrcOcts>) -> Result<Self, Self::Error> {
        Ok(unsafe {
            Cds::new_unchecked(
                source.key_tag,
                source.algorithm,
                source.digest_type,
                Octs::try_octets_from(source.digest)?,
            )
        })
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

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs> RecordData for Cds<Octs> {
    fn rtype(&self) -> Rtype {
        Cds::RTYPE
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Cds<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Cds::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Cds<Octs> {
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

//--- Present

impl<Octs: AsRef<[u8]>> Present for Cds<Octs> {
    fn present(&self, f: &mut ZoneFileFormatter) -> fmt::Result {
        use std::fmt::Write;
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

//------------ parsed --------------------------------------------------------

pub mod parsed {
    pub use super::{Cdnskey, Cds};
}

//============ Test ==========================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };

    //--- Cdnskey

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn cdnskey_compose_parse_scan() {
        let rdata = Cdnskey::new(10, 11, SecAlg::RSASHA1, b"key").unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Cdnskey::parse(parser));
        test_scan(&["10", "11", "RSASHA1", "a2V5"], Cdnskey::scan, &rdata);
    }

    //--- Cds

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn cds_compose_parse_scan() {
        let rdata = Cds::new(
            10, SecAlg::RSASHA1, DigestAlg::SHA256, b"key"
        ).unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Cds::parse(parser));
        test_scan(&["10", "RSASHA1", "2", "6b6579"], Cds::scan, &rdata);
    }
}
