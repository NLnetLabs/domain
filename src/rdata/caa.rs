//! Record data from [RFC 8659]: CAA records.
//!
//! This RFC defines the CAA record type.
//!
//! [RFC 8659]: https://www.rfc-editor.org/info/rfc8659

use crate::base::{
    name::FlattenInto,
    rdata::ComposeRecordData,
    scan::{Scan, Scanner},
    wire::{Compose, Parse, ParseError},
    zonefile_fmt::{self, Formatter, ZonefileFmt},
    CanonicalOrd, CharStr, ParseRecordData, RecordData, Rtype,
};
use core::{cmp::Ordering, fmt, hash};
#[cfg(feature = "serde")]
use octseq::{
    builder::{EmptyBuilder, FromBuilder, OctetsBuilder},
    serde::DeserializeOctets,
    serde::SerializeOctets,
};
use octseq::{Octets, OctetsFrom, OctetsInto, Parser};

//------------ Caa ---------------------------------------------------------

/// Caa record data.
///
/// The Certification Authority Authorization (CAA) DNS Resource Record allows
/// a DNS domain name holder to specify one or more Certification Authorities
/// (CAs) authorized to issue certificates for that domain name.
///
/// CAA Resource Records allow a public CA to implement additional controls to reduce the
/// risk of unintended certificate mis-issue.
///
/// The Caa record type is defined in [RFC 8659, section 4.1][1].
///
/// [1]: https://www.rfc-editor.org/rfc/rfc8659#section-4.1
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "
            Octs: SerializeOctets + AsRef<[u8]>
        ",
        deserialize = "
            Octs: FromBuilder + DeserializeOctets<'de>,
            <Octs as FromBuilder>::Builder:
                OctetsBuilder + EmptyBuilder
                + AsRef<[u8]>,
        ",
    ))
)]
pub struct Caa<Octs> {
    flags: u8,
    tag: CharStr<Octs>,
    #[cfg_attr(
        feature = "serde",
        serde(
            serialize_with = "octseq::serde::SerializeOctets::serialize_octets",
            deserialize_with = "octseq::serde::DeserializeOctets::deserialize_octets",
            bound(
                serialize = "Octs: octseq::serde::SerializeOctets",
                deserialize = "Octs: octseq::serde::DeserializeOctets<'de>",
            )
        )
    )]
    value: Octs,
}

impl Caa<()> {
    // The rtype of this record data type.
    pub const RTYPE: Rtype = Rtype::CAA;
}

impl<Octs> Caa<Octs> {
    /// Creates a new CAA record data from the flags, tag, and value.
    pub fn new(flags: u8, tag: CharStr<Octs>, value: Octs) -> Self {
        Caa { flags, tag, value }
    }

    /// If the value is set to "1", the Property is critical.
    /// A CA MUST NOT issue certificates for any FQDN if the
    /// Relevant RRset for that FQDN contains a CAA critical
    /// Property for an unknown or unsupported Property Tag.
    pub fn flags(&self) -> u8 {
        self.flags
    }

    /// The Property identifier
    pub fn tag(&self) -> &CharStr<Octs> {
        &self.tag
    }

    /// The Property Value
    pub fn value(&self) -> &Octs {
        &self.value
    }

    pub(in crate::rdata) fn convert_octets<TOcts: OctetsFrom<Octs>>(
        self,
    ) -> Result<Caa<TOcts>, TOcts::Error> {
        Ok(Caa::new(
            self.flags,
            self.tag.try_octets_into()?,
            self.value.try_octets_into()?,
        ))
    }

    pub(in crate::rdata) fn flatten<TOcts: OctetsFrom<Octs>>(
        self,
    ) -> Result<Caa<TOcts>, TOcts::Error> {
        self.convert_octets()
    }

    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(
            u8::scan(scanner)?,
            CharStr::scan(scanner)?,
            scanner.scan_octets()?,
        ))
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            u8::parse(parser)?,
            CharStr::parse(parser)?,
            parser.parse_octets(parser.remaining())?,
        ))
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Caa<SrcOcts>> for Caa<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Caa<SrcOcts>) -> Result<Self, Self::Error> {
        Ok(Caa {
            flags: source.flags,
            tag: CharStr::try_octets_from(source.tag)?,
            value: Octs::try_octets_from(source.value)?,
        })
    }
}

//--- FlattenInto

impl<Octs, TOcts> FlattenInto<Caa<TOcts>> for Caa<Octs>
where
    TOcts: OctetsFrom<Octs>,
{
    type AppendError = TOcts::Error;

    fn try_flatten_into(self) -> Result<Caa<TOcts>, Self::AppendError> {
        self.flatten()
    }
}

//--- PartialEq and Eq

impl<Octs, OtherOcts> PartialEq<Caa<OtherOcts>> for Caa<Octs>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
{
    fn eq(&self, other: &Caa<OtherOcts>) -> bool {
        self.flags == other.flags
            && self.tag.eq(&other.tag)
            && self.value.as_ref().eq(other.value.as_ref())
    }
}

impl<O: AsRef<[u8]>> Eq for Caa<O> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<Octs, OtherOcts> PartialOrd<Caa<OtherOcts>> for Caa<Octs>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Caa<OtherOcts>) -> Option<Ordering> {
        match self.flags.partial_cmp(&other.flags) {
            Some(Ordering::Equal) => (),
            other => return other,
        }
        match self.tag.partial_cmp(&other.tag) {
            Some(Ordering::Equal) => (),
            other => return other,
        }
        self.value.as_ref().partial_cmp(other.value.as_ref())
    }
}

impl<Octs, OtherOcts> CanonicalOrd<Caa<OtherOcts>> for Caa<Octs>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Caa<OtherOcts>) -> Ordering {
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => (),
            ord => return ord,
        }
        match self.tag.canonical_cmp(&other.tag) {
            Ordering::Equal => (),
            ord => return ord,
        }
        self.value.as_ref().cmp(other.value.as_ref())
    }
}

impl<O: AsRef<[u8]>> Ord for Caa<O> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => (),
            ord => return ord,
        }
        match self.tag.cmp(&other.tag) {
            Ordering::Equal => (),
            ord => return ord,
        }
        self.value.as_ref().cmp(other.value.as_ref())
    }
}

//--- Hash

impl<O: AsRef<[u8]>> hash::Hash for Caa<O> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.flags.hash(state);
        self.tag.hash(state);
        self.value.as_ref().hash(state);
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs> RecordData for Caa<Octs> {
    fn rtype(&self) -> Rtype {
        Caa::RTYPE
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Caa<Octs::Range<'a>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut octseq::Parser<'a, Octs>,
    ) -> Result<Option<Self>, crate::base::wire::ParseError> {
        if rtype == Caa::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Caa<Octs>
where
    Octs: AsRef<[u8]>,
{
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            u8::COMPOSE_LEN
                .checked_add(self.tag.compose_len())
                .expect("long tag")
                .checked_add(
                    u16::try_from(self.value.as_ref().len())
                        .expect("long value"),
                )
                .expect("long value"),
        )
    }

    fn compose_rdata<Target: crate::base::wire::Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.flags.compose(target)?;
        self.tag.compose(target)?;
        target.append_slice(self.value.as_ref())
    }

    fn compose_canonical_rdata<
        Target: crate::base::wire::Composer + ?Sized,
    >(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.flags.compose(target)?;
        self.tag.compose(target)?;
        target.append_slice(self.value.as_ref())
    }
}

//--- Display

impl<O: AsRef<[u8]>> fmt::Display for Caa<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.flags,
            self.tag,
            unsafe { CharStr::from_octets_unchecked(&self.value) }
                .display_quoted()
        )
    }
}

//--- Debug

impl<O: AsRef<[u8]>> fmt::Debug for Caa<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Caa")
            .field("flags", &self.flags)
            .field("tag", &self.tag)
            .field("value", &unsafe {
                CharStr::from_octets_unchecked(&self.value)
            })
            .finish()
    }
}

//--- ZonefileFmt

impl<O: AsRef<[u8]>> ZonefileFmt for Caa<O> {
    fn fmt(&self, p: &mut impl Formatter) -> zonefile_fmt::Result {
        p.block(|p| {
            p.write_token(self.flags)?;
            p.write_comment("flags")?;
            p.write_token(&self.tag)?;
            p.write_comment("tag")?;
            p.write_token(
                unsafe { CharStr::from_octets_unchecked(&self.value) }
                    .display_quoted(),
            )?;
            p.write_comment("value")
        })
    }
}

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::std::string::ToString;
    use std::vec::Vec;

    #[test]
    fn caa_eq() {
        let caa1: Caa<Vec<u8>> = Caa::new(
            0,
            "ISSUE".parse().unwrap(),
            "ca.example.net".as_bytes().to_vec(),
        );
        let caa2: Caa<Vec<u8>> = Caa::new(
            0,
            "issue".parse().unwrap(),
            "ca.example.net".as_bytes().to_vec(),
        );
        assert_eq!(caa1, caa2);
    }

    #[test]
    fn caa_octets_info() {
        let caa: Caa<Vec<u8>> = Caa::new(
            0,
            "issue".parse().unwrap(),
            "ca.example.net".as_bytes().to_vec(),
        );
        let caa_bytes: Caa<bytes::Bytes> = caa.clone().octets_into();
        assert_eq!(caa.flags, caa_bytes.flags);
        assert_eq!(caa.tag, caa_bytes.tag);
        assert_eq!(caa.value, caa_bytes.value);
    }

    #[test]
    fn caa_display() {
        let caa: Caa<Vec<u8>> = Caa::new(
            0,
            "issue".parse().unwrap(),
            "ca.example.net".as_bytes().to_vec(),
        );

        assert_eq!(caa.to_string(), r#"0 issue "ca.example.net""#);
    }
}
