//! Record data from [RFC 3403]: NAPTR records.
//!
//! This RFC defines the NAPTR record type.
//!
//! [RFC 3403]: https://www.rfc-editor.org/info/rfc3403

use crate::base::{
    name::FlattenInto,
    rdata::ComposeRecordData,
    scan::{Scan, Scanner},
    wire::{Compose, Parse, ParseError},
    zonefile_fmt::{self, Formatter, ZonefileFmt},
    CanonicalOrd, CharStr, ParseRecordData, ParsedName, RecordData, Rtype,
    ToName,
};
use core::{cmp::Ordering, fmt, hash};
#[cfg(feature = "serde")]
use octseq::builder::{EmptyBuilder, FromBuilder, OctetsBuilder};
use octseq::{Octets, OctetsFrom, OctetsInto, Parser};

//------------ Naptr ---------------------------------------------------------

/// Naptr record data.
///
/// The Naptr encodes DNS rules for URI delegation, allowing changes and redelegation.
/// It uses regex for string-to-domain name conversion, chosen for compactness and
/// expressivity in small DNS packets.
///
/// The Naptr record type is defined in [RFC 3403, section 4.1][1].
///
/// [1]: https://www.rfc-editor.org/rfc/rfc3403#section-4.1
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
                OctetsBuilder + EmptyBuilder
                + AsRef<[u8]> + AsMut<[u8]>,
            Name: serde::Deserialize<'de>,
        ",
    ))
)]
pub struct Naptr<Octs, Name> {
    order: u16,
    preference: u16,
    flags: CharStr<Octs>,
    services: CharStr<Octs>,
    regexp: CharStr<Octs>,
    replacement: Name,
}

impl Naptr<(), ()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::NAPTR;
}

impl<Octs, Name> Naptr<Octs, Name> {
    /// Creates a new Naptr record data from content.
    pub fn new(
        order: u16,
        preference: u16,
        flags: CharStr<Octs>,
        services: CharStr<Octs>,
        regexp: CharStr<Octs>,
        replacement: Name,
    ) -> Self {
        Naptr {
            order,
            preference,
            flags,
            services,
            regexp,
            replacement,
        }
    }

    /// The order of processing the records is from lowest to highest.
    /// If two records have the same order value, they should be processed
    /// according to their preference value and services field.
    pub fn order(&self) -> u16 {
        self.order
    }

    /// The priority of the DDDS Algorithm, from lowest to highest.
    pub fn preference(&self) -> u16 {
        self.preference
    }

    /// The flags controls aspects of the rewriting and interpretation of
    /// the fields in the record.
    pub fn flags(&self) -> &CharStr<Octs> {
        &self.flags
    }

    /// The services specify the Service Parameters applicable to
    /// this delegation path.
    pub fn services(&self) -> &CharStr<Octs> {
        &self.services
    }

    /// The regexp containing a substitution expression that is
    /// applied to the original string held by the client in order to
    /// construct the next domain name to lookup.
    pub fn regexp(&self) -> &CharStr<Octs> {
        &self.regexp
    }

    /// The replacement is the next domain name to query for,
    /// depending on the potential values found in the flags field.
    pub fn replacement(&self) -> &Name {
        &self.replacement
    }

    pub(in crate::rdata) fn convert_octets<TOcts, TName>(
        self,
    ) -> Result<Naptr<TOcts, TName>, TOcts::Error>
    where
        TOcts: OctetsFrom<Octs>,
        TName: OctetsFrom<Name, Error = TOcts::Error>,
    {
        Ok(Naptr::new(
            self.order,
            self.preference,
            self.flags.try_octets_into()?,
            self.services.try_octets_into()?,
            self.regexp.try_octets_into()?,
            self.replacement.try_octets_into()?,
        ))
    }

    pub(in crate::rdata) fn flatten<TOcts, TName>(
        self,
    ) -> Result<Naptr<TOcts, TName>, TOcts::Error>
    where
        TOcts: OctetsFrom<Octs>,
        Name: FlattenInto<TName, AppendError = TOcts::Error>,
    {
        Ok(Naptr::new(
            self.order,
            self.preference,
            CharStr::try_octets_into(self.flags)?,
            CharStr::try_octets_into(self.services)?,
            CharStr::try_octets_into(self.regexp)?,
            Name::try_flatten_into(self.replacement)?,
        ))
    }

    pub fn scan<S: Scanner<Octets = Octs, Name = Name>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(
            u16::scan(scanner)?,
            u16::scan(scanner)?,
            scanner.scan_charstr()?,
            scanner.scan_charstr()?,
            scanner.scan_charstr()?,
            scanner.scan_name()?,
        ))
    }
}

impl<Octs: AsRef<[u8]>> Naptr<Octs, ParsedName<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut octseq::Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            u16::parse(parser)?,
            u16::parse(parser)?,
            CharStr::parse(parser)?,
            CharStr::parse(parser)?,
            CharStr::parse(parser)?,
            ParsedName::parse(parser)?,
        ))
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts, Name, SrcName> OctetsFrom<Naptr<SrcOcts, SrcName>>
    for Naptr<Octs, Name>
where
    Octs: OctetsFrom<SrcOcts>,
    Name: OctetsFrom<SrcName, Error = Octs::Error>,
{
    type Error = Octs::Error;

    fn try_octets_from(
        source: Naptr<SrcOcts, SrcName>,
    ) -> Result<Self, Self::Error> {
        Ok(Naptr::new(
            source.order,
            source.preference,
            CharStr::try_octets_from(source.flags)?,
            CharStr::try_octets_from(source.services)?,
            CharStr::try_octets_from(source.regexp)?,
            Name::try_octets_from(source.replacement)?,
        ))
    }
}

//--- FlattenInto

impl<Octs, TOcts, Name, TName> FlattenInto<Naptr<TOcts, TName>>
    for Naptr<Octs, Name>
where
    TOcts: OctetsFrom<Octs>,
    Name: FlattenInto<TName, AppendError = TOcts::Error>,
{
    type AppendError = TOcts::Error;

    fn try_flatten_into(self) -> Result<Naptr<TOcts, TName>, TOcts::Error> {
        self.flatten()
    }
}

//--- PartialEq and Eq

impl<Octs, OtherOcts, Name, OtherName> PartialEq<Naptr<OtherOcts, OtherName>>
    for Naptr<Octs, Name>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
    Name: ToName,
    OtherName: ToName,
{
    fn eq(&self, other: &Naptr<OtherOcts, OtherName>) -> bool {
        self.order == other.order
            && self.preference == other.preference
            && self.flags.eq(&other.flags)
            && self.services.eq(&other.services)
            && self.regexp.eq(&other.regexp)
            && self.replacement.name_eq(&other.replacement)
    }
}

impl<Octs: AsRef<[u8]>, Name: ToName> Eq for Naptr<Octs, Name> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<Octs, OtherOcts, Name, OtherName> PartialOrd<Naptr<OtherOcts, OtherName>>
    for Naptr<Octs, Name>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
    Name: ToName,
    OtherName: ToName,
{
    fn partial_cmp(
        &self,
        other: &Naptr<OtherOcts, OtherName>,
    ) -> Option<Ordering> {
        match self.order.partial_cmp(&other.order) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.preference.partial_cmp(&other.preference) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.flags.partial_cmp(&other.flags) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.services.partial_cmp(&other.services) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.regexp.partial_cmp(&other.regexp) {
            Some(Ordering::Equal) => {}
            other => return other,
        }

        Some(self.replacement.name_cmp(&other.replacement))
    }
}

impl<Octs, OtherOcts, Name, OtherName>
    CanonicalOrd<Naptr<OtherOcts, OtherName>> for Naptr<Octs, Name>
where
    Octs: AsRef<[u8]>,
    OtherOcts: AsRef<[u8]>,
    Name: ToName,
    OtherName: ToName,
{
    fn canonical_cmp(&self, other: &Naptr<OtherOcts, OtherName>) -> Ordering {
        match self.order.cmp(&other.order) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.preference.cmp(&other.preference) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.flags.canonical_cmp(&other.flags) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.services.canonical_cmp(&other.services) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.regexp.canonical_cmp(&other.regexp) {
            Ordering::Equal => {}
            other => return other,
        }

        self.replacement.lowercase_composed_cmp(&other.replacement)
    }
}

impl<Octs, Name> Ord for Naptr<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: ToName,
{
    fn cmp(&self, other: &Self) -> Ordering {
        match self.order.cmp(&other.order) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.preference.cmp(&other.preference) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.flags.cmp(&other.flags) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.services.cmp(&other.services) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.regexp.cmp(&other.regexp) {
            Ordering::Equal => {}
            other => return other,
        }

        self.replacement.name_cmp(&other.replacement)
    }
}

//--- Hash

impl<Octs, Name> hash::Hash for Naptr<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: hash::Hash,
{
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.order.hash(state);
        self.preference.hash(state);
        self.flags.hash(state);
        self.services.hash(state);
        self.regexp.hash(state);
        self.replacement.hash(state);
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs, Name> RecordData for Naptr<Octs, Name> {
    fn rtype(&self) -> Rtype {
        Naptr::RTYPE
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Naptr<Octs::Range<'a>, ParsedName<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Naptr::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs, Name> ComposeRecordData for Naptr<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: ToName,
{
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(
            (u16::COMPOSE_LEN + u16::COMPOSE_LEN)
                .checked_add(self.flags.compose_len())
                .expect("flags too long")
                .checked_add(self.services.compose_len())
                .expect("services too long")
                .checked_add(self.regexp.compose_len())
                .expect("regexp too long")
                .checked_add(self.replacement.compose_len())
                .expect("replacement too long"),
        )
    }

    fn compose_rdata<Target: crate::base::wire::Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_head(target)?;
        self.replacement.compose(target)
    }

    fn compose_canonical_rdata<
        Target: crate::base::wire::Composer + ?Sized,
    >(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_head(target)?;
        self.replacement.compose_canonical(target)
    }
}

impl<Octs, Name> Naptr<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: ToName,
{
    fn compose_head<Target: crate::base::wire::Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.order.compose(target)?;
        self.preference.compose(target)?;
        self.flags.compose(target)?;
        self.services.compose(target)?;
        self.regexp.compose(target)
    }
}

//--- Display

impl<Octs, Name> core::fmt::Display for Naptr<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {}.",
            self.order,
            self.preference,
            self.flags.display_quoted(),
            self.services.display_quoted(),
            self.regexp.display_quoted(),
            self.replacement
        )
    }
}

//--- Debug

impl<Octs, Name> core::fmt::Debug for Naptr<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Naptr")
            .field("order", &self.order)
            .field("preference", &self.preference)
            .field("flags", &self.flags)
            .field("services", &self.services)
            .field("regexp", &self.regexp)
            .field("replacement", &self.replacement)
            .finish()
    }
}

//--- ZonefileFmt

impl<Octs, Name> ZonefileFmt for Naptr<Octs, Name>
where
    Octs: AsRef<[u8]>,
    Name: ToName,
{
    fn fmt(&self, p: &mut impl Formatter) -> zonefile_fmt::Result {
        p.block(|p| {
            p.write_token(self.order)?;
            p.write_comment("order")?;
            p.write_token(self.preference)?;
            p.write_comment("preference")?;
            p.write_token(self.flags.display_quoted())?;
            p.write_comment("flags")?;
            p.write_token(self.services.display_quoted())?;
            p.write_comment("services")?;
            p.write_token(self.regexp.display_quoted())?;
            p.write_comment("regexp")?;
            p.write_token(self.replacement.fmt_with_dot())?;
            p.write_comment("replacement")
        })
    }
}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use bytes::Bytes;

    use super::*;
    use crate::base::{
        rdata::test::{test_compose_parse, test_rdlen, test_scan},
        Name,
    };
    use core::str::FromStr;
    use std::vec::Vec;

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn naptr_compose_parse_scan() {
        let rdata = Naptr::new(
            100,
            50,
            CharStr::from_octets("a").unwrap(),
            CharStr::from_octets("z3950+N2L+N2C").unwrap(),
            CharStr::from_octets("").unwrap(),
            Name::<Vec<u8>>::from_str("cidserver.example.com.").unwrap(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Naptr::parse(parser));
        test_scan(
            &[
                "100",
                "50",
                "a",
                "z3950+N2L+N2C",
                "",
                "cidserver.example.com.",
            ],
            Naptr::scan,
            &rdata,
        );
    }

    #[test]
    fn naptr_octets_into() {
        let naptr: Naptr<&str, Name<Vec<u8>>> = Naptr::new(
            100,
            50,
            CharStr::from_octets("a").unwrap(),
            CharStr::from_octets("z3950+N2L+N2C").unwrap(),
            CharStr::from_octets("").unwrap(),
            Name::<Vec<u8>>::from_str("cidserver.example.com.").unwrap(),
        );
        let naptr_bytes: Naptr<Bytes, Name<Bytes>> =
            naptr.clone().octets_into();
        assert_eq!(naptr.order(), naptr_bytes.order());
        assert_eq!(naptr.preference(), naptr_bytes.preference());
        assert_eq!(naptr.flags(), naptr_bytes.flags());
        assert_eq!(naptr.services(), naptr_bytes.services());
        assert_eq!(naptr.regexp(), naptr_bytes.regexp());
        assert_eq!(naptr.replacement(), naptr_bytes.replacement());
    }

    #[test]
    fn naptr_display() {
        let naptr: Naptr<&str, Name<Vec<u8>>> = Naptr::new(
            100,
            50,
            CharStr::from_octets("a").unwrap(),
            CharStr::from_octets("z3950+N2L+N2C").unwrap(),
            CharStr::from_octets(r#"!^urn:cid:.+@([^\.]+\.)(.*)$!\2!i"#)
                .unwrap(),
            Name::<Vec<u8>>::from_str("cidserver.example.com.").unwrap(),
        );
        assert_eq!(
            format!("{}", naptr),
            r#"100 50 "a" "z3950+N2L+N2C" "!^urn:cid:.+@([^\\.]+\\.)(.*)$!\\2!i" cidserver.example.com."#
        );
    }
}
