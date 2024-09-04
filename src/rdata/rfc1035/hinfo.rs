//! Record data for the HINFO record.
//!
//! This is a private module. It’s content is re-exported by the parent.

use crate::base::charstr::CharStr;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::rdata::{
    ComposeRecordData, ParseRecordData, RecordData,
};
use crate::base::scan::Scanner;
use crate::base::show::{self, Presenter, Show};
use crate::base::wire::{Composer, ParseError};
use core::{fmt, hash};
use core::cmp::Ordering;
#[cfg(feature = "serde")]
use octseq::builder::{EmptyBuilder, FromBuilder};
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;

//------------ Hinfo --------------------------------------------------------

/// Hinfo record data.
///
/// Hinfo records are used to acquire general information about a host,
/// specifically the CPU type and operating system type.
///
/// The Hinfo type is defined in [RFC 1035, section 3.3.2][1].
///
/// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.2
#[derive(Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound(
        serialize = "Octs: AsRef<[u8]> + octseq::serde::SerializeOctets",
        deserialize = "Octs: \
                FromBuilder \
                + octseq::serde::DeserializeOctets<'de>, \
            <Octs as FromBuilder>::Builder: AsRef<[u8]> + EmptyBuilder ",
    ))
)]
pub struct Hinfo<Octs> {
    cpu: CharStr<Octs>,
    os: CharStr<Octs>,
}

impl Hinfo<()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::HINFO;
}

impl<Octs> Hinfo<Octs> {
    /// Creates a new Hinfo record data from the components.
    pub fn new(cpu: CharStr<Octs>, os: CharStr<Octs>) -> Self {
        Hinfo { cpu, os }
    }

    /// The CPU type of the host.
    pub fn cpu(&self) -> &CharStr<Octs> {
        &self.cpu
    }

    /// The operating system type of the host.
    pub fn os(&self) -> &CharStr<Octs> {
        &self.os
    }

    pub(in crate::rdata) fn convert_octets<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Hinfo<Target>, Target::Error> {
        Ok(Hinfo::new(
            self.cpu.try_octets_into()?,
            self.os.try_octets_into()?,
        ))
    }

    pub(in crate::rdata) fn flatten<Target: OctetsFrom<Octs>>(
        self,
    ) -> Result<Hinfo<Target>, Target::Error> {
        self.convert_octets()
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(CharStr::parse(parser)?, CharStr::parse(parser)?))
    }

    pub fn scan<S: Scanner<Octets = Octs>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(scanner.scan_charstr()?, scanner.scan_charstr()?))
    }
}

//--- OctetsFrom

impl<Octs, SrcOcts> OctetsFrom<Hinfo<SrcOcts>> for Hinfo<Octs>
where
    Octs: OctetsFrom<SrcOcts>,
{
    type Error = Octs::Error;

    fn try_octets_from(source: Hinfo<SrcOcts>) -> Result<Self, Self::Error> {
        Ok(Hinfo::new(
            CharStr::try_octets_from(source.cpu)?,
            CharStr::try_octets_from(source.os)?,
        ))
    }
}

//--- PartialEq and Eq

impl<Octs, Other> PartialEq<Hinfo<Other>> for Hinfo<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn eq(&self, other: &Hinfo<Other>) -> bool {
        self.cpu.eq(&other.cpu) && self.os.eq(&other.os)
    }
}

impl<Octs: AsRef<[u8]>> Eq for Hinfo<Octs> {}

//--- PartialOrd, CanonicalOrd, and Ord

impl<Octs, Other> PartialOrd<Hinfo<Other>> for Hinfo<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn partial_cmp(&self, other: &Hinfo<Other>) -> Option<Ordering> {
        match self.cpu.partial_cmp(&other.cpu) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.os.partial_cmp(&other.os)
    }
}

impl<Octs, Other> CanonicalOrd<Hinfo<Other>> for Hinfo<Octs>
where
    Octs: AsRef<[u8]>,
    Other: AsRef<[u8]>,
{
    fn canonical_cmp(&self, other: &Hinfo<Other>) -> Ordering {
        match self.cpu.canonical_cmp(&other.cpu) {
            Ordering::Equal => {}
            other => return other,
        }
        self.os.canonical_cmp(&other.os)
    }
}

impl<Octs: AsRef<[u8]>> Ord for Hinfo<Octs> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.cpu.cmp(&other.cpu) {
            Ordering::Equal => {}
            other => return other,
        }
        self.os.cmp(&other.os)
    }
}

//--- Hash

impl<Octs: AsRef<[u8]>> hash::Hash for Hinfo<Octs> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.cpu.hash(state);
        self.os.hash(state);
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<Octs> RecordData for Hinfo<Octs> {
    fn rtype(&self) -> Rtype {
        Hinfo::RTYPE
    }
}

impl<'a, Octs> ParseRecordData<'a, Octs> for Hinfo<Octs::Range<'a>>
where
    Octs: Octets + ?Sized,
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Hinfo::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeRecordData for Hinfo<Octs> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(self.cpu.compose_len() + self.os.compose_len())
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.cpu.compose(target)?;
        self.os.compose(target)
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display

impl<Octs: AsRef<[u8]>> fmt::Display for Hinfo<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
    }
}

//--- Debug

impl<Octs: AsRef<[u8]>> fmt::Debug for Hinfo<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Hinfo")
            .field("cpu", &self.cpu)
            .field("os", &self.os)
            .finish()
    }
}

//--- Show

impl<Octs: AsRef<[u8]>> Show for Hinfo<Octs> {
    fn show(&self, p: &mut Presenter) -> show::Result {
        p.block()
            .write_token(&self.cpu)
            .write_token(&self.os)
            .finish()
    }
}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use std::vec::Vec;

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn hinfo_compose_parse_scan() {
        let rdata = Hinfo::new(
            CharStr::from_octets("cpu").unwrap(),
            CharStr::from_octets("os").unwrap(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Hinfo::parse(parser));
        test_scan(&["cpu", "os"], Hinfo::scan, &rdata);
    }

    #[test]
    fn hinfo_octets_into() {
        let hinfo: Hinfo<Vec<u8>> =
            Hinfo::new("1234".parse().unwrap(), "abcd".parse().unwrap());
        let hinfo_bytes: Hinfo<bytes::Bytes> = hinfo.clone().octets_into();
        assert_eq!(hinfo.cpu(), hinfo_bytes.cpu());
        assert_eq!(hinfo.os(), hinfo_bytes.os());
    }
}

