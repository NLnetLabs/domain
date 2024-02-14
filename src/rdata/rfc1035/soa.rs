//! Record data for the SOA record.
//!
//! This is a private module. It’s content is re-exported by the parent.

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::{FlattenInto, ParsedDname, ToDname};
use crate::base::rdata::{
    ComposeRecordData, ParseRecordData, RecordData,
};
use crate::base::record::Ttl;
use crate::base::scan::{Scan, Scanner};
use crate::base::serial::Serial;
use crate::base::wire::{Compose, Composer, ParseError};
use core::{fmt, str};
use core::cmp::Ordering;
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;

//------------ Soa ----------------------------------------------------------

/// Soa record data.
///
/// Soa records mark the top of a zone and contain information pertinent to
/// name server maintenance operations.
///
/// The Soa record type is defined in RFC 1035, section 3.3.13.
#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Soa<N> {
    mname: N,
    rname: N,
    serial: Serial,
    refresh: Ttl,
    retry: Ttl,
    expire: Ttl,
    minimum: Ttl,
}

impl<N> Soa<N> {
    /// Creates new Soa record data from content.
    pub fn new(
        mname: N,
        rname: N,
        serial: Serial,
        refresh: Ttl,
        retry: Ttl,
        expire: Ttl,
        minimum: Ttl,
    ) -> Self {
        Soa {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }
    }

    /// The primary name server for the zone.
    pub fn mname(&self) -> &N {
        &self.mname
    }

    /// The mailbox for the person responsible for this zone.
    pub fn rname(&self) -> &N {
        &self.rname
    }

    /// The serial number of the original copy of the zone.
    pub fn serial(&self) -> Serial {
        self.serial
    }

    /// The time interval before the zone should be refreshed.
    pub fn refresh(&self) -> Ttl {
        self.refresh
    }

    /// The time before a failed refresh is retried.
    pub fn retry(&self) -> Ttl {
        self.retry
    }

    /// The upper limit of time the zone is authoritative.
    pub fn expire(&self) -> Ttl {
        self.expire
    }

    /// The minimum TTL to be exported with any RR from this zone.
    pub fn minimum(&self) -> Ttl {
        self.minimum
    }

    pub(in crate::rdata) fn convert_octets<Target: OctetsFrom<N>>(
        self,
    ) -> Result<Soa<Target>, Target::Error> {
        Ok(Soa::new(
            self.mname.try_octets_into()?,
            self.rname.try_octets_into()?,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        ))
    }

    pub(in crate::rdata) fn flatten<TargetName>(
        self,
    ) -> Result<Soa<TargetName>, N::AppendError>
    where N: FlattenInto<TargetName> {
        Ok(Soa::new(
            self.mname.try_flatten_into()?,
            self.rname.try_flatten_into()?,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum,
        ))
    }

    pub fn scan<S: Scanner<Dname = N>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(
            scanner.scan_dname()?,
            scanner.scan_dname()?,
            Serial::scan(scanner)?,
            Ttl::scan(scanner)?,
            Ttl::scan(scanner)?,
            Ttl::scan(scanner)?,
            Ttl::scan(scanner)?,
        ))
    }
}

impl<Octs> Soa<ParsedDname<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            ParsedDname::parse(parser)?,
            ParsedDname::parse(parser)?,
            Serial::parse(parser)?,
            Ttl::parse(parser)?,
            Ttl::parse(parser)?,
            Ttl::parse(parser)?,
            Ttl::parse(parser)?,
        ))
    }
}

//--- OctetsFrom and FlattenInto

impl<Name, SrcName> OctetsFrom<Soa<SrcName>> for Soa<Name>
where
    Name: OctetsFrom<SrcName>,
{
    type Error = Name::Error;

    fn try_octets_from(source: Soa<SrcName>) -> Result<Self, Self::Error> {
        Ok(Soa::new(
            Name::try_octets_from(source.mname)?,
            Name::try_octets_from(source.rname)?,
            source.serial,
            source.refresh,
            source.retry,
            source.expire,
            source.minimum,
        ))
    }
}

impl<Name, TName> FlattenInto<Soa<TName>> for Soa<Name>
where
    Name: FlattenInto<TName>,
{
    type AppendError = Name::AppendError;

    fn try_flatten_into(self) -> Result<Soa<TName>, Name::AppendError> {
        self.flatten()
    }
}

//--- PartialEq and Eq

impl<N, NN> PartialEq<Soa<NN>> for Soa<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn eq(&self, other: &Soa<NN>) -> bool {
        self.mname.name_eq(&other.mname)
            && self.rname.name_eq(&other.rname)
            && self.serial == other.serial
            && self.refresh == other.refresh
            && self.retry == other.retry
            && self.expire == other.expire
            && self.minimum == other.minimum
    }
}

impl<N: ToDname> Eq for Soa<N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN> PartialOrd<Soa<NN>> for Soa<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn partial_cmp(&self, other: &Soa<NN>) -> Option<Ordering> {
        match self.mname.name_cmp(&other.mname) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        match self.rname.name_cmp(&other.rname) {
            Ordering::Equal => {}
            other => return Some(other),
        }
        match u32::from(self.serial).partial_cmp(&u32::from(other.serial)) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.refresh.partial_cmp(&other.refresh) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.retry.partial_cmp(&other.retry) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.expire.partial_cmp(&other.expire) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        self.minimum.partial_cmp(&other.minimum)
    }
}

impl<N: ToDname> Ord for Soa<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.mname.name_cmp(&other.mname) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.rname.name_cmp(&other.rname) {
            Ordering::Equal => {}
            other => return other,
        }
        match u32::from(self.serial).cmp(&u32::from(other.serial)) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.refresh.cmp(&other.refresh) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.retry.cmp(&other.retry) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.expire.cmp(&other.expire) {
            Ordering::Equal => {}
            other => return other,
        }
        self.minimum.cmp(&other.minimum)
    }
}

impl<N: ToDname, NN: ToDname> CanonicalOrd<Soa<NN>> for Soa<N> {
    fn canonical_cmp(&self, other: &Soa<NN>) -> Ordering {
        match self.mname.lowercase_composed_cmp(&other.mname) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.rname.lowercase_composed_cmp(&other.rname) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.serial.canonical_cmp(&other.serial) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.refresh.cmp(&other.refresh) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.retry.cmp(&other.retry) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.expire.cmp(&other.expire) {
            Ordering::Equal => {}
            other => return other,
        }
        self.minimum.cmp(&other.minimum)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<N> RecordData for Soa<N> {
    fn rtype(&self) -> Rtype {
        Rtype::Soa
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Soa<ParsedDname<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Soa {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Name: ToDname> ComposeRecordData for Soa<Name> {
    fn rdlen(&self, compress: bool) -> Option<u16> {
        if compress {
            None
        } else {
            Some(
                self.mname.compose_len()
                    + self.rname.compose_len()
                    + Serial::COMPOSE_LEN
                    + 4 * u32::COMPOSE_LEN,
            )
        }
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if target.can_compress() {
            target.append_compressed_dname(&self.mname)?;
            target.append_compressed_dname(&self.rname)?;
        } else {
            self.mname.compose(target)?;
            self.rname.compose(target)?;
        }
        self.compose_fixed(target)
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.mname.compose_canonical(target)?;
        self.rname.compose_canonical(target)?;
        self.compose_fixed(target)
    }
}

impl<Name: ToDname> Soa<Name> {
    fn compose_fixed<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.serial.compose(target)?;
        self.refresh.compose(target)?;
        self.retry.compose(target)?;
        self.expire.compose(target)?;
        self.minimum.compose(target)
    }
}

//--- Display

impl<N: fmt::Display> fmt::Display for Soa<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}. {}. {} {} {} {} {}",
            self.mname,
            self.rname,
            self.serial,
            self.refresh.as_secs(),
            self.retry.as_secs(),
            self.expire.as_secs(),
            self.minimum.as_secs()
        )
    }
}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::name::Dname;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use core::str::FromStr;
    use std::vec::Vec;

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn soa_compose_parse_scan() {
        let rdata = Soa::<Dname<Vec<u8>>>::new(
            Dname::from_str("m.example.com").unwrap(),
            Dname::from_str("r.example.com").unwrap(),
            Serial(11),
            Ttl::from_secs(12),
            Ttl::from_secs(13),
            Ttl::from_secs(14),
            Ttl::from_secs(15),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Soa::parse(parser));
        test_scan(
            &[
                "m.example.com",
                "r.example.com",
                "11",
                "12",
                "13",
                "14",
                "15",
            ],
            Soa::scan,
            &rdata,
        );
    }
}

