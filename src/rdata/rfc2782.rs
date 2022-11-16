//! Record data from [RFC 2782]: SRV records.
//!
//! This RFC defines the Srv record type.
//!
//! [RFC 2782]: https://tools.ietf.org/html/rfc2782

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::{Dname, ParsedDname, PushError, ToDname};
use crate::base::octets::{
    Compose, EmptyBuilder, FromBuilder, Octets, OctetsBuilder, OctetsFrom,
    OctetsInto, Parse, ParseError, Parser, ShortBuf,
};
use crate::base::rdata::RtypeRecordData;
use crate::base::scan::{Scan, Scanner};
use core::cmp::Ordering;
use core::fmt;

//------------ Srv ---------------------------------------------------------

#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Srv<N> {
    priority: u16,
    weight: u16,
    port: u16,
    target: N,
}

impl<N> Srv<N> {
    pub const RTYPE: Rtype = Rtype::Srv;

    pub fn new(priority: u16, weight: u16, port: u16, target: N) -> Self {
        Srv {
            priority,
            weight,
            port,
            target,
        }
    }

    pub fn into_target(self) -> N {
        self.target
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }

    pub fn weight(&self) -> u16 {
        self.weight
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn target(&self) -> &N {
        &self.target
    }

    pub(super) fn convert_octets<Target: OctetsFrom<N>>(
        self,
    ) -> Result<Srv<Target>, Target::Error> {
        Ok(Srv::new(
            self.priority,
            self.weight,
            self.port,
            self.target.try_octets_into()?,
        ))
    }
}

impl<'a, Octs> Srv<ParsedDname<'a, Octs>> {
    pub fn flatten_into<Target>(self) -> Result<Srv<Dname<Target>>, PushError>
    where
        Octs: Octets,
        Target: OctetsFrom<Octs::Range<'a>> + FromBuilder,
        <Target as FromBuilder>::Builder: EmptyBuilder,
    {
        let Self {
            priority,
            weight,
            port,
            target,
        } = self;
        Ok(Srv::new(priority, weight, port, target.to_dname()?))
    }
}

//--- OctetsFrom

impl<Name, SrcName> OctetsFrom<Srv<SrcName>> for Srv<Name>
where
    Name: OctetsFrom<SrcName>,
{
    type Error = Name::Error;

    fn try_octets_from(source: Srv<SrcName>) -> Result<Self, Self::Error> {
        Ok(Srv::new(
            source.priority,
            source.weight,
            source.port,
            Name::try_octets_from(source.target)?,
        ))
    }
}

//--- PartialEq and Eq

impl<N, NN> PartialEq<Srv<NN>> for Srv<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn eq(&self, other: &Srv<NN>) -> bool {
        self.priority == other.priority
            && self.weight == other.weight
            && self.port == other.port
            && self.target.name_eq(&other.target)
    }
}

impl<N: ToDname> Eq for Srv<N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN> PartialOrd<Srv<NN>> for Srv<N>
where
    N: ToDname,
    NN: ToDname,
{
    fn partial_cmp(&self, other: &Srv<NN>) -> Option<Ordering> {
        match self.priority.partial_cmp(&other.priority) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.weight.partial_cmp(&other.weight) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        match self.port.partial_cmp(&other.port) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        Some(self.target.name_cmp(&other.target))
    }
}

impl<N: ToDname> Ord for Srv<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.weight.cmp(&other.weight) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.port.cmp(&other.port) {
            Ordering::Equal => {}
            other => return other,
        }
        self.target.name_cmp(&other.target)
    }
}

impl<N: ToDname, NN: ToDname> CanonicalOrd<Srv<NN>> for Srv<N> {
    fn canonical_cmp(&self, other: &Srv<NN>) -> Ordering {
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.weight.cmp(&other.weight) {
            Ordering::Equal => {}
            other => return other,
        }
        match self.port.cmp(&other.port) {
            Ordering::Equal => {}
            other => return other,
        }
        self.target.lowercase_composed_cmp(&other.target)
    }
}

//--- Parse, ParseAll, Compose and Compress

impl<'a, Octs: Octets> Parse<'a, Octs> for Srv<ParsedDname<'a, Octs>> {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        Ok(Self::new(
            u16::parse(parser)?,
            u16::parse(parser)?,
            u16::parse(parser)?,
            ParsedDname::parse(parser)?,
        ))
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        u16::skip(parser)?;
        u16::skip(parser)?;
        u16::skip(parser)?;
        ParsedDname::skip(parser)
    }
}

impl<N: Compose> Compose for Srv<N> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.priority.compose(buf)?;
            self.weight.compose(buf)?;
            self.port.compose(buf)?;
            self.target.compose(buf)
        })
    }

    fn compose_canonical<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T,
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.priority.compose(buf)?;
            self.weight.compose(buf)?;
            self.port.compose(buf)?;
            self.target.compose_canonical(buf)
        })
    }
}

//--- RtypeRecordData

impl<N> RtypeRecordData for Srv<N> {
    const RTYPE: Rtype = Rtype::Srv;
}

//--- Scan and Display

impl<N, S: Scanner<Dname = N>> Scan<S> for Srv<N> {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        Ok(Self::new(
            u16::scan(scanner)?,
            u16::scan(scanner)?,
            u16::scan(scanner)?,
            scanner.scan_dname()?,
        ))
    }
}

impl<N: fmt::Display> fmt::Display for Srv<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.priority, self.weight, self.port, self.target
        )
    }
}
