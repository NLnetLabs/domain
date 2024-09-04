//! Record data from [RFC 2782]: SRV records.
//!
//! This RFC defines the Srv record type.
//!
//! [RFC 2782]: https://tools.ietf.org/html/rfc2782

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::{FlattenInto, ParsedName, ToName};
use crate::base::rdata::{ComposeRecordData, ParseRecordData, RecordData};
use crate::base::scan::{Scan, Scanner};
use crate::base::show::{self, Presenter, Show};
use crate::base::wire::{Compose, Composer, Parse, ParseError};
use core::cmp::Ordering;
use core::fmt;
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;

//------------ Srv ---------------------------------------------------------

#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Srv<N> {
    priority: u16,
    weight: u16,
    port: u16,
    target: N,
}

impl Srv<()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::SRV;
}

impl<N> Srv<N> {

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

    pub(super) fn flatten<TargetName>(
        self,
    ) -> Result<Srv<TargetName>, N::AppendError>
    where N: FlattenInto<TargetName> {
        Ok(Srv::new(
            self.priority,
            self.weight,
            self.port,
            self.target.try_flatten_into()?,
        ))
    }

    pub fn scan<S: Scanner<Name = N>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(
            u16::scan(scanner)?,
            u16::scan(scanner)?,
            u16::scan(scanner)?,
            scanner.scan_name()?,
        ))
    }
}

impl<Octs> Srv<ParsedName<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(
            u16::parse(parser)?,
            u16::parse(parser)?,
            u16::parse(parser)?,
            ParsedName::parse(parser)?,
        ))
    }
}

//--- OctetsFrom and FlattenInto

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

impl<Name: FlattenInto<TName>, TName> FlattenInto<Srv<TName>> for Srv<Name> {
    type AppendError = Name::AppendError;

    fn try_flatten_into(self) -> Result<Srv<TName>, Name::AppendError> {
        self.flatten()
    }
}

//--- PartialEq and Eq

impl<N, NN> PartialEq<Srv<NN>> for Srv<N>
where
    N: ToName,
    NN: ToName,
{
    fn eq(&self, other: &Srv<NN>) -> bool {
        self.priority == other.priority
            && self.weight == other.weight
            && self.port == other.port
            && self.target.name_eq(&other.target)
    }
}

impl<N: ToName> Eq for Srv<N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN> PartialOrd<Srv<NN>> for Srv<N>
where
    N: ToName,
    NN: ToName,
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

impl<N: ToName> Ord for Srv<N> {
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

impl<N: ToName, NN: ToName> CanonicalOrd<Srv<NN>> for Srv<N> {
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

//--- RecordData, ParseRecordData, ComposeRecordData

impl<N> RecordData for Srv<N> {
    fn rtype(&self) -> Rtype {
        Srv::RTYPE
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Srv<ParsedName<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Srv::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Name: ToName> ComposeRecordData for Srv<Name> {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        // SRV records are not compressed.
        Some(self.target.compose_len() + 6)
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_head(target)?;
        self.target.compose(target)
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_head(target)?;
        self.target.compose_canonical(target) // ... but are lowercased.
    }
}

impl<Name: ToName> Srv<Name> {
    fn compose_head<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.priority.compose(target)?;
        self.weight.compose(target)?;
        self.port.compose(target)
    }
}

//--- Display

impl<N: fmt::Display> fmt::Display for Srv<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.priority, self.weight, self.port, self.target
        )
    }
}

//--- Show

impl<N: fmt::Display> Show for Srv<N> {
    fn show(&self, p: &mut Presenter) -> show::Result {
        p.block()
            .write_token(self.priority)
            .write_token(self.weight)
            .write_token(self.port)
            .write_token(&self.target)
            .finish()
    }
}

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::name::Name;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };
    use core::str::FromStr;
    use std::vec::Vec;

    #[test]
    #[allow(clippy::redundant_closure)] // lifetimes ...
    fn srv_compose_parse_scan() {
        let rdata = Srv::new(
            10,
            11,
            12,
            Name::<Vec<u8>>::from_str("example.com.").unwrap(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Srv::parse(parser));
        test_scan(&["10", "11", "12", "example.com."], Srv::scan, &rdata);
    }
}
