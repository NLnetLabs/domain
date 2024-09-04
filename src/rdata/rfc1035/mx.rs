//! Record data for the MX record.
//!
//! This is a private module. It’s content is re-exported by the parent.

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::{FlattenInto, ParsedName, ToName};
use crate::base::rdata::{
    ComposeRecordData, ParseRecordData, RecordData,
};
use crate::base::scan::{Scan, Scanner};
use crate::base::show::{self, Presenter, Show};
use crate::base::wire::{Compose, Composer, Parse, ParseError};
use core::fmt;
use core::cmp::Ordering;
use octseq::octets::{Octets, OctetsFrom, OctetsInto};
use octseq::parse::Parser;

//------------ Mx -----------------------------------------------------------

/// Mx record data.
///
/// The Mx record specifies a host willing to serve as a mail exchange for
/// the owner name.
///
/// The Mx record type is defined in [RFC 1035, section 3.3.9][1].
/// 
/// [1]: https://tools.ietf.org/html/rfc1035#section-3.3.9
#[derive(Clone, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Mx<N> {
    preference: u16,
    exchange: N,
}

impl Mx<()> {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::MX;
}

impl<N> Mx<N> {
    /// Creates a new Mx record data from the components.
    pub fn new(preference: u16, exchange: N) -> Self {
        Mx {
            preference,
            exchange,
        }
    }

    /// The preference for this record.
    ///
    /// Defines an order if there are several Mx records for the same owner.
    /// Lower values are preferred.
    pub fn preference(&self) -> u16 {
        self.preference
    }

    /// The name of the host that is the exchange.
    pub fn exchange(&self) -> &N {
        &self.exchange
    }

    pub(in crate::rdata) fn convert_octets<Target: OctetsFrom<N>>(
        self,
    ) -> Result<Mx<Target>, Target::Error> {
        Ok(Mx::new(self.preference, self.exchange.try_octets_into()?))
    }

    pub(in crate::rdata) fn flatten<TargetName>(
        self,
    ) -> Result<Mx<TargetName>, N::AppendError>
    where N: FlattenInto<TargetName> {
        Ok(Mx::new(self.preference, self.exchange.try_flatten_into()?))
    }

    pub fn scan<S: Scanner<Name = N>>(
        scanner: &mut S,
    ) -> Result<Self, S::Error> {
        Ok(Self::new(u16::scan(scanner)?, scanner.scan_name()?))
    }
}

impl<Octs> Mx<ParsedName<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized + 'a>(
        parser: &mut Parser<'a, Src>,
    ) -> Result<Self, ParseError> {
        Ok(Self::new(u16::parse(parser)?, ParsedName::parse(parser)?))
    }
}

//--- OctetsFrom and FlattenInto

impl<Name, SrcName> OctetsFrom<Mx<SrcName>> for Mx<Name>
where
    Name: OctetsFrom<SrcName>,
{
    type Error = Name::Error;

    fn try_octets_from(source: Mx<SrcName>) -> Result<Self, Self::Error> {
        Ok(Mx::new(
            source.preference,
            Name::try_octets_from(source.exchange)?,
        ))
    }
}

impl<Name, TName> FlattenInto<Mx<TName>> for Mx<Name>
where
    Name: FlattenInto<TName>,
{
    type AppendError = Name::AppendError;

    fn try_flatten_into(self) -> Result<Mx<TName>, Name::AppendError> {
        self.flatten()
    }
}

//--- PartialEq and Eq

impl<N, NN> PartialEq<Mx<NN>> for Mx<N>
where
    N: ToName,
    NN: ToName,
{
    fn eq(&self, other: &Mx<NN>) -> bool {
        self.preference == other.preference
            && self.exchange.name_eq(&other.exchange)
    }
}

impl<N: ToName> Eq for Mx<N> {}

//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN> PartialOrd<Mx<NN>> for Mx<N>
where
    N: ToName,
    NN: ToName,
{
    fn partial_cmp(&self, other: &Mx<NN>) -> Option<Ordering> {
        match self.preference.partial_cmp(&other.preference) {
            Some(Ordering::Equal) => {}
            other => return other,
        }
        Some(self.exchange.name_cmp(&other.exchange))
    }
}

impl<N: ToName> Ord for Mx<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.preference.cmp(&other.preference) {
            Ordering::Equal => {}
            other => return other,
        }
        self.exchange.name_cmp(&other.exchange)
    }
}

impl<N: ToName, NN: ToName> CanonicalOrd<Mx<NN>> for Mx<N> {
    fn canonical_cmp(&self, other: &Mx<NN>) -> Ordering {
        match self.preference.cmp(&other.preference) {
            Ordering::Equal => {}
            other => return other,
        }
        self.exchange.lowercase_composed_cmp(&other.exchange)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl<N> RecordData for Mx<N> {
    fn rtype(&self) -> Rtype {
        Mx::RTYPE
    }
}

impl<'a, Octs: Octets + ?Sized> ParseRecordData<'a, Octs>
    for Mx<ParsedName<Octs::Range<'a>>>
{
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Mx::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl<Name: ToName> ComposeRecordData for Mx<Name> {
    fn rdlen(&self, compress: bool) -> Option<u16> {
        if compress {
            None
        } else {
            Some(u16::COMPOSE_LEN + self.exchange.compose_len())
        }
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        if target.can_compress() {
            self.preference.compose(target)?;
            target.append_compressed_name(&self.exchange)
        } else {
            self.preference.compose(target)?;
            self.exchange.compose(target)
        }
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.preference.compose(target)?;
        self.exchange.compose_canonical(target)
    }
}

//--- Display

impl<N: fmt::Display> fmt::Display for Mx<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}.", self.preference, self.exchange)
    }
}

//--- Show

impl<N: fmt::Display> Show for Mx<N> {
    fn show(&self, p: &mut Presenter) -> show::Result {
        p.block()
            .write_token(self.preference)
            .write_token(format_args!("{}.", self.exchange))
            .finish()
    }
}

//============ Testing =======================================================

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
    fn mx_compose_parse_scan() {
        let rdata = Mx::<Name<Vec<u8>>>::new(
            12,
            Name::from_str("mail.example.com").unwrap(),
        );
        test_rdlen(&rdata);
        test_compose_parse(&rdata, |parser| Mx::parse(parser));
        test_scan(&["12", "mail.example.com"], Mx::scan, &rdata);
    }
}

