//! EDNS option to request the complete DNSSEC validation chain.
//!
//! The option in this module – [`Chain<Name>`] – allows a validating resolver
//! to request to include all records necessary to validate the answer in the
//! response. The option is defined in [RFC 7901].
//!
//! [RFC 7901]: https://tools.ietf.org/html/rfc7901

use core::fmt;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::name::{Dname, ToDname};
use super::super::wire::{Composer, ParseError};
use super::{Opt, OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::octets::{Octets, OctetsFrom};
use octseq::parse::Parser;
use core::hash;
use core::cmp::Ordering;


//------------ Chain --------------------------------------------------------

/// Option data for the CHAIN option.
///
/// The CHAIN option can be used to request that the queried include all the
/// records necessary to validate the DNSSEC signatures of an answer. The
/// option includes the absolute domain name that serves as the starting
/// point of the included records, i.e., the suffix of the queried name
/// furthest away from the root to which the requesting resolver already has
/// all necessary records.
#[derive(Clone, Copy, Debug)]
pub struct Chain<Name: ?Sized> {
    /// The start name AKA ‘closest trust point.’
    start: Name
}

impl<Name: ?Sized> Chain<Name> {
    /// Creates new CHAIN option data using the given name as the start.
    pub fn new(start: Name) -> Self
    where
        Name: Sized
    {
        Chain { start }
    }

    /// Creates a reference to CHAIN option data from a reference to the start.
    pub fn new_ref(start: &Name) -> &Self {
        unsafe {
            &*(start as *const Name as *const Self)
        }
    }

    /// Returns a reference to the start point.
    ///
    /// The start point is the name furthest along the chain to which the
    /// requester already has all necessary records.
    pub fn start(&self) -> &Name {
        &self.start
    }

    /// Converts the value into the start point.
    pub fn into_start(self) -> Name
    where
        Name: Sized
    {
        self.start
    }
}

impl<Octs> Chain<Dname<Octs>> {
    /// Parses CHAIN option data from its wire format.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        Dname::parse(parser).map(Self::new)
    }
}

//--- OctetsFrom

impl<Name, SrcName> OctetsFrom<Chain<SrcName>> for Chain<Name>
where Name: OctetsFrom<SrcName> {
    type Error = Name::Error;

    fn try_octets_from(src: Chain<SrcName>) -> Result<Self, Self::Error> {
        Name::try_octets_from(src.start).map(Self::new)
    }
}

//--- PartialEq and Eq

impl<Name, OtherName> PartialEq<Chain<OtherName>> for Chain<Name>
where
    Name: ToDname,
    OtherName: ToDname
{
    fn eq(&self, other: &Chain<OtherName>) -> bool {
        self.start().name_eq(other.start())
    }
}

impl<Name: ToDname> Eq for Chain<Name> { }

//--- PartialOrd and Ord

impl<Name, OtherName> PartialOrd<Chain<OtherName>> for Chain<Name>
where
    Name: ToDname,
    OtherName: ToDname
{
    fn partial_cmp(&self, other: &Chain<OtherName>) -> Option<Ordering> {
        Some(self.start().name_cmp(other.start()))
    }
}

impl<Name: ToDname> Ord for Chain<Name> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start().name_cmp(other.start())
    }
}

//--- Hash

impl<Name: hash::Hash> hash::Hash for Chain<Name> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.start().hash(state)
    }
}

//--- OptData

impl<Name> OptData for Chain<Name> {
    fn code(&self) -> OptionCode {
        OptionCode::Chain
    }
}

impl<'a, Octs> ParseOptData<'a, Octs> for Chain<Dname<Octs::Range<'a>>>
where Octs: Octets {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::Chain {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<Name: ToDname> ComposeOptData for Chain<Name> {
    fn compose_len(&self) -> u16 {
        self.start.compose_len()
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.start.compose(target)
    }
}

//--- Display

impl<Name: fmt::Display> fmt::Display for Chain<Name> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.start)
    }
}

//--- Extended Opt and OptBuilder

impl<Octs: Octets> Opt<Octs> {
    /// Returns the first CHAIN option if present.
    ///
    /// The CHAIN option allows a client to request that all records that
    /// are necessary for DNSSEC validation are included in the response.
    pub fn chain(&self) -> Option<Chain<Dname<Octs::Range<'_>>>> {
        self.first()
    }
}

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    /// Appends the CHAIN option.
    ///
    /// The CHAIN option allows a client to request that all records that
    /// are necessary for DNSSEC validation are included in the response.
    /// The `start` name is the longest suffix of the queried owner name
    /// for which the client already has all necessary records.
    pub fn chain(
        &mut self, start: impl ToDname
    ) -> Result<(), Target::AppendError> {
        self.push(&Chain::new(start))
    }
}

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use super::super::test::test_option_compose_parse;
    use std::vec::Vec;
    use core::str::FromStr;
    
    #[test]
    fn chain_compose_parse() {
        test_option_compose_parse(
            &Chain::new(Dname::<Vec<u8>>::from_str("example.com").unwrap()),
            |parser| Chain::parse(parser)
        );
    }
}

