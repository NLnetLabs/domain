//! EDNS Options from RFC 7901

use core::fmt;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::name::{Dname, ToDname};
use super::super::wire::{Composer, ParseError};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::octets::Octets;
use octseq::parse::Parser;
use core::hash;
use core::cmp::Ordering;


//------------ Chain --------------------------------------------------------

// TODO Impl more traits. We can’t derive them because that would force
//      trait boundaries on Octs.
#[derive(Clone, Debug)]
pub struct Chain<Name> {
    start: Name
}

impl<Name> Chain<Name> {
    pub fn new(start: Name) -> Self {
        Chain { start }
    }

    pub fn start(&self) -> &Name {
        &self.start
    }
}

impl<Octs> Chain<Dname<Octs>> {
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        Dname::parse(parser).map(Self::new)
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
        write!(f, "{}", self.start)?;
        Ok(())
    }
}

//--- PartialEq and Eq

impl<Name: PartialEq<Other>, Other> PartialEq<Chain<Other>> for Chain<Name> {
    fn eq(&self, other: &Chain<Other>) -> bool {
        self.start().eq(other.start())
    }
}

impl<Name: Eq> Eq for Chain<Name> { }

//--- PartialOrd and Ord

impl<Name: PartialOrd<Other>, Other> PartialOrd<Chain<Other>> for Chain<Name> {
    fn partial_cmp(&self, other: &Chain<Other>) -> Option<Ordering> {
        self.start().partial_cmp(other.start())
    }
}

impl<Name: Ord> Ord for Chain<Name> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.start().cmp(other.start())
    }
}

//--- Hash

impl<Name: hash::Hash> hash::Hash for Chain<Name> {
    fn hash<H: hash::Hasher>(&self, state: &mut H) {
        self.start().hash(state)
    }
}

//------------ OptBuilder ----------------------------------------------------

impl<'a, Target: Composer> OptBuilder<'a, Target> {
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

