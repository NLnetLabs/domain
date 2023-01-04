//! EDNS Options from RFC 7901

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::name::{Dname, ToDname};
use super::super::wire::{Composer, ParseError};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::octets::Octets;
use octseq::parse::Parser;


//------------ Chain --------------------------------------------------------

// TODO Impl more traits. We can’t derive them because that would force
//      trait boundaries on Octs.
#[derive(Clone)]
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


//------------ OptBuilder ----------------------------------------------------

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn chain(
        &mut self, start: impl ToDname
    ) -> Result<(), Target::AppendError> {
        self.push(&Chain::new(start))
    }
}

