//! EDNS Options from RFC 7901

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::name::{Dname, ToDname};
use super::super::octets::{
    Compose, Composer, Octets, Parse, ParseError, Parser,
    ShortBuf
};
use super::{CodeOptData, ComposeOptData};
use octseq::builder::OctetsBuilder;


//------------ Chain --------------------------------------------------------

// TODO Impl more traits. We can’t derive them because that would force
//      trait boundaries on Octs.
#[derive(Clone)]
pub struct Chain<Octs> {
    start: Dname<Octs>,
}

impl<Octs> Chain<Octs> {
    pub fn new(start: Dname<Octs>) -> Self {
        Chain { start }
    }

    pub fn push<Target: Composer, N: ToDname + Compose>(
        builder: &mut OptBuilder<Target>,
        start: &N
    ) -> Result<(), ShortBuf> {
        builder.push_raw_option(OptionCode::Chain, |target| {
            for label in start.iter_labels() {
                label.compose(target)?
            }
            Ok(())
        })
    }

    pub fn start(&self) -> &Dname<Octs> {
        &self.start
    }
}


//--- ParseAll

impl<'a, Octs: Octets> Parse<'a, Octs> for Chain<Octs::Range<'a>> {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        Dname::parse(parser).map(Self::new)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        Dname::skip(parser)
    }
}

//--- CodeOptData and ComposeOptData

impl<Octs> CodeOptData for Chain<Octs> {
    const CODE: OptionCode = OptionCode::Chain;
}

impl<Octs: AsRef<[u8]>> ComposeOptData for Chain<Octs> {
    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.start.compose(target)
    }
}

