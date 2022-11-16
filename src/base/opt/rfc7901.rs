//! EDNS Options from RFC 7901

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::name::{Dname, ToDname};
use super::super::octets::{
    Compose, OctetsBuilder, Octets, Parse, ParseError, Parser, ShortBuf
};
use super::CodeOptData;


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

    pub fn push<Target, N>(
        builder: &mut OptBuilder<Target>,
        start: &N
    ) -> Result<(), ShortBuf>
    where
        Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>,
        N: ToDname,
    {
        builder.push_raw_option(OptionCode::Chain, |target| {
            target.append_all(|target| {
                for label in start.iter_labels() {
                    label.compose(target)?
                }
                Ok(())
            })
        })
    }

    pub fn start(&self) -> &Dname<Octs> {
        &self.start
    }
}


//--- ParseAll and Compose

impl<'a, Octs: Octets> Parse<'a, Octs> for Chain<Octs::Range<'a>> {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        Dname::parse(parser).map(Self::new)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        Dname::skip(parser)
    }
}

impl<Octs: AsRef<[u8]>> Compose for Chain<Octs> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        self.start.compose(target)
    }
}


//--- CodeOptData

impl<Octs> CodeOptData for Chain<Octs> {
    const CODE: OptionCode = OptionCode::Chain;
}

