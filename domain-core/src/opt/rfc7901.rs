//! EDNS Options from RFC 7901

use crate::iana::OptionCode;
use crate::message_builder::OptBuilder;
use crate::name::{Dname, ToDname};
use crate::octets::{
    Compose, OctetsBuilder, OctetsRef, Parse, ParseError, Parser, ShortBuf
};
use super::CodeOptData;


//------------ Chain --------------------------------------------------------

// TODO Impl more traits. We can’t derive them because that would force
//      trait boundaries on Octets.
#[derive(Clone)]
pub struct Chain<Octets> {
    start: Dname<Octets>,
}

impl<Octets> Chain<Octets> {
    pub fn new(start: Dname<Octets>) -> Self {
        Chain { start }
    }

    pub fn push<Target: OctetsBuilder, N: ToDname>(
        builder: &mut OptBuilder<Target>,
        start: &N
    ) -> Result<(), ShortBuf> {
        builder.append_raw_option(OptionCode::Chain, |target| {
            target.append_all(|target| {
                for label in start.iter_labels() {
                    label.compose(target)?
                }
                Ok(())
            })
        })
    }

    pub fn start(&self) -> &Dname<Octets> {
        &self.start
    }
}


//--- ParseAll and Compose

impl<Ref: OctetsRef> Parse<Ref> for Chain<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        Dname::parse(parser).map(Self::new)
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        Dname::skip(parser)
    }
}

impl<Octets: AsRef<[u8]>> Compose for Chain<Octets> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        self.start.compose(target)
    }
}


//--- CodeOptData

impl<Octets> CodeOptData for Chain<Octets> {
    const CODE: OptionCode = OptionCode::Chain;
}

