//! EDNS Options from RFC 7901

use crate::compose::{Compose, ComposeTarget};
use crate::iana::OptionCode;
// XXX use crate::message_builder::OptBuilder;
use crate::name::Dname;
use crate::parse::{ParseAll, Parser, ParseSource};
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

    /* XXX
    pub fn push<N: ToDname>(builder: &mut OptBuilder, start: &N)
                            -> Result<(), ShortBuf> {
        let len = start.compose_len();
        assert!(len <= ::std::u16::MAX as usize);
        builder.build(OptionCode::Chain, len as u16, |buf| {
            buf.compose(start)
        })
    }
    */

    pub fn start(&self) -> &Dname<Octets> {
        &self.start
    }
}


//--- ParseAll and Compose

impl<Octets: ParseSource> ParseAll<Octets> for Chain<Octets> {
    type Err = <Dname<Octets> as ParseAll<Octets>>::Err;

    fn parse_all(
        parser: &mut Parser<Octets>,
        len: usize
    ) -> Result<Self, Self::Err> {
        Dname::parse_all(parser, len).map(Self::new)
    }
}

impl<Octets: AsRef<[u8]>> Compose for Chain<Octets> {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        self.start.compose(target)
    }
}


//--- CodeOptData

impl<Octets> CodeOptData for Chain<Octets> {
    const CODE: OptionCode = OptionCode::Chain;
}

