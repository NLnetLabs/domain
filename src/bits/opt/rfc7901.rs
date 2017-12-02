//! EDNS Options from RFC 7901

use bytes::BufMut;
use ::bits::compose::Compose;
use ::bits::message_builder::OptBuilder;
use ::bits::name::{Dname, ToDname};
use ::bits::parse::{ParseAll, Parser, ShortBuf};
use ::iana::OptionCode;
use super::CodeOptData;


//------------ Chain --------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Chain {
    start: Dname,
}

impl Chain {
    pub fn new(start: Dname) -> Self {
        Chain { start }
    }

    pub fn push<N: ToDname>(builder: &mut OptBuilder, start: &N)
                            -> Result<(), ShortBuf> {
        let len = start.compose_len();
        assert!(len <= ::std::u16::MAX as usize);
        builder.build(OptionCode::Chain, len as u16, |buf| {
            buf.compose(start)
        })
    }

    pub fn start(&self) -> &Dname {
        &self.start
    }
}


//--- ParseAll and Compose

impl ParseAll for Chain {
    type Err = <Dname as ParseAll>::Err;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        Dname::parse_all(parser, len).map(Self::new)
    }
}

impl Compose for Chain {
    fn compose_len(&self) -> usize {
        self.start.compose_len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        self.start.compose(buf)
    }
}


//--- CodeOptData

impl CodeOptData for Chain {
    const CODE: OptionCode = OptionCode::Chain;
}

