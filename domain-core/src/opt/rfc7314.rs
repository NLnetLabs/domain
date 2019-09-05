//! EDNS Options from RFC 7314

use crate::compose::{Compose, ComposeTarget};
use crate::iana::OptionCode;
// XXX use crate::message_builder::OptBuilder;
use crate::parse::{ParseAll, Parser, ParseAllError};
use super::CodeOptData;


//------------ Expire --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Expire(Option<u32>);

impl Expire {
    pub fn new(expire: Option<u32>) -> Self {
        Expire(expire)
    }

    /* XXX
    pub fn push(builder: &mut OptBuilder, expire: Option<u32>)
                -> Result<(), ShortBuf> {
        builder.push(&Self::new(expire))
    }
    */

    pub fn expire(self) -> Option<u32> {
        self.0
    }
}


//--- ParseAll and Compose

impl<Octets: AsRef<[u8]>> ParseAll<Octets> for Expire {
    type Err = ParseAllError;

    fn parse_all(
        parser: &mut Parser<Octets>,
        len: usize
    ) -> Result<Self, Self::Err> {
        if len == 0 {
            Ok(Expire::new(None))
        }
        else {
            u32::parse_all(parser, len).map(|res| Expire::new(Some(res)))
        }
    }
}

impl Compose for Expire {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        if let Some(value) = self.0 {
            value.compose(target)
        }
    }
}


//--- OptData

impl CodeOptData for Expire {
    const CODE: OptionCode = OptionCode::Expire;
}

