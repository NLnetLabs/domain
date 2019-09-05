//! EDNS Options form RFC 7873

use crate::compose::{Compose, ComposeTarget};
use crate::iana::OptionCode;
// XXX use crate::message_builder::OptBuilder;
use crate::parse::{ParseAll, ParseAllError, Parser};
use super::CodeOptData;


//------------ Cookie --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cookie([u8; 8]);

impl Cookie {
    pub fn new(cookie: [u8; 8]) -> Self {
        Cookie(cookie)
    }

    /* XXX
    pub fn push(builder: &mut OptBuilder, cookie: [u8; 8])
                -> Result<(), ShortBuf> {
        builder.push(&Self::new(cookie))
    }
    */

    pub fn cookie(self) -> [u8; 8] {
        self.0
    }
}


//--- ParseAll and Compose

impl<Octets: AsRef<[u8]>> ParseAll<Octets> for Cookie {
    type Err = ParseAllError;

    fn parse_all(
        parser: &mut Parser<Octets>,
        len: usize
    ) -> Result<Self, Self::Err> {
        ParseAllError::check(8, len)?;
        let mut res = [0u8; 8];
        parser.parse_buf(&mut res[..])?;
        Ok(Self::new(res))
    }
}


impl Compose for Cookie {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
        target.append_slice(&self.0[..])
    }
}


//--- OptData

impl CodeOptData for Cookie {
    const CODE: OptionCode = OptionCode::Cookie;
}

