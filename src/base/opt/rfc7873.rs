//! EDNS Options form RFC 7873

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Composer, ParseError};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::parse::Parser;


//------------ Cookie --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cookie([u8; 8]);

impl Cookie {
    pub fn new(cookie: [u8; 8]) -> Self {
        Cookie(cookie)
    }

    pub fn cookie(self) -> [u8; 8] {
        self.0
    }

    pub fn parse<'a, Octs: AsRef<[u8]>>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self, ParseError> {
        let mut res = [0u8; 8];
        parser.parse_buf(&mut res[..])?;
        Ok(Self::new(res))
    }
}


//--- OptData

impl OptData for Cookie {
    fn code(&self) -> OptionCode {
        OptionCode::Cookie
    }
}

impl<'a, Octs: AsRef<[u8]>> ParseOptData<'a, Octs> for Cookie {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::Cookie {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeOptData for Cookie {
    fn compose_len(&self) -> u16 {
        8
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.0[..])
    }
}


//------------ OptBuilder ----------------------------------------------------

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn cookie(
        &mut self, cookie: [u8; 8]
    ) -> Result<(), Target::AppendError> {
        self.push(&Cookie::new(cookie))
    }
}

