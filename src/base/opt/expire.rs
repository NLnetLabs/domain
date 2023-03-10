//! EDNS Options from RFC 7314

use core::fmt;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Compose, Composer, Parse, ParseError};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::parse::Parser;


//------------ Expire --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Expire(Option<u32>);

impl Expire {
    pub fn new(expire: Option<u32>) -> Self {
        Expire(expire)
    }

    pub fn expire(self) -> Option<u32> {
        self.0
    }

    pub fn parse<Octs: AsRef<[u8]>>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        if parser.remaining() == 0 {
            Ok(Expire::new(None))
        }
        else {
            u32::parse(parser).map(|res| Expire::new(Some(res)))
        }
    }
}

//--- OptData

impl OptData for Expire {
    fn code(&self) -> OptionCode {
        OptionCode::Expire
    }
}

impl<'a, Octs: AsRef<[u8]>> ParseOptData<'a, Octs> for Expire {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::Expire {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeOptData for Expire {
    fn compose_len(&self) -> u16 {
        match self.0 {
            Some(_) => u32::COMPOSE_LEN,
            None => 0,
        }
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        if let Some(value) = self.0 {
            value.compose(target)?;
        }
        Ok(())
    }
}

impl fmt::Display for Expire {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            Some(expire) => expire.fmt(f),
            None => Ok(())
        }
    }
}

//------------ OptBuilder ----------------------------------------------------

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn expire(
        &mut self, expire: Option<u32>
    ) -> Result<(), Target::AppendError> {
        self.push(&Expire::new(expire))
    }
}

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use super::super::test::test_option_compose_parse;
    
    #[test]
    fn expire_compose_parse() {
        test_option_compose_parse(
            &Expire::new(None),
            |parser| Expire::parse(parser)
        );
        test_option_compose_parse(
            &Expire::new(Some(12)),
            |parser| Expire::parse(parser)
        );
    }
}

