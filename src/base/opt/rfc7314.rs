//! EDNS Options from RFC 7314

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, Composer, Parse, ParseError, Parser, ShortBuf
};
use super::{CodeOptData, ComposeOptData};
use octseq::builder::OctetsBuilder;


//------------ Expire --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Expire(Option<u32>);

impl Expire {
    pub fn new(expire: Option<u32>) -> Self {
        Expire(expire)
    }

    pub fn push<Target: Composer>(
        builder: &mut OptBuilder<Target>,
        expire: Option<u32>
    ) -> Result<(), ShortBuf> {
        builder.push(&Self::new(expire))
    }

    pub fn expire(self) -> Option<u32> {
        self.0
    }
}

//--- Parse

impl<'a, Octs: AsRef<[u8]>> Parse<'a, Octs> for Expire {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        if parser.remaining() == 0 {
            Ok(Expire::new(None))
        }
        else {
            u32::parse(parser).map(|res| Expire::new(Some(res)))
        }
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        if parser.remaining() == 0 {
            Ok(())
        }
        else {
            parser.advance(4).map_err(Into::into)
        }
    }
}

//--- OptData

impl CodeOptData for Expire {
    const CODE: OptionCode = OptionCode::Expire;
}

impl ComposeOptData for Expire {
    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        if let Some(value) = self.0 {
            value.compose(target)?;
        }
        Ok(())
    }
}

