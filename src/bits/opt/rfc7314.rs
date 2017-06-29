//! EDNS Options from RFC 7314

use ::bits::{Composer, ComposeResult, Parser, ParseError, ParseResult};
use ::iana::OptionCode;
use super::{OptData, ParsedOptData};


//------------ Expire --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Expire(Option<u32>);

impl Expire {
    pub fn new(expire: Option<u32>) -> Self {
        Expire(expire)
    }

    pub fn expire(&self) -> Option<u32> {
        self.0
    }
}

impl OptData for Expire {
    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        let target = target.as_mut();
        target.compose_u16(OptionCode::EdnsExpire.into())?;
        match self.0 {
            Some(expire) => {
                target.compose_u16(4)?;
                target.compose_u32(expire)
            }
            None => {
                target.compose_u16(0)
            }
        }
    }
}

impl<'a> ParsedOptData<'a> for Expire {
    fn parse(code: OptionCode, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if code != OptionCode::EdnsExpire {
            return Ok(None)
        }
        match parser.remaining() {
            0 => Ok(Some(Self::new(None))),
            4 => Ok(Some(Self::new(Some(parser.parse_u32()?)))),
            _ => Err(ParseError::FormErr)
        }
    }
}

