//! EDNS Options form RFC 7873

use std::mem;
use ::bits::{Composer, ComposeResult, Parser, ParseResult};
use ::iana::OptionCode;
use super::{OptData, ParsedOptData};


//------------ Cookie --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cookie([u8; 8]);

impl Cookie {
    pub fn new(cookie: [u8; 8]) -> Self {
        Cookie(cookie)
    }

    pub fn cookie(&self) -> &[u8; 8] {
        &self.0
    }
}

impl OptData for Cookie {
    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        let target = target.as_mut();
        target.compose_u16(OptionCode::Cookie.into())?;
        target.compose_u16(8)?;
        target.compose_bytes(&self.0[..])
    }
}

impl<'a> ParsedOptData<'a> for Cookie {
    fn parse(code: OptionCode, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if code != OptionCode::Cookie {
            return Ok(None)
        }
        let bytes: &[u8; 8] = unsafe {
            mem::transmute(parser.parse_bytes(8)?.as_ptr())
        };
        parser.exhausted()?;
        Ok(Some(Cookie::new(*bytes)))
    }
}
