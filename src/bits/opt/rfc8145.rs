//! EDNS Options from RFC 8145.

use ::bits::{Composer, ComposeResult, Parser, ParseError, ParseResult};
use ::iana::OptionCode;
use super::{OptData, ParsedOptData};


//------------ KeyTag -------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct KeyTag<B: AsRef<[u8]>>(B);

impl<B: AsRef<[u8]>> KeyTag<B> {
}

impl<'a> KeyTag<&'a [u8]> {
    pub fn new(bytes: &'a [u8]) -> Self {
        KeyTag(bytes)
    }
}

impl KeyTag<Vec<u8>> {
    pub fn new() -> Self {
        KeyTag(Vec::new())
    }

    pub fn push(&mut self, tag: u16) {
        if self.0.len() >= (0xFFFF - 2) {
            panic!("excessively large Keytag");
        }
        self.0.push((tag & 0xFF00 >> 8) as u8);
        self.0.push((tag & 0xFF) as u8);
    }
}

impl<B: AsRef<[u8]>> OptData for KeyTag<B> {
    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        assert!(self.0.as_ref().len() <= 0xFFFF);
        let target = target.as_mut();
        target.compose_u16(OptionCode::EdnsKeyTag.into())?;
        target.compose_u16(self.0.as_ref().len() as u16)?;
        target.compose_bytes(&self.0.as_ref())
    }
}

impl<'a> ParsedOptData<'a> for KeyTag<&'a [u8]> {
    fn parse(code: OptionCode, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if code != OptionCode::EdnsKeyTag {
            return Ok(None)
        }
        if parser.remaining() % 2 == 1 {
            Err(ParseError::FormErr)
        }
        else {
            Ok(Some(Self::new(parser.parse_remaining()?)))
        }
    }
}
