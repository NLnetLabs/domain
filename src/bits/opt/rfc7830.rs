//! EDNS Options from RFC 7830

use rand::random;
use ::bits::{Composer, ComposeResult, Parser, ParseResult};
use ::iana::OptionCode;
use super::{OptData, ParsedOptData};


//------------ PaddingMode ---------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PaddingMode {
    Zero,
    Random,
}


//------------ Padding -------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Padding {
    len: u16,
    mode: PaddingMode
}


impl Padding {
    pub fn new(len: u16, mode: PaddingMode) -> Self {
        Padding { len, mode }
    }

    pub fn len(&self) -> u16 {
        self.len
    }

    pub fn mode(&self) -> PaddingMode {
        self.mode
    }
}

impl OptData for Padding {
    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        let target = target.as_mut();
        target.compose_u16(OptionCode::Padding.into())?;
        target.compose_u16(self.len)?;
        match self.mode {
            PaddingMode::Zero => {
                target.compose_empty(self.len as usize)
            }
            PaddingMode::Random => {
                for _ in 0..self.len {
                    target.compose_u8(random())?
                }
                Ok(())
            }
        }
    }
}

impl<'a> ParsedOptData<'a> for Padding {
    fn parse(code: OptionCode, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if code != OptionCode::Padding {
            return Ok(None)
        }
        Ok(Some(Padding::new(parser.remaining() as u16, PaddingMode::Zero)))
    }
}
