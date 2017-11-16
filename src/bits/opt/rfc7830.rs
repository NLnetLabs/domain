//! EDNS Options from RFC 7830

use bytes::BufMut;
use rand::random;
use ::bits::compose::Composable;
use ::bits::parse::{Parser, ShortParser};
use ::iana::OptionCode;
use super::OptData;


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

impl Composable for Padding {
    fn compose_len(&self) -> usize {
        self.len as usize
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        match self.mode {
            PaddingMode::Zero => {
                for _ in 0..self.len {
                    buf.put_u8(0)
                }
            }
            PaddingMode::Random => {
                for _ in 0..self.len {
                    buf.put_u8(random())
                }
            }
        }
    }
}

impl OptData for Padding {
    type ParseErr = ShortParser;

    fn code(&self) -> OptionCode {
        OptionCode::Padding
    }

    fn parse(code: OptionCode, len: usize, parser: &mut Parser)
             -> Result<Option<Self>, Self::ParseErr> {
        if code != OptionCode::Padding {
            return Ok(None)
        }
        parser.advance(len)?;
        Ok(Some(Padding::new(len as u16, PaddingMode::Zero)))
    }
}

