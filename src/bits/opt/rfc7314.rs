//! EDNS Options from RFC 7314

use bytes::BufMut;
use ::bits::compose::Composable;
use ::bits::parse::Parser;
use ::iana::OptionCode;
use super::{OptData, OptionParseError};


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


//--- Composable and OptData

impl Composable for Expire {
    fn compose_len(&self) -> usize {
        match self.0 {
            Some(_) => 4,
            None => 0,
        }
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        if let Some(value) = self.0 {
            value.compose(buf)
        }
    }
}

impl OptData for Expire {
    type ParseErr = OptionParseError;

    fn code(&self) -> OptionCode {
        OptionCode::EdnsExpire
    }

    fn parse(code: OptionCode, len: usize, parser: &mut Parser)
             -> Result<Option<Self>, Self::ParseErr> {
        if code != OptionCode::EdnsExpire {
            return Ok(None)
        }
        match len {
            0 => Ok(Some(Self::new(None))),
            4 => Ok(Some(Self::new(Some(parser.parse_u32()?)))),
            _ => Err(OptionParseError::InvalidLength(len))
        }
    }
}

