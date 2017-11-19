//! EDNS Options form RFC 7873

use std::mem;
use bytes::BufMut;
use ::bits::compose::Composable;
use ::bits::error::ShortBuf;
use ::bits::message_builder::OptBuilder;
use ::bits::parse::Parser;
use ::iana::OptionCode;
use super::{OptData, OptionParseError};


//------------ Cookie --------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Cookie([u8; 8]);

impl Cookie {
    pub fn new(cookie: [u8; 8]) -> Self {
        Cookie(cookie)
    }

    pub fn push(builder: &mut OptBuilder, cookie: [u8; 8])
                -> Result<(), ShortBuf> {
        builder.push(&Self::new(cookie))
    }

    pub fn cookie(&self) -> &[u8; 8] {
        &self.0
    }
}


//--- Composable and OptData

impl Composable for Cookie {
    fn compose_len(&self) -> usize {
        8
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(&self.0[..])
    }
}

impl OptData for Cookie {
    type ParseErr = OptionParseError;

    fn code(&self) -> OptionCode {
        OptionCode::Cookie
    }

    fn parse(code: OptionCode, len: usize, parser: &mut Parser)
             -> Result<Option<Self>, OptionParseError> {
        if code != OptionCode::Cookie {
            return Ok(None)
        }
        if len != 8 {
            return Err(OptionParseError::InvalidLength(len))
        }
        let bytes: &[u8; 8] = unsafe {
            mem::transmute(parser.parse_bytes(8)?.as_ptr())
        };
        parser.advance(8)?;
        Ok(Some(Cookie::new(*bytes)))
    }
}

