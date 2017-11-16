//! EDNS Options from RFC 8145.

use bytes::{BufMut, Bytes};
use ::bits::compose::Composable;
use ::bits::parse::Parser;
use ::iana::OptionCode;
use super::{OptData, OptionParseError};


//------------ KeyTag -------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct KeyTag {
    bytes: Bytes,
}

impl KeyTag {
    pub fn new(bytes: Bytes) -> Self {
        KeyTag { bytes }
    }
}

impl Composable for KeyTag {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.bytes.as_ref())
    }
}

impl OptData for KeyTag {
    type ParseErr = OptionParseError;

    fn code(&self) -> OptionCode {
        OptionCode::EdnsKeyTag
    }

    fn parse(code: OptionCode, len: usize, parser: &mut Parser)
             -> Result<Option<Self>, OptionParseError> {
        if code != OptionCode::EdnsKeyTag {
            return Ok(None)
        }
        if len % 2 == 1 {
            return Err(OptionParseError::InvalidLength(len))
        }
        Ok(Some(Self::new(parser.parse_bytes(len)?)))
    }
}
