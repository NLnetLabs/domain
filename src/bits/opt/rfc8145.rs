//! EDNS Options from RFC 8145.

use bytes::{BigEndian, BufMut, ByteOrder, Bytes};
use ::bits::compose::Composable;
use ::bits::error::ShortBuf;
use ::bits::message_builder::OptBuilder;
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

    pub fn push(builder: &mut OptBuilder, tags: &[u16])
                -> Result<(), ShortBuf> {
        let len = tags.len() * 2;
        assert!(len <= ::std::u16::MAX as usize);
        builder.build(OptionCode::EdnsKeyTag, len as u16, |buf| {
            for tag in tags {
                buf.compose(&tag)?
            }
            Ok(())
        })
    }

    pub fn iter(&self) -> KeyTagIter {
        KeyTagIter(self.bytes.as_ref())
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

impl<'a> IntoIterator for &'a KeyTag {
    type Item = u16;
    type IntoIter = KeyTagIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ KeyTagIter ----------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct KeyTagIter<'a>(&'a [u8]);

impl<'a> Iterator for KeyTagIter<'a> {
    type Item = u16;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.len() < 2 {
            None
        }
        else {
            let (item, tail) = self.0.split_at(2);
            self.0 = tail;
            Some(BigEndian::read_u16(item))
        }
    }
}

