//! EDNS Options from RFC 8145.

use bytes::{BigEndian, BufMut, ByteOrder, Bytes};
use ::bits::compose::Compose;
use ::bits::error::ShortBuf;
use ::bits::message_builder::OptBuilder;
use ::bits::parse::{ParseAll, ParseAllError, Parser};
use ::iana::OptionCode;
use super::CodeOptData;


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


//--- ParseAll and Compose

impl ParseAll for KeyTag {
    type Err = ParseAllError;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        if len % 2 == 1 {
            Err(ParseAllError::TrailingData)
        }
        else {
            Ok(Self::new(parser.parse_bytes(len)?))
        }
    }
}

impl Compose for KeyTag {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        buf.put_slice(self.bytes.as_ref())
    }
}


//--- CodeOptData

impl CodeOptData for KeyTag {
    const CODE: OptionCode = OptionCode::EdnsKeyTag;
}


//--- IntoIterator

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

