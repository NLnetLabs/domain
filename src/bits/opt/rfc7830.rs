//! EDNS Options from RFC 7830

use bytes::BufMut;
use rand::random;
use ::bits::compose::Compose;
use ::bits::error::ShortBuf;
use ::bits::message_builder::OptBuilder;
use ::bits::parse::{ParseAll, Parser};
use ::iana::OptionCode;
use super::CodeOptData;


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
    
    pub fn push(builder: &mut OptBuilder, len: u16, mode: PaddingMode)
                -> Result<(), ShortBuf> {
        builder.push(&Self::new(len, mode))
    }

    pub fn len(&self) -> u16 {
        self.len
    }

    pub fn mode(&self) -> PaddingMode {
        self.mode
    }
}


//--- ParseAll and Compose

impl ParseAll for Padding {
    type Err = ShortBuf;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        // XXX Check whether there really are all zeros.
        parser.advance(len)?;
        Ok(Padding::new(len as u16, PaddingMode::Zero))
    }
}

impl Compose for Padding {
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

impl CodeOptData for Padding {
    const CODE: OptionCode = OptionCode::Padding;
}

