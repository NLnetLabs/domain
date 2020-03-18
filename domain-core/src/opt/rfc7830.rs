//! EDNS Options from RFC 7830

use rand::random;
use crate::iana::OptionCode;
use crate::message_builder::OptBuilder;
use crate::octets::{
    Compose, OctetsBuilder, Parse, ParseError, Parser, ShortBuf
};
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
    
    pub fn push<Target: OctetsBuilder>(
        builder: &mut OptBuilder<Target>,
        len: u16,
        mode: PaddingMode
    ) -> Result<(), ShortBuf> {
        builder.push(&Self::new(len, mode))
    }

    pub fn len(self) -> u16 {
        self.len
    }

    pub fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn mode(self) -> PaddingMode {
        self.mode
    }
}


//--- Parse and Compose

impl<Ref: AsRef<[u8]>> Parse<Ref> for Padding {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        // XXX Check whether there really are all zeros.
        let len = parser.remaining();
        parser.advance(len)?;
        Ok(Padding::new(len as u16, PaddingMode::Zero))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance_to_end();
        Ok(())
    }
}

impl Compose for Padding {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|target| {
            match self.mode {
                PaddingMode::Zero => {
                    for _ in 0..self.len {
                        0u8.compose(target)?
                    }
                }
                PaddingMode::Random => {
                    for _ in 0..self.len {
                        random::<u8>().compose(target)?
                    }
                }
            }
            Ok(())
        })
    }
}

impl CodeOptData for Padding {
    const CODE: OptionCode = OptionCode::Padding;
}

