//! EDNS Options from RFC 7830

use rand::random;
use crate::iana::OptionCode;
use crate::message_builder::OptBuilder;
use crate::octets::{Compose, OctetsBuilder};
use crate::parse::{ParseAll, Parser, ShortBuf};
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


//--- ParseAll and Compose

impl<Octets: AsRef<[u8]>> ParseAll<Octets> for Padding {
    type Err = ShortBuf;

    fn parse_all(
        parser: &mut Parser<Octets>,
        len: usize
    ) -> Result<Self, Self::Err> {
        // XXX Check whether there really are all zeros.
        parser.advance(len)?;
        Ok(Padding::new(len as u16, PaddingMode::Zero))
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

