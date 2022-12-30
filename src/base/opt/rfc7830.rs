//! EDNS Options from RFC 7830

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, Composer, Parse, ParseError, Parser, ShortBuf
};
use super::{CodeOptData, ComposeOptData};
use octseq::builder::OctetsBuilder;


//------------ PaddingMode ---------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PaddingMode {
    Zero,
    #[cfg(feature = "random")]
    Random,
}


//------------ Padding -------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Padding {
    len: u16,
    mode: PaddingMode
}

impl Padding {
    pub fn new(len: u16) -> Self {
        Self::new_with_mode(len, PaddingMode::Zero)
    }

    pub fn new_with_mode(len: u16, mode: PaddingMode) -> Self {
        Padding { len, mode }
    }

    pub fn push<Target: Composer>(
        builder: &mut OptBuilder<Target>,
        len: u16,
    ) -> Result<(), ShortBuf> {
        Self::push_with_mode(builder, len, PaddingMode::Zero)
    }

    pub fn push_with_mode<Target: Composer>(
        builder: &mut OptBuilder<Target>,
        len: u16,
        mode: PaddingMode
    ) -> Result<(), ShortBuf> {
        builder.push(&Self::new_with_mode(len, mode))
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

impl<'a, Octs: AsRef<[u8]>> Parse<'a, Octs> for Padding {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        // XXX Check whether there really are all zeros.
        let len = parser.remaining();
        parser.advance(len)?;
        Ok(Padding::new_with_mode(len as u16, PaddingMode::Zero))
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance_to_end();
        Ok(())
    }
}

//--- CodeOptData and ComposeOptData

impl CodeOptData for Padding {
    const CODE: OptionCode = OptionCode::Padding;
}

impl ComposeOptData for Padding {
    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        match self.mode {
            PaddingMode::Zero => {
                for _ in 0..self.len {
                    0u8.compose(target)?
                }
            }
            #[cfg(feature = "random")]
            PaddingMode::Random => {
                for _ in 0..self.len {
                    ::rand::random::<u8>().compose(target)?
                }
            }
        }
        Ok(())
    }
}

