//! EDNS Options from RFC 7830

use core::fmt;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Compose, Composer, ParseError};
use super::{OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::parse::Parser;


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
        Self::with_mode(len, PaddingMode::Zero)
    }

    pub fn with_mode(len: u16, mode: PaddingMode) -> Self {
        Padding { len, mode }
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

    pub fn parse<Octs: AsRef<[u8]>>(
        parser: &mut Parser<Octs>
    ) -> Result<Self, ParseError> {
        // XXX Check whether there really are all zeros.
        let len = parser.remaining();
        parser.advance(len)?;
        Ok(Padding::with_mode(len as u16, PaddingMode::Zero))
    }
}

//--- OptData

impl OptData for Padding {
    fn code(&self) -> OptionCode {
        OptionCode::Padding
    }
}

impl<'a, Octs: AsRef<[u8]>> ParseOptData<'a, Octs> for Padding {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::Padding {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeOptData for Padding {
    fn compose_len(&self) -> u16 {
        self.len
    }

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

impl fmt::Display for Padding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.mode {
            PaddingMode::Zero => {
                write!(f, "{} zeros", self.len)
            }
            #[cfg(feature = "random")]
            PaddingMode::Random => {
                write!(f, "{} random bytes", self.len)
            }
        }
    }
}

//------------ OptBuilder ----------------------------------------------------

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn padding(&mut self, len: u16) -> Result<(), Target::AppendError> {
        self.push(&Padding::new(len))
    }

    pub fn padding_with_mode(
        &mut self, len: u16, mode: PaddingMode
    ) -> Result<(), Target::AppendError> {
        self.push(&Padding::with_mode(len, mode))
    }
}

