//! EDNS Options from RFC 7830

use core::fmt;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, OctetsBuilder, Parse, ParseError, Parser, ShortBuf
};
use super::CodeOptData;


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
    // @TODO we're not storing the octets where the padding is non-zero.
}

impl Padding {
    pub fn new(len: u16) -> Self {
        Self::new_with_mode(len, PaddingMode::Zero)
    }

    pub fn new_with_mode(len: u16, mode: PaddingMode) -> Self {
        Padding { len, mode }
    }

    pub fn push<Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>>(
        builder: &mut OptBuilder<Target>,
        len: u16,
    ) -> Result<(), ShortBuf> {
        Self::push_with_mode(builder, len, PaddingMode::Zero)
    }

    pub fn push_with_mode<Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>>(
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

impl<Ref: AsRef<[u8]>> Parse<Ref> for Padding {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        // XXX Check whether there really are all zeros.
        let len = parser.remaining();
        parser.advance(len)?;
        Ok(Padding::new_with_mode(len as u16, PaddingMode::Zero))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance_to_end();
        Ok(())
    }
}

impl Compose for Padding {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
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
                #[cfg(feature = "random")]
                PaddingMode::Random => {
                    for _ in 0..self.len {
                        ::rand::random::<u8>().compose(target)?
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

impl fmt::Display for Padding {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.mode {
            PaddingMode::Zero => {
                write!(f, "{}", self.len)?;
            }
            #[cfg(feature = "random")]
            PaddingMode::Random => {
            // @TODO fix when we're  storing the octets where
            // the padding is non-zero.
            }
        }
        Ok(())
    }
}
