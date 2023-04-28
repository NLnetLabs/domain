//! EDNS options for paddin message sizes.
//!
//! The option in this module – [`Padding<Octs>`] – allows to increase the
//! size of a DNS message to any desired value. This can be helpful with
//! confidentialty.
//!
//! Since this option does not have any meaning for the receiver of a message,
//! you should generally just use the [`OptBuilder::padding`] and
//! [`OptBuilder::random_padding`] methods when constructing a message.

use core::{borrow, fmt, str};
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::wire::{Compose, Composer, ParseError};
use super::{LongOptData, OptData, ComposeOptData, ParseOptData};
use octseq::builder::OctetsBuilder;
use octseq::octets::Octets;
use octseq::parse::Parser;


//------------ Padding -------------------------------------------------------

/// Option data for the padding option.
///
/// This option is used to increase the size of a DNS message to a fixed
/// value so eavesdropper can’t dertermine information from the size.
///
/// Generally, you should not need to use this type. Instead, you can use
/// the [`OptBuilder::padding`] and [`OptBuilder::random_padding`] methods to
/// add padding to a message – and ignore it when receving one.
///
/// The option is defined in [RFC 7830](https://tools.ietf.org/html/rfc7830).
#[derive(Clone, Copy)]
pub struct Padding<Octs: ?Sized> {
    /// The padding octets.
    octets: Octs,
}

impl<Octs> Padding<Octs> {
    /// Creates a value from the padding octets.
    ///
    /// Returns an error if `octets` are longer than 65,535 octets.
    pub fn from_octets(octets: Octs) -> Result<Self, LongOptData>
    where Octs: AsRef<[u8]> {
        LongOptData::check_len(octets.as_ref().len())?;
        Ok(unsafe { Self::from_octets_unchecked(octets) })
    }

    /// Creates a value from the padding octets without checking.
    ///
    /// # Safety
    ///
    /// The caller needs to ensure that `octets` are not longer than
    /// 65,535 octets.
    pub unsafe fn from_octets_unchecked(octets: Octs) -> Self {
        Self { octets }
    }

    /// Parses a value from its wire formal.
    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        let len = parser.remaining();
        LongOptData::check_len(len)?;
        Ok(unsafe { Self::from_octets_unchecked(
            parser.parse_octets(len)?
        )})
    }
}

impl<Octs: ?Sized> Padding<Octs> {
    /// Returns a reference to the padding octets.
    pub fn as_octets(&self) -> &Octs {
        &self.octets
    }

    /// Converts the value into the padding octets.
    pub fn into_octets(self) -> Octs
    where
        Octs: Sized,
    {
        self.octets
    }

    /// Returns a slice of the padding octets.
    pub fn as_slice(&self) -> &[u8]
    where
        Octs: AsRef<[u8]>,
    {
        self.octets.as_ref()
    }
}

//--- AsRef and Borrow

impl<Octs: AsRef<[u8]> + ?Sized> AsRef<[u8]> for Padding<Octs> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> borrow::Borrow<[u8]> for Padding<Octs> {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

//--- OptData

impl<Octs> OptData for Padding<Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::Padding
    }
}

impl<'a, Octs: Octets> ParseOptData<'a, Octs> for Padding<Octs::Range<'a>> {
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

impl<Octs: AsRef<[u8]>> ComposeOptData for Padding<Octs> {
    fn compose_len(&self) -> u16 {
        self.octets.as_ref().len().try_into().expect("long option data")
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.octets.as_ref())
    }
}

//--- Display and Debug

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Display for Padding<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for v in self.octets.as_ref() {
            write!(f, "{:X} ", *v)?;
        }
        if let Ok(s) = str::from_utf8(self.octets.as_ref()) {
            write!(f, "({})", s)?;
        }
        Ok(())
    }
}

impl<Octs: AsRef<[u8]> + ?Sized> fmt::Debug for Padding<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Padding({})", self)
    }
}

//--- Extended OptBuilder

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn padding( &mut self, len: u16) -> Result<(), Target::AppendError> {
        self.push_raw_option(
            OptionCode::Padding,
            len,
            |target| {
                for _ in 0..len {
                    0u8.compose(target)?
                }
                Ok(())
            }
        )
    }

    #[cfg(feature = "rand")]
    pub fn random_padding(
        &mut self, len: u16
    ) -> Result<(), Target::AppendError> {
        self.push_raw_option(
            OptionCode::Padding,
            len,
            |target| {
                for _ in 0..len {
                    rand::random::<u8>().compose(target)?
                }
                Ok(())
            }
        )
    }
}

