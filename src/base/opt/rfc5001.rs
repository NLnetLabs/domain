/// EDNS0 Options from RFC 5001.

use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Composer, Octets, OctetsBuilder, ParseError, Parser,
};
use super::{OptData, ComposeOptData, ParseOptData};
use core::fmt;


//------------ Nsid ---------------------------------------------------------/

/// The Name Server Identifier (NSID) Option.
///
/// Specified in RFC 5001.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Nsid<Octs> {
    octets: Octs,
}

impl<Octs> Nsid<Octs> {
    pub fn from_octets(octets: Octs) -> Self {
        Nsid { octets }
    }

    pub fn parse<'a, Src: Octets<Range<'a> = Octs> + ?Sized>(
        parser: &mut Parser<'a, Src>
    ) -> Result<Self, ParseError> {
        let len = parser.remaining();
        parser.parse_octets(len).map(Nsid::from_octets).map_err(Into::into)
    }
}

impl<Octs> OptData for Nsid<Octs> {
    fn code(&self) -> OptionCode {
        OptionCode::Nsid
    }
}

impl<'a, Octs: Octets> ParseOptData<'a, Octs> for Nsid<Octs::Range<'a>> {
    fn parse_option(
        code: OptionCode,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if code == OptionCode::Nsid {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl<Octs: AsRef<[u8]>> ComposeOptData for Nsid<Octs> {
    fn compose_len(&self) -> u16 {
        self.octets.as_ref().len().try_into().expect("long option data")
    }

    fn compose_option<Target: OctetsBuilder + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(self.octets.as_ref())
    }
}

impl<Octs: AsRef<[u8]>> fmt::Display for Nsid<Octs> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // RFC 5001 § 2.4:
        // | User interfaces MUST read and write the contents of the NSID
        // | option as a sequence of hexadecimal digits, two digits per
        // | payload octet.
        for v in self.octets.as_ref() {
            write!(f, "{:X}", *v)?
        }
        Ok(())
    }
}


//------------ OptBuilder ----------------------------------------------------

impl<'a, Target: Composer> OptBuilder<'a, Target> {
    pub fn nsid(
        &mut self, data: &impl AsRef<[u8]>
    ) -> Result<(), Target::AppendError> {
        self.push(&Nsid::from_octets(data.as_ref()))
    }
}

