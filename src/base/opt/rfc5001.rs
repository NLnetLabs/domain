/// EDNS0 Options from RFC 5001.

use core::fmt;
use super::super::iana::OptionCode;
use super::super::message_builder::OptBuilder;
use super::super::octets::{
    Compose, OctetsBuilder, Octets, Parse, ParseError, Parser, ShortBuf
};
use super::CodeOptData;


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
}

impl Nsid<()> {
    pub fn push<Target, Data>(
        builder: &mut OptBuilder<Target>,
        data: &Data
    ) -> Result<(), ShortBuf>
    where
        Target: OctetsBuilder + AsRef<[u8]> + AsMut<[u8]>,
        Data: AsRef<[u8]>,
    {
        let data = data.as_ref();
        assert!(data.len() <= core::u16::MAX as usize);
        builder.push_raw_option(OptionCode::Nsid, |target| {
            target.append_slice(data)
        })
    }
}

impl<'a, Octs: Octets> Parse<'a, Octs> for Nsid<Octs::Range<'a>> {
    fn parse(parser: &mut Parser<'a, Octs>) -> Result<Self, ParseError> {
        let len = parser.remaining();
        parser.parse_octets(len).map(Nsid::from_octets).map_err(Into::into)
    }

    fn skip(parser: &mut Parser<'a, Octs>) -> Result<(), ParseError> {
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octs> CodeOptData for Nsid<Octs> {
    const CODE: OptionCode = OptionCode::Nsid;
}


impl<Octs: AsRef<[u8]>> Compose for Nsid<Octs> {
    fn compose<T: OctetsBuilder + AsMut<[u8]>>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        assert!(self.octets.as_ref().len() < core::u16::MAX as usize);
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

