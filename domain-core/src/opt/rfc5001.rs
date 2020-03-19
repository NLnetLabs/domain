/// EDNS0 Options from RFC 5001.

use core::fmt;
use crate::iana::OptionCode;
use crate::message_builder::OptBuilder;
use crate::octets::{
    Compose, OctetsBuilder, OctetsRef, Parse, ParseError, Parser, ShortBuf
};
use super::CodeOptData;


//------------ Nsid ---------------------------------------------------------/

/// The Name Server Identifier (NSID) Option.
///
/// Specified in RFC 5001.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Nsid<Octets> {
    octets: Octets,
}

impl<Octets> Nsid<Octets> {
    pub fn from_octets(octets: Octets) -> Self {
        Nsid { octets }
    }
}

impl Nsid<()> {
    pub fn push<Target: OctetsBuilder, Data: AsRef<[u8]>>(
        builder: &mut OptBuilder<Target>,
        data: &Data
    ) -> Result<(), ShortBuf> {
        let data = data.as_ref();
        assert!(data.len() <= ::std::u16::MAX as usize);
        builder.append_raw_option(OptionCode::Nsid, |target| {
            target.append_slice(data)
        })
    }
}

impl<Ref: OctetsRef> Parse<Ref> for Nsid<Ref::Range> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        let len = parser.remaining();
        parser.parse_octets(len).map(Nsid::from_octets)
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        parser.advance_to_end();
        Ok(())
    }
}

impl<Octets> CodeOptData for Nsid<Octets> {
    const CODE: OptionCode = OptionCode::Nsid;
}


impl<Octets: AsRef<[u8]>> Compose for Nsid<Octets> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        assert!(self.octets.as_ref().len() < core::u16::MAX as usize);
        target.append_slice(self.octets.as_ref())
    }
}

impl<Octets: AsRef<[u8]>> fmt::Display for Nsid<Octets> {
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

