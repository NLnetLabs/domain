/// EDNS0 Options from RFC 5001.

use core::fmt;
use crate::compose::{Compose, ComposeTarget};
use crate::iana::OptionCode;
// XXX use crate::message_builder::OptBuilder;
use crate::parse::{ParseAll, Parser, ParseSource, ShortBuf};
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

    /* XXX
    pub fn push<T: AsRef<[u8]>>(builder: &mut OptBuilder, data: &T)
                                -> Result<(), ShortBuf> {
        let data = data.as_ref();
        assert!(data.len() <= ::std::u16::MAX as usize);
        builder.build(OptionCode::Nsid, data.len() as u16, |buf| {
            buf.compose(data)
        })
    }
    */
}

impl<Octets: ParseSource> ParseAll<Octets> for Nsid<Octets> {
    type Err = ShortBuf;

    fn parse_all(
        parser: &mut Parser<Octets>,
        len: usize
    ) -> Result<Self, Self::Err> {
        parser.parse_octets(len).map(Nsid::from_octets)
    }
}

impl<Octets> CodeOptData for Nsid<Octets> {
    const CODE: OptionCode = OptionCode::Nsid;
}


impl<Octets: AsRef<[u8]>> Compose for Nsid<Octets> {
    fn compose<T: ComposeTarget + ?Sized>(&self, target: &mut T) {
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

