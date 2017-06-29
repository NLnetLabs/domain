/// EDNS0 Options from RFC 5001.

use std::fmt;
use ::bits::{Composer, ComposeResult, Parser, ParseResult};
use ::iana::OptionCode;
use super::{OptData, ParsedOptData};


//------------ Nsid ---------------------------------------------------------/

/// The Name Server Identifier (NSID) Option.
///
/// Specified in RFC 5001.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Nsid<B: AsRef<[u8]>>(B);

impl<B: AsRef<[u8]>> Nsid<B> {
    pub fn new(data: B) -> Self {
        Nsid(data)
    }
}

impl<B: AsRef<[u8]>> OptData for Nsid<B> {
    fn compose<C: AsMut<Composer>>(&self, mut target: C) -> ComposeResult<()> {
        assert!(self.0.as_ref().len() < ::std::u16::MAX as usize);
        target.as_mut().compose_u16(OptionCode::Nsid.to_int())?;
        target.as_mut().compose_u16(self.0.as_ref().len() as u16)?;
        target.as_mut().compose_bytes(self.0.as_ref())
    }
}

impl<'a> ParsedOptData<'a> for Nsid<&'a [u8]> {
    fn parse(code: OptionCode, parser: &mut Parser<'a>)
             -> ParseResult<Option<Self>> {
        if let OptionCode::Nsid = code {
            parser.parse_remaining().map(|bytes| Some(Nsid(bytes)))
        }
        else {
            Ok(None)
        }
    }
}

impl<B: AsRef<[u8]>> fmt::Display for Nsid<B> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // RFC 5001 § 2.4:
        // | User interfaces MUST read and write the contents of the NSID
        // | option as a sequence of hexadecimal digits, two digits per
        // | payload octet.
        for v in self.0.as_ref() {
            write!(f, "{:X}", *v)?
        }
        Ok(())
    }
}


