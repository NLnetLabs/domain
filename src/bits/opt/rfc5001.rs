/// EDNS0 Options from RFC 5001.

use std::fmt;
use bytes::{BufMut, Bytes};
use ::bits::compose::Compose;
use ::bits::error::ShortBuf;
use ::bits::message_builder::OptBuilder;
use ::bits::parse::{ParseAll, Parser};
use ::iana::OptionCode;
use super::CodeOptData;


//------------ Nsid ---------------------------------------------------------/

/// The Name Server Identifier (NSID) Option.
///
/// Specified in RFC 5001.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Nsid {
    bytes: Bytes
}

impl Nsid {
    pub fn new(bytes: Bytes) -> Self {
        Nsid { bytes }
    }

    pub fn push<T: AsRef<[u8]>>(builder: &mut OptBuilder, data: &T)
                                -> Result<(), ShortBuf> {
        let data = data.as_ref();
        assert!(data.len() <= ::std::u16::MAX as usize);
        builder.build(OptionCode::Nsid, data.len() as u16, |buf| {
            buf.compose(data)
        })
    }
}

impl ParseAll for Nsid {
    type Err = ShortBuf;

    fn parse_all(parser: &mut Parser, len: usize) -> Result<Self, Self::Err> {
        parser.parse_bytes(len).map(Nsid::new)
    }
}

impl CodeOptData for Nsid {
    const CODE: OptionCode = OptionCode::Nsid;
}


impl Compose for Nsid {
    fn compose_len(&self) -> usize {
        self.bytes.len()
    }

    fn compose<B: BufMut>(&self, buf: &mut B) {
        assert!(self.bytes.len() < ::std::u16::MAX as usize);
        buf.put_slice(self.bytes.as_ref())
    }
}

impl fmt::Display for Nsid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // RFC 5001 § 2.4:
        // | User interfaces MUST read and write the contents of the NSID
        // | option as a sequence of hexadecimal digits, two digits per
        // | payload octet.
        for v in self.bytes.as_ref() {
            write!(f, "{:X}", *v)?
        }
        Ok(())
    }
}


