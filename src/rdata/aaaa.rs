//! Record data from [RFC 3596]: AAAA records.
//!
//! This RFC defines the Aaaa record type.
//!
//! [RFC 3596]: https://tools.ietf.org/html/rfc3596

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::net::Ipv6Addr;
use crate::base::rdata::{ComposeRecordData, ParseRecordData, RecordData};
use crate::base::scan::{Scanner, ScannerError};
use crate::base::wire::{Composer, Parse, ParseError};
use crate::zonefile::present::Present;
use core::cmp::Ordering;
use core::convert::Infallible;
use core::str::FromStr;
use core::{fmt, str};
use octseq::octets::OctetsFrom;
use octseq::parse::Parser;

//------------ Aaaa ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Aaaa {
    addr: Ipv6Addr,
}

impl Aaaa {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::AAAA;
}

impl Aaaa {
    #[must_use]
    pub fn new(addr: Ipv6Addr) -> Aaaa {
        Aaaa { addr }
    }

    #[must_use]
    pub fn addr(&self) -> Ipv6Addr {
        self.addr
    }
    pub fn set_addr(&mut self, addr: Ipv6Addr) {
        self.addr = addr
    }

    pub(super) fn convert_octets<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    pub(super) fn flatten<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>,
    ) -> Result<Self, ParseError> {
        Ipv6Addr::parse(parser).map(Self::new)
    }

    pub fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Error> {
        let token = scanner.scan_octets()?;
        let token = str::from_utf8(token.as_ref())
            .map_err(|_| S::Error::custom("expected IPv6 address"))?;
        Aaaa::from_str(token)
            .map_err(|_| S::Error::custom("expected IPv6 address"))
    }
}

//--- From and FromStr

impl From<Ipv6Addr> for Aaaa {
    fn from(addr: Ipv6Addr) -> Self {
        Self::new(addr)
    }
}

impl From<Aaaa> for Ipv6Addr {
    fn from(data: Aaaa) -> Self {
        data.addr
    }
}

impl FromStr for Aaaa {
    type Err = <Ipv6Addr as core::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv6Addr::from_str(s).map(Aaaa::new)
    }
}

//--- OctetsFrom

impl OctetsFrom<Aaaa> for Aaaa {
    type Error = Infallible;

    fn try_octets_from(source: Aaaa) -> Result<Self, Self::Error> {
        Ok(source)
    }
}

//--- CanonicalOrd

impl CanonicalOrd for Aaaa {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl RecordData for Aaaa {
    fn rtype(&self) -> Rtype {
        Self::RTYPE
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> ParseRecordData<'a, Octs> for Aaaa {
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Self::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl ComposeRecordData for Aaaa {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(16)
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.addr().octets())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display

impl fmt::Display for Aaaa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}

//--- Present

impl Present for Aaaa {
    fn present(&self, f: &mut crate::zonefile::present::ZoneFileFormatter) -> fmt::Result {
        use std::fmt::Write;
        write!(f, "{}", self.addr)
    }
}

//--- AsRef and AsMut

impl AsRef<Ipv6Addr> for Aaaa {
    fn as_ref(&self) -> &Ipv6Addr {
        &self.addr
    }
}

impl AsMut<Ipv6Addr> for Aaaa {
    fn as_mut(&mut self) -> &mut Ipv6Addr {
        &mut self.addr
    }
}

//============ Testing ======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };

    #[test]
    fn aaaa_compose_parse_scan() {
        let addr = "2001:db9::12:13";
        let rdata = Aaaa::from_str(addr).unwrap();
        test_rdlen(&rdata);
        test_compose_parse(&rdata, Aaaa::parse);
        test_scan(&[addr], Aaaa::scan, &rdata);
    }
}
