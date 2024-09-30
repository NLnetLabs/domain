//! Record data for the A record.
//!
//! This is a private module. It’s content is re-exported by the parent.

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::net::Ipv4Addr;
use crate::base::rdata::{ComposeRecordData, ParseRecordData, RecordData};
use crate::base::scan::{Scanner, ScannerError};
use crate::base::wire::{Composer, Parse, ParseError};
use crate::base::zonefile_fmt::{self, Formatter, ZonefileFmt};
use core::cmp::Ordering;
use core::convert::Infallible;
use core::str::FromStr;
use core::{fmt, str};
use octseq::octets::OctetsFrom;
use octseq::parse::Parser;

//------------ A ------------------------------------------------------------

/// A record data.
///
/// A records convey the IPv4 address of a host. The wire format is the 32
/// bit IPv4 address in network byte order. The representation file format
/// is the usual dotted notation.
///
/// The A record type is defined in [RFC 1035, section 3.4.1][1].
///
/// [1]: https://tools.ietf.org/html/rfc1035#section-3.4.1
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct A {
    addr: Ipv4Addr,
}

impl A {
    /// The rtype of this record data type.
    pub(crate) const RTYPE: Rtype = Rtype::A;
}

impl A {
    /// Creates a new A record data from an IPv4 address.
    #[must_use]
    pub fn new(addr: Ipv4Addr) -> A {
        A { addr }
    }

    /// Creates a new A record from the IPv4 address components.
    #[must_use]
    pub fn from_octets(a: u8, b: u8, c: u8, d: u8) -> A {
        A::new(Ipv4Addr::new(a, b, c, d))
    }

    #[must_use]
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }
    pub fn set_addr(&mut self, addr: Ipv4Addr) {
        self.addr = addr
    }

    pub(in crate::rdata) fn convert_octets<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    pub(in crate::rdata) fn flatten<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    pub fn parse<Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<Octs>,
    ) -> Result<Self, ParseError> {
        Ipv4Addr::parse(parser).map(Self::new)
    }

    pub fn scan<S: Scanner>(scanner: &mut S) -> Result<Self, S::Error> {
        let token = scanner.scan_octets()?;
        let token = str::from_utf8(token.as_ref())
            .map_err(|_| S::Error::custom("expected IPv4 address"))?;
        A::from_str(token)
            .map_err(|_| S::Error::custom("expected IPv4 address"))
    }
}

//--- OctetsFrom

impl OctetsFrom<A> for A {
    type Error = Infallible;

    fn try_octets_from(source: A) -> Result<Self, Self::Error> {
        Ok(source)
    }
}

//--- From and FromStr

impl From<Ipv4Addr> for A {
    fn from(addr: Ipv4Addr) -> Self {
        Self::new(addr)
    }
}

impl From<A> for Ipv4Addr {
    fn from(a: A) -> Self {
        a.addr
    }
}

impl FromStr for A {
    type Err = <Ipv4Addr as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv4Addr::from_str(s).map(A::new)
    }
}

//--- CanonicalOrd

impl CanonicalOrd for A {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}

//--- RecordData, ParseRecordData, ComposeRecordData

impl RecordData for A {
    fn rtype(&self) -> Rtype {
        A::RTYPE
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> ParseRecordData<'a, Octs> for A {
    fn parse_rdata(
        rtype: Rtype,
        parser: &mut Parser<'a, Octs>,
    ) -> Result<Option<Self>, ParseError> {
        if rtype == A::RTYPE {
            Self::parse(parser).map(Some)
        } else {
            Ok(None)
        }
    }
}

impl ComposeRecordData for A {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(4)
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.addr.octets())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self,
        target: &mut Target,
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Display

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}

//--- ZonefileFmt

impl ZonefileFmt for A {
    fn fmt(&self, p: &mut impl Formatter) -> zonefile_fmt::Result {
        p.write_token(self.addr)
    }
}

//--- AsRef and AsMut

impl AsRef<Ipv4Addr> for A {
    fn as_ref(&self) -> &Ipv4Addr {
        &self.addr
    }
}

impl AsMut<Ipv4Addr> for A {
    fn as_mut(&mut self) -> &mut Ipv4Addr {
        &mut self.addr
    }
}

//============ Testing =======================================================

#[cfg(test)]
#[cfg(all(feature = "std", feature = "bytes"))]
mod test {
    use super::*;
    use crate::base::rdata::test::{
        test_compose_parse, test_rdlen, test_scan,
    };

    #[test]
    fn a_compose_parse_scan() {
        let rdata = A::from_octets(1, 2, 3, 4);
        test_rdlen(&rdata);
        test_compose_parse(&rdata, A::parse);
        test_scan(&["1.2.3.4"], A::scan, &rdata);
    }
}
