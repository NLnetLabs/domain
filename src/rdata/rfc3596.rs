//! Record data from [RFC 3596]: AAAA records.
//!
//! This RFC defines the Aaaa record type.
//!
//! [RFC 3596]: https://tools.ietf.org/html/rfc3596

use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::net::Ipv6Addr;
use crate::base::rdata::{ComposeRecordData, ParseRecordData, RecordData};
use crate::base::scan::{Scan, Scanner, ScannerError};
use crate::base::wire::{Composer, Parse, ParseError};
use octseq::octets::OctetsFrom;
use octseq::parse::Parser;
use core::cmp::Ordering;
use core::convert::Infallible;
use core::str::FromStr;
use core::{fmt, ops, str};

//------------ Aaaa ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Aaaa {
    addr: Ipv6Addr,
}

impl Aaaa {
    pub fn new(addr: Ipv6Addr) -> Aaaa {
        Aaaa { addr }
    }

    pub fn addr(&self) -> Ipv6Addr {
        self.addr
    }
    pub fn set_addr(&mut self, addr: Ipv6Addr) {
        self.addr = addr
    }

    pub(super) fn flatten_into<E>(self) -> Result<Aaaa, E> {
        Ok(self)
    }

    pub(super) fn convert_octets<E>(self) -> Result<Self, E> {
        Ok(self)
    }

    pub fn parse<'a, Octs: AsRef<[u8]> + ?Sized>(
        parser: &mut Parser<'a, Octs>
    ) -> Result<Self, ParseError> {
        Ipv6Addr::parse(parser).map(Self::new)
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
        Rtype::Aaaa
    }
}

impl<'a, Octs: AsRef<[u8]> + ?Sized> ParseRecordData<'a, Octs> for Aaaa {
    fn parse_rdata(
        rtype: Rtype, parser: &mut Parser<'a, Octs>
    ) -> Result<Option<Self>, ParseError> {
        if rtype == Rtype::Aaaa {
            Self::parse(parser).map(Some)
        }
        else {
            Ok(None)
        }
    }
}

impl ComposeRecordData for Aaaa {
    fn rdlen(&self, _compress: bool) -> Option<u16> {
        Some(16)
    }

    fn compose_rdata<Target: Composer + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        target.append_slice(&self.octets())
    }

    fn compose_canonical_rdata<Target: Composer + ?Sized>(
        &self, target: &mut Target
    ) -> Result<(), Target::AppendError> {
        self.compose_rdata(target)
    }
}

//--- Scan and Display

impl<S: Scanner> Scan<S> for Aaaa {
    fn scan(scanner: &mut S) -> Result<Self, S::Error> {
        let token = scanner.scan_octets()?;
        let token = str::from_utf8(token.as_ref())
            .map_err(|_| S::Error::custom("expected IPv6 address"))?;
        Aaaa::from_str(token)
            .map_err(|_| S::Error::custom("expected IPv6 address"))
    }
}

impl fmt::Display for Aaaa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}

//--- Deref and DerefMut

impl ops::Deref for Aaaa {
    type Target = Ipv6Addr;

    fn deref(&self) -> &Self::Target {
        &self.addr
    }
}

impl ops::DerefMut for Aaaa {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.addr
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
