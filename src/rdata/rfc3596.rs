//! Record data from [RFC 3596]: AAAA records.
//!
//! This RFC defines the Aaaa record type.
//!
//! [RFC 3596]: https://tools.ietf.org/html/rfc3596

use core::{fmt, ops};
use core::cmp::Ordering;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::net::Ipv6Addr;
use crate::base::octets::{
    Compose, Convert, OctetsBuilder, Parse, ParseError, Parser, ShortBuf
};
use crate::base::rdata::RtypeRecordData;
#[cfg(feature="master")] use crate::master::scan::{
    CharSource, Scan, Scanner, ScanError
};


//------------ Aaaa ---------------------------------------------------------

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Aaaa {
    addr: Ipv6Addr
}

impl Aaaa {
    pub fn new(addr: Ipv6Addr) -> Aaaa {
        Aaaa { addr }
    }

    pub fn addr(&self) -> Ipv6Addr { self.addr }
    pub fn set_addr(&mut self, addr: Ipv6Addr) { self.addr = addr }
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

#[cfg(feature = "std")]
impl core::str::FromStr for Aaaa {
    type Err = <Ipv6Addr as core::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ipv6Addr::from_str(s).map(Aaaa::new)
    }
}


//--- CanonicalOrd

impl CanonicalOrd for Aaaa {
    fn canonical_cmp(&self, other: &Self) -> Ordering {
        self.cmp(other)
    }
}


//--- Convert

impl Convert<Aaaa> for Aaaa {
    fn convert(&self) -> Result<Aaaa, ShortBuf> {
        Ok(self.clone())
    }
}


//--- Parse and Compose

impl<Ref: AsRef<[u8]>> Parse<Ref> for Aaaa {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        Ipv6Addr::parse(parser).map(Self::new)
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        Ipv6Addr::skip(parser)
    }
}

impl Compose for Aaaa {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        self.addr.compose(target)
    }
}


//--- Scan and Display

#[cfg(feature="master")]
impl Scan for Aaaa {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        scanner.scan_string_phrase(|res| {
            core::str::FromStr::from_str(&res).map_err(Into::into)
        })
    }
}

impl fmt::Display for Aaaa {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}


//--- RecordData

impl RtypeRecordData for Aaaa {
    const RTYPE: Rtype = Rtype::Aaaa;
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

