//! Record data from [RFC 2782]: SRV records.
//!
//! This RFC defines the Srv record type.
//!
//! [RFC 2782]: https://tools.ietf.org/html/rfc2782

use core::fmt;
use core::cmp::Ordering;
use crate::base::cmp::CanonicalOrd;
use crate::base::iana::Rtype;
use crate::base::name::{ParsedDname, ToDname};
use crate::base::octets::{
    Compose, Convert, OctetsBuilder, OctetsRef, Parse, Parser, ParseError,
    ShortBuf
};
use crate::base::rdata::RtypeRecordData;
#[cfg(feature="master")] use crate::master::scan::{
    CharSource, Scan, Scanner, ScanError
};


//------------ Srv ---------------------------------------------------------

#[derive(Clone, Debug, Hash)]
pub struct Srv<N> {
    priority: u16,
    weight: u16,
    port: u16,
    target: N
}

impl<N> Srv<N> {
    pub const RTYPE: Rtype = Rtype::Srv;

    pub fn new(priority: u16, weight: u16, port: u16, target: N) -> Self {
        Srv { priority, weight, port, target }
    }

    pub fn into_target(self) -> N {
        self.target
    }

    pub fn priority(&self) -> u16 {
        self.priority
    }

    pub fn weight(&self) -> u16 {
        self.weight
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn target(&self) -> &N {
        &self.target
    }
}


//--- PartialEq and Eq

impl<N, NN> PartialEq<Srv<NN>> for Srv<N>
where N: ToDname, NN: ToDname {
    fn eq(&self, other: &Srv<NN>) -> bool {
        self.priority == other.priority
        && self.weight == other.weight
        && self.port == other.port
        && self.target.name_eq(&other.target)
    }
}

impl<N: ToDname> Eq for Srv<N> { }


//--- PartialOrd, Ord, and CanonicalOrd

impl<N, NN> PartialOrd<Srv<NN>> for Srv<N>
where N: ToDname, NN: ToDname {
    fn partial_cmp(&self, other: &Srv<NN>) -> Option<Ordering> {
        match self.priority.partial_cmp(&other.priority) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.weight.partial_cmp(&other.weight) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        match self.port.partial_cmp(&other.port) {
            Some(Ordering::Equal) => { }
            other => return other
        }
        Some(self.target.name_cmp(&other.target))
    }
}

impl<N: ToDname> Ord for Srv<N> {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => { }
            other => return other
        }
        match self.weight.cmp(&other.weight) {
            Ordering::Equal => { }
            other => return other
        }
        match self.port.cmp(&other.port) {
            Ordering::Equal => { }
            other => return other
        }
        self.target.name_cmp(&other.target)
    }
}

impl<N: ToDname, NN: ToDname> CanonicalOrd<Srv<NN>> for Srv<N> {
    fn canonical_cmp(&self, other: &Srv<NN>) -> Ordering {
        match self.priority.cmp(&other.priority) {
            Ordering::Equal => { }
            other => return other
        }
        match self.weight.cmp(&other.weight) {
            Ordering::Equal => { }
            other => return other
        }
        match self.port.cmp(&other.port) {
            Ordering::Equal => { }
            other => return other
        }
        self.target.lowercase_composed_cmp(&other.target)
    }
}


//--- Convert

impl<N, Other> Convert<Srv<Other>> for Srv<N>
where N: Convert<Other> {
    fn convert(&self) -> Result<Srv<Other>, ShortBuf> {
        Ok(Srv::new(self.priority, self.weight, self.port, self.target.convert()?))
    }
}


//--- Parse and Compose

impl<Ref: OctetsRef> Parse<Ref> for Srv<ParsedDname<Ref>> {
    fn parse(parser: &mut Parser<Ref>) -> Result<Self, ParseError> {
        Ok(Self::new(
            u16::parse(parser)?,
            u16::parse(parser)?,
            u16::parse(parser)?,
            ParsedDname::parse(parser)?
        ))
    }

    fn skip(parser: &mut Parser<Ref>) -> Result<(), ParseError> {
        u16::skip(parser)?;
        u16::skip(parser)?;
        u16::skip(parser)?;
        ParsedDname::skip(parser)
    }
}

impl<N: Compose> Compose for Srv<N> {
    fn compose<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.priority.compose(buf)?;
            self.weight.compose(buf)?;
            self.port.compose(buf)?;
            self.target.compose(buf)
        })
    }

    fn compose_canonical<T: OctetsBuilder>(
        &self,
        target: &mut T
    ) -> Result<(), ShortBuf> {
        target.append_all(|buf| {
            self.priority.compose(buf)?;
            self.weight.compose(buf)?;
            self.port.compose(buf)?;
            self.target.compose_canonical(buf)
        })
    }
}


//--- RtypeRecordData

impl<N> RtypeRecordData for Srv<N> {
    const RTYPE: Rtype = Rtype::Srv;
}


//--- Scan and Display
 
#[cfg(feature="master")]
impl<N: Scan> Scan for Srv<N> {
    fn scan<C: CharSource>(scanner: &mut Scanner<C>)
                           -> Result<Self, ScanError> {
        Ok(Self::new(u16::scan(scanner)?, u16::scan(scanner)?,
                     u16::scan(scanner)?, N::scan(scanner)?))
    }
}

impl<N: fmt::Display> fmt::Display for Srv<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {} {} {}", self.priority, self.weight, self.port,
               self.target)
    }
}

