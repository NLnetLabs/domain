//! Record data from RFC 1035.
//!
//! This RFC defines the initial set of record types.

use std::fmt;
use std::net;
use super::super::compose::ComposeBytes;
use super::super::error::{ComposeResult, ParseResult};
use super::super::flavor::{FlatFlavor, Flavor};
use super::super::iana::RRType;
use super::super::parse::ParseFlavor;
use super::traits::{FlatRecordData, RecordData};


//------------ dname_type! --------------------------------------------------

/// A macro for implementing a record data type with a single domain name.
///
/// Implements some basic methods plus the RecordData, FlatRecordData, and
/// Display traits.
macro_rules! dname_type {
    ($target:ident, $rtype:ident, $field:ident) => {
        impl<F: Flavor> $target<F> {
            pub fn new($field: F::DName) -> Self {
                $target { $field: $field }
            }

            pub fn $field(&self) -> &F::DName {
                &self.$field
            }
        }

        impl<F: Flavor> RecordData<F> for $target<F> {
            fn rtype(&self) -> RRType { RRType::$rtype }

            fn compose<C: ComposeBytes>(&self, target: &mut C)
                                        -> ComposeResult<()> {
                target.push_dname_compressed(&self.$field)
            }
        }

        impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for $target<F> {
            fn parse<P>(rtype: RRType, parser: &mut P)
                        -> ParseResult<Option<Self>>
                     where P: ParseFlavor<'a, F> {
                if rtype != RRType::$rtype { Ok(None) }
                else { Ok(Some($target::new(try!(parser.parse_name())))) }
            }
        }

        impl<F: Flavor> fmt::Display for $target<F> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                self.$field.fmt(f)
            }
        }
    }
}

//------------ A ------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct A {
    addr: net::Ipv4Addr,
}

impl A {
    pub fn new(addr: net::Ipv4Addr) -> A {
        A { addr: addr }
    }

    pub fn addr(&self) -> &net::Ipv4Addr { &self.addr }
    pub fn addr_mut(&mut self) -> &mut net::Ipv4Addr { &mut self.addr }
}

impl<F: Flavor> RecordData<F> for A {
    fn rtype(&self) -> RRType { RRType::A }
    
    fn compose<C: ComposeBytes>(&self, target: &mut C) -> ComposeResult<()> {
        for i in self.addr.octets().iter() {
            try!(target.push_u8(*i))
        }
        Ok(())
    }
}

impl<'a, F: FlatFlavor<'a>> FlatRecordData<'a, F> for A {
    fn parse<P>(rtype: RRType, parser: &mut P) -> ParseResult<Option<Self>>
             where P: ParseFlavor<'a, F> {
        if rtype != RRType::A { return Ok(None) }
        Ok(Some(A::new(net::Ipv4Addr::new(try!(parser.parse_u8()),
                                          try!(parser.parse_u8()),
                                          try!(parser.parse_u8()),
                                          try!(parser.parse_u8())))))
    }
}

impl fmt::Display for A {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.addr.fmt(f)
    }
}


//------------ CName --------------------------------------------------------

/// CNAME record data.
///
/// The CNAME record specifies the canonical or primary name for domain
/// name alias.
///
/// The CNAME type is defined in RFC 1035, section 3.3.1.
#[derive(Clone, Debug)]
pub struct CName<F: Flavor> {
    cname: F::DName
}

dname_type!(CName, CNAME, cname);


//------------ NS -----------------------------------------------------------

#[derive(Clone, Debug)]
pub struct NS<F: Flavor> {
    nsdname: F::DName
}

dname_type!(NS, NS, nsdname);

