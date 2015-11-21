use std::net;
use super::error::Result;
use super::ingress::Fragment;
use super::name;


//------------ Record Data Trait --------------------------------------------

/// A trait for all record types.
///
///
pub trait RecordData: Sized {
    /// The integer value of the registered record type.
    ///
    fn rtype() -> u16;

    /// Parse the record data out of a fragment.
    ///
    fn from_fragment(frag: &mut Fragment) -> Result<Self>;
}



//------------ A ------------------------------------------------------------

/// A host address.
///
/// See RFC1035, section .
///
#[derive(Clone, Debug)]
pub struct A {
    pub addr: net::Ipv4Addr,
}

impl A {
    pub fn new(addr: net::Ipv4Addr) -> A {
        A { addr: addr }
    }
}

impl RecordData for A {
    fn rtype() -> u16 {
        1
    }

    fn from_fragment(frag: &mut Fragment) -> Result<A> {
        let a = try!(frag.parse_u8());
        let b = try!(frag.parse_u8());
        let c = try!(frag.parse_u8());
        let d = try!(frag.parse_u8());
        Ok(A::new(net::Ipv4Addr::new(a, b, c, d)))
    }
}


//------------ NS -----------------------------------------------------------

/// An authoritative name server.
///
/// See RFC1035, section 3.3.11.
///
#[derive(Clone, Debug)]
pub struct NS {
    /// Specifies a host which should be authoritative for the specified
    /// class and domain.
    ///
    pub nsdname: name::DomainNameBuf,
}

impl NS {
    pub fn new(nsdname: name::DomainNameBuf) -> NS {
        NS { nsdname: nsdname }
    }
}

impl RecordData for NS {
    fn rtype() -> u16 {
        2
    }

    fn from_fragment(frag: &mut Fragment) -> Result<NS> {
        Ok(NS { nsdname: try!(frag.parse_name()) })
    }
}
