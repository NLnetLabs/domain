use std::fmt::Debug;
use std::net;
use super::egress::Assembly;
use super::ingress::{self, Fragment};
use super::name;


//------------ Record Data Trait --------------------------------------------

/// A trait for assemblying record data.
///
/// This is separate from `RecordData` because we want to use trait objects
/// for keeping record data objects until we actually assemble the message.
/// However, `RecordData` is not object safe.
///
pub trait RecordDataAssembly: Debug {
    /// Assembles the wire format of the record data by pushing to `asm`.
    ///
    fn assemble(&self, assembly: &mut Assembly);
}

/// A trait for record data.
///
pub trait RecordData: RecordDataAssembly + Sized {
    /// The integer value of the registered record type.
    ///
    fn rtype() -> u16;

    /// The textual name of the record type.
    ///
    fn rname() -> &'static str;

    /// Parse the record data out of a fragment.
    ///
    fn parse(frag: &mut Fragment) -> ingress::Result<Self>;
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
    fn rtype() -> u16 { 1 }
    fn rname() -> &'static str { "A" }

    fn parse(frag: &mut Fragment) -> ingress::Result<A> {
        let a = try!(frag.parse_u8());
        let b = try!(frag.parse_u8());
        let c = try!(frag.parse_u8());
        let d = try!(frag.parse_u8());
        Ok(A::new(net::Ipv4Addr::new(a, b, c, d)))
    }
}

impl RecordDataAssembly for A {
    fn assemble(&self, asm: &mut Assembly) {
        let octets = self.addr.octets();
        asm.push_u8(octets[0]);
        asm.push_u8(octets[1]);
        asm.push_u8(octets[2]);
        asm.push_u8(octets[3]);
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
    fn rtype() -> u16 { 2 }
    fn rname() -> &'static str { "NS" }

    fn parse(frag: &mut Fragment) -> ingress::Result<NS> {
        Ok(NS { nsdname: try!(frag.parse_name()) })
    }
}

impl RecordDataAssembly for NS {
    fn assemble(&self, asm: &mut Assembly) {
        asm.push_name_compressed(&self.nsdname);
    }
}
