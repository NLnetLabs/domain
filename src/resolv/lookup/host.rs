//! Looking up host names.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::slice;
use futures::{BoxFuture, Future};
use ::bits::{DNameBuf, DNameSlice, MessageBuf, ParseResult};
use ::iana::{RRType, Class};
use ::rdata::{A, Aaaa};
use super::super::error::Result;
use super::super::resolver::ResolverTask;
use super::search::search;


//------------ lookup_host ---------------------------------------------------

/// Creates a future that resolves a host name into its IP addresses.
///
/// The future will use the resolver represented by `resolv` to query the
/// DNS for the IPv4 and IPv6 addresses associated with `name`. If `name`
/// is a relative domain name, it is being translated into a series of
/// absolute names according to the resolver’s configuration.
///
/// The value returned upon success can be turned into an iterator over
/// IP addresses or even socket addresses. Since the lookup may determine that
/// the host name is in fact an alias for another name, the value will also
/// return the canonical name.
pub fn lookup_host<N>(resolv: ResolverTask, name: N)
                      -> BoxFuture<LookupHost, io::Error>
                   where N: AsRef<DNameSlice> {
    search(resolv, name, |resolv, name| {
        let a = resolv.query(&name, RRType::A, Class::In);
        let both = a.select(resolv.query(name, RRType::Aaaa, Class::In));
        let res = both.then(|res| {
            let (a, b) = match res {
                Ok((a, b)) => (Ok(a), b),
                Err((a, b)) => (Err(a), b)
            };
            b.then(move |b| LookupHost::new(a, b))
        });
        res.boxed()
    }).boxed()
}


//------------ LookupHost ----------------------------------------------------

/// The value returned by a successful host lookup.
///
/// You can use the `iter()` method to get an iterator over the IP addresses
/// or `port_iter()` to get an iterator over socket addresses with the given
/// port.
///
/// The `canonical_name()` method returns the canonical name of the host for
/// which the addresses were found.
#[derive(Clone, Debug)]
pub struct LookupHost {
    canonical: DNameBuf,
    addrs: Vec<IpAddr>
}

impl LookupHost {
    fn new(a: Result<MessageBuf>, b: Result<MessageBuf>) -> io::Result<Self> {
        let (a, b) = match (a, b) {
            (Ok(a), b) => (a, b),
            (a, Ok(b)) => (b, a),
            (Err(a), Err(b)) => return Err(a.merge(b).into())
        };
        let name = a.canonical_name().unwrap();
        let mut addrs = Vec::new();
        Self::process_records(&mut addrs, &a, &name).ok();
        if let Ok(b) = b {
            Self::process_records(&mut addrs, &b, &name).ok();
        }
        Ok(LookupHost{canonical: name.into_owned(), addrs: addrs})
    }

    fn process_records(addrs: &mut Vec<IpAddr>, msg: &MessageBuf,
                       name: &DNameSlice) -> ParseResult<()> {
        for record in try!(msg.answer()).iter::<A>() {
            if let Ok(record) = record {
                if record.name() == name {
                    addrs.push(IpAddr::V4(record.rdata().addr()))
                }
            }
        }
        for record in try!(msg.answer()).iter::<Aaaa>() {
            if let Ok(record) = record {
                if record.name() == name {
                    addrs.push(IpAddr::V6(record.rdata().addr()))
                }
            }
        }
        Ok(())
    }

    /// Returns a reference to the canonical name for the host.
    pub fn canonical_name(&self) -> &DNameSlice {
        &self.canonical
    }

    /// Returns an iterator over the IP addresses returned by the lookup.
    pub fn iter(&self) -> LookupHostIter {
        LookupHostIter(self.addrs.iter())
    }

    /// Returns an iterator over socket addresses gained from the lookup.
    ///
    /// The socket addresses are gained by combining the IP addresses with
    /// `port`.
    pub fn port_iter(&self, port: u16) -> LookupHostSocketIter {
        LookupHostSocketIter(self.addrs.iter(), port)
    }
}


//------------ LookupHostIter ------------------------------------------------

/// An iterator over the IP addresses returned by a host lookup.
#[derive(Clone, Debug)]
pub struct LookupHostIter<'a>(slice::Iter<'a, IpAddr>);

impl<'a> Iterator for LookupHostIter<'a> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        self.0.next().cloned()
    }
}


//------------ LookupHostSocketIter ------------------------------------------

/// An iterator over socket addresses derived from a host lookup.
#[derive(Clone, Debug)]
pub struct LookupHostSocketIter<'a>(slice::Iter<'a, IpAddr>, u16);

impl<'a> Iterator for LookupHostSocketIter<'a> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<SocketAddr> {
        self.0.next().map(|addr| SocketAddr::new(*addr, self.1))
    }
}

impl<'a> ToSocketAddrs for LookupHostSocketIter<'a> {
    type Iter = Self;

    fn to_socket_addrs(&self) -> io::Result<Self> {
        Ok(self.clone())
    }
}

