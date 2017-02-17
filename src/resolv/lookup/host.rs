//! Looking up host names.

use std::{io, mem, result};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::slice;
use futures::{Async, Future, Poll};
use ::bits::{DName, DNameBuf, DNameSlice, MessageBuf, ParsedDName, ParseResult};
use ::iana::{Rtype, Class};
use ::rdata::{A, Aaaa};
use super::super::{Query, Resolver};
use super::super::error::{Error, Result};
use super::search::SearchIter;


//------------ lookup_host ---------------------------------------------------

/// Creates a future that resolves a host name into its IP addresses.
///
/// The future will use the resolver given in `resolv` to query the
/// DNS for the IPv4 and IPv6 addresses associated with `name`. If `name`
/// is a relative domain name, it is being translated into a series of
/// absolute names according to the resolver’s configuration.
///
/// The value returned upon success can be turned into an iterator over
/// IP addresses or even socket addresses. Since the lookup may determine that
/// the host name is in fact an alias for another name, the value will also
/// return the canonical name.
pub fn lookup_host<N>(resolver: Resolver, name: N) -> LookupHost
                   where N: AsRef<DNameSlice> {
    let name = name.as_ref();
    let mut search = SearchIter::new(resolver.clone(), name);
    let search_name = search.as_mut().map(|s| s.next().unwrap());
    let query_name = match search_name {
        Some(ref name) => name,
        None => name
    };
    let a = resolver.clone().query((query_name, Rtype::A, Class::In));
    let aaaa = resolver.clone().query((query_name, Rtype::Aaaa, Class::In));
    LookupHost {
        resolver: resolver,
        a: MaybeDone::NotYet(a),
        aaaa: MaybeDone::NotYet(aaaa),
        search: search
    }
}



//------------ LookupHost ----------------------------------------------------

/// The future for [`lookup_host()`].
///
/// [`lookup_host()`]: fn.lookup_host.html
pub struct LookupHost {
    /// The resolver to use.
    resolver: Resolver,

    /// The A query for the currently processed name.
    a: MaybeDone<Query>,

    /// The AAAA query for the currently processed name.
    aaaa: MaybeDone<Query>,

    /// An optional search list iterator for searching a name.
    search: Option<SearchIter>,
}


//--- Future

impl Future for LookupHost {
    type Item = FoundHosts;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if (self.a.poll(), self.aaaa.poll()) != (true, true) {
            return Ok(Async::NotReady)
        }
        let err = match FoundHosts::new(self.a.take(), self.aaaa.take()) {
            Ok(some) => return Ok(Async::Ready(some)),
            Err(err) => err,
        };
        let name = match self.search {
            None => return Err(err),
            Some(ref mut search) => {
                match search.next() {
                    None => return Err(err),
                    Some(name) => name
                }
            }
        };
        self.a = MaybeDone::NotYet(
            self.resolver.clone().query((&name, Rtype::A, Class::In)));
        self.aaaa = MaybeDone::NotYet(
            self.resolver.clone().query((&name, Rtype::Aaaa, Class::In)));
        self.poll()
    }
}


//------------ MaybeDone -----------------------------------------------------

/// A future that may or may not yet have been resolved.
///
/// This is mostly the type used by futures’ own `join()`, except that we need
/// to consider errors as part success is still good.
enum MaybeDone<A: Future> {
    /// It’s still ongoing.
    NotYet(A),

    /// It resolved successfully.
    Item(A::Item),

    /// It resolved with an error.
    Error(A::Error),

    /// It is gone.
    Gone
}

impl<A: Future> MaybeDone<A> {
    /// Polls the wrapped future.
    ///
    /// Returns whether the future is resolved.
    ///
    /// # Panics
    ///
    /// If the value is of the `MaybeDone::Gone`, calling this function will
    /// panic.
    fn poll(&mut self) -> bool {
        let res = match *self {
            MaybeDone::NotYet(ref mut a) => a.poll(),
            MaybeDone::Item(_) | MaybeDone::Error(_) => return true,
            MaybeDone::Gone => panic!("polling a completed LookupHost"),
        };
        match res {
            Ok(Async::Ready(item)) => {
                *self = MaybeDone::Item(item);
                true
            }
            Err(err) => {
                *self = MaybeDone::Error(err);
                true
            }
            Ok(Async::NotReady) => {
                false
            }
        }
    }

    /// Trades the value in for the result of the future.
    ///
    /// # Panics
    ///
    /// Panics if there isn’t actually a result.
    fn take(&mut self) -> result::Result<A::Item, A::Error> {
        match mem::replace(self, MaybeDone::Gone) {
            MaybeDone::Item(item) => Ok(item),
            MaybeDone::Error(err) => Err(err),
            _ => panic!(),
        }
    }
}


//------------ FoundHosts ----------------------------------------------------

/// The value returned by a successful host lookup.
///
/// You can use the `iter()` method to get an iterator over the IP addresses
/// or `port_iter()` to get an iterator over socket addresses with the given
/// port.
///
/// The `canonical_name()` method returns the canonical name of the host for
/// which the addresses were found.
#[derive(Clone, Debug)]
pub struct FoundHosts {
    /// The canonical domain name for the host.
    canonical: DNameBuf,

    /// All the IP addresses we’ve got.
    addrs: Vec<IpAddr>
}

impl FoundHosts {
    /// Creates a new value from the results of the A and AAAA queries.
    ///
    /// Either of the queries can have resulted in an error but not both.
    fn new(a: Result<MessageBuf>, b: Result<MessageBuf>) -> Result<Self> {
        let (a, b) = match (a, b) {
            (Ok(a), b) => (a, b),
            (a, Ok(b)) => (b, a),
            (Err(a), Err(b)) => return Err(a.merge(b))
        };
        let name = a.canonical_name().unwrap();
        let mut addrs = Vec::new();
        Self::process_records(&mut addrs, &a, &name).ok();
        if let Ok(b) = b {
            Self::process_records(&mut addrs, &b, &name).ok();
        }
        Ok(FoundHosts{canonical: name.to_cow().into_owned(), addrs: addrs})
    }

    /// Processes the records of a response message.
    ///
    /// Adds all A and AAA records contained in `msg`’s answer to `addrs`,
    /// assuming they domain name in the record matches `name`.
    fn process_records(addrs: &mut Vec<IpAddr>, msg: &MessageBuf,
                       name: &ParsedDName) -> ParseResult<()> {
        for record in try!(msg.answer()).limit_to::<A>() {
            if let Ok(record) = record {
                if record.name() == name {
                    addrs.push(IpAddr::V4(record.data().addr()))
                }
            }
        }
        for record in try!(msg.answer()).limit_to::<Aaaa>() {
            if let Ok(record) = record {
                if record.name() == name {
                    addrs.push(IpAddr::V6(record.data().addr()))
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
    pub fn iter(&self) -> FoundHostsIter {
        FoundHostsIter(self.addrs.iter())
    }

    /// Returns an iterator over socket addresses gained from the lookup.
    ///
    /// The socket addresses are gained by combining the IP addresses with
    /// `port`. The returned iterator implements `ToSocketAddrs` and thus
    /// can be used where `std::net` wants addresses right away.
    pub fn port_iter(&self, port: u16) -> FoundHostsSocketIter {
        FoundHostsSocketIter(self.addrs.iter(), port)
    }
}


//------------ FoundHostsIter ------------------------------------------------

/// An iterator over the IP addresses returned by a host lookup.
#[derive(Clone, Debug)]
pub struct FoundHostsIter<'a>(slice::Iter<'a, IpAddr>);

impl<'a> Iterator for FoundHostsIter<'a> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        self.0.next().cloned()
    }
}


//------------ FoundHostsSocketIter ------------------------------------------

/// An iterator over socket addresses derived from a host lookup.
#[derive(Clone, Debug)]
pub struct FoundHostsSocketIter<'a>(slice::Iter<'a, IpAddr>, u16);

impl<'a> Iterator for FoundHostsSocketIter<'a> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<SocketAddr> {
        self.0.next().map(|addr| SocketAddr::new(*addr, self.1))
    }
}

impl<'a> ToSocketAddrs for FoundHostsSocketIter<'a> {
    type Iter = Self;

    fn to_socket_addrs(&self) -> io::Result<Self> {
        Ok(self.clone())
    }
}

