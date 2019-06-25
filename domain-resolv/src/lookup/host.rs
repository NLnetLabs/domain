//! Looking up host names.

use std::{io, mem, slice};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use domain_core::iana::Rtype;
use domain_core::message::Message;
use domain_core::name::{
    Dname, ParsedDname, ParsedDnameError, ToDname, ToRelativeDname
};
use domain_core::rdata::parsed::{A, Aaaa};
use tokio::prelude::{Async, Future, Poll};
use crate::resolver::{Resolver, SearchNames};


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
pub fn lookup_host<R: Resolver, N: ToDname>(
    resolver: &R,
    name: &N
) -> LookupHost<R> {
    LookupHost {
        a: MaybeDone::NotYet(resolver.query((name, Rtype::A))),
        aaaa: MaybeDone::NotYet(resolver.query((name, Rtype::Aaaa))),
    }
}

pub fn search_host<R: Resolver + SearchNames, N: ToRelativeDname> (
    resolver: R,
    name: N
) -> SearchHost<R, N> {
    SearchHost::new(resolver, name)
}


//------------ SearchHost ----------------------------------------------------

pub struct SearchHost<R: Resolver + SearchNames, N: ToRelativeDname> {
    resolver: R,
    name: N,
    iter: <R as SearchNames>::Iter,
    pending: Option<LookupHost<R>>
}

impl<R: Resolver + SearchNames, N: ToRelativeDname> SearchHost<R, N> {
    fn new(resolver: R, name: N) -> Self {
        let mut iter = resolver.search_iter();
        while let Some(suffix) = iter.next() {
            let lookup = match (&name).chain(suffix) {
                Ok(query_name) => lookup_host(&resolver, &query_name),
                Err(_) => continue,
            };
            return SearchHost {
                pending: Some(lookup),
                resolver, name, iter
            }
        }
        SearchHost {
            resolver, name, iter,
            pending: None
        }
    }
}

impl<R, N> Future for SearchHost<R, N>
where R: Resolver + SearchNames, N: ToRelativeDname {
    type Item = FoundHosts;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        let err = match self.pending {
            Some(ref mut pending) => match pending.poll() {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(res)) => return Ok(Async::Ready(res)),
                Err(err) => err
            }
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "no usable search list item"
                ))
            }
        };

        while let Some(suffix) = self.iter.next() {
            let lookup = match (&self.name).chain(suffix) {
                Ok(query_name) => lookup_host(&self.resolver, &query_name),
                Err(_) => continue,
            };
            self.pending = Some(lookup);
            return self.poll()
        }
        self.pending = None;
        Err(err)
    }
}


//------------ LookupHost ----------------------------------------------------

/// The future for [`lookup_host()`].
///
/// [`lookup_host()`]: fn.lookup_host.html
pub struct LookupHost<R: Resolver> {
    /// The A query for the currently processed name.
    a: MaybeDone<R::Query>,

    /// The AAAA query for the currently processed name.
    aaaa: MaybeDone<R::Query>,
}


//--- Future

impl<R: Resolver> Future for LookupHost<R> {
    type Item = FoundHosts;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if (self.a.poll(), self.aaaa.poll()) != (true, true) {
            return Ok(Async::NotReady)
        }
        match FoundHosts::from_answers(self.a.take(), self.aaaa.take()) {
            Ok(res) => Ok(Async::Ready(res)),
            Err(err) => Err(err)
        }
    }
}


//------------ MaybeDone -----------------------------------------------------

/// A future that may or may not yet have been resolved.
///
/// This is mostly the type used by futures’ own `join()`, except that we need
/// to consider errors as part success is still good.
#[derive(Debug)]
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
    fn take(&mut self) -> Result<A::Item, A::Error> {
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
    /// The domain name that was resolved.
    qname: Dname,

    /// The canonical domain name for the host.
    canonical: Dname,

    /// All the IP addresses we’ve got.
    addrs: Vec<IpAddr>
}

impl FoundHosts {
    pub fn new(canonical: Dname, addrs: Vec<IpAddr>) -> Self {
        FoundHosts {
            qname: canonical.clone(),
            canonical,
            addrs,
        }
    }

    /// Creates a new value from the results of the A and AAAA queries.
    ///
    /// Either of the queries can have resulted in an error but not both.
    fn from_answers<M: AsRef<Message>>(
        a: Result<M, io::Error>, b: Result<M, io::Error>
    ) -> Result<Self, io::Error> {
        let (a, b) = match (a, b) {
            (Ok(a), b) => (a, b),
            (a, Ok(b)) => (b, a),
            (Err(a), Err(_)) => return Err(a)
        };
        let qname = a.as_ref().first_question().unwrap().qname().to_name();
        let name = a.as_ref().canonical_name().unwrap();
        let mut addrs = Vec::new();
        Self::process_records(&mut addrs, &a, &name).ok();
        if let Ok(b) = b {
            Self::process_records(&mut addrs, &b, &name).ok();
        }
        Ok(FoundHosts {
            qname,
            canonical: name.to_name(),
            addrs: addrs
        })
    }

    /// Processes the records of a response message.
    ///
    /// Adds all A and AAA records contained in `msg`’s answer to `addrs`,
    /// assuming they domain name in the record matches `name`.
    fn process_records<M: AsRef<Message>>(
        addrs: &mut Vec<IpAddr>,
        msg: &M,
        name: &ParsedDname
    ) -> Result<(), ParsedDnameError> {
        for record in msg.as_ref().answer()?.limit_to::<A>() {
            if let Ok(record) = record {
                if record.owner() == name {
                    addrs.push(IpAddr::V4(record.data().addr()))
                }
            }
        }
        for record in msg.as_ref().answer()?.limit_to::<Aaaa>() {
            if let Ok(record) = record {
                if record.owner() == name {
                    addrs.push(IpAddr::V6(record.data().addr()))
                }
            }
        }
        Ok(())
    }

    /// Returns a reference to the domain name that was queried.
    pub fn qname(&self) -> &Dname {
        &self.qname
    }

    /// Returns a reference to the canonical name for the host.
    pub fn canonical_name(&self) -> &Dname {
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


