//! Looking up host names.

use std::{io, mem};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use domain_core::iana::Rtype;
use domain_core::message::RecordIter;
use domain_core::name::{
    ParsedDname, ToDname, ToRelativeDname
};
use domain_core::octets::OctetsRef;
//use domain_core::parse::ParseError;
use domain_core::rdata::{A, Aaaa};
use tokio::prelude::{Async, Future, Poll};
use unwrap::unwrap;
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
    qname: N
) -> LookupHost<R> {
    LookupHost {
        a: MaybeDone::NotYet(resolver.query((&qname, Rtype::A))),
        aaaa: MaybeDone::NotYet(resolver.query((&qname, Rtype::Aaaa))),
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
    type Item = FoundHosts<R>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        let err = match self.pending {
            Some(ref mut pending) => match pending.poll() {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(res)) => {
                    if !res.is_empty() {
                        return Ok(Async::Ready(res))
                    }
                    None
                }
                Err(err) => Some(err)
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
        Err(err.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "no usable search list item"
            )
        }))
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
    type Item = FoundHosts<R>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if (self.a.poll(), self.aaaa.poll()) != (true, true) {
            return Ok(Async::NotReady)
        }
        match FoundHosts::new(
            self.aaaa.take(), self.a.take()
        ) {
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
#[derive(Debug)]
pub struct FoundHosts<R: Resolver> {
    /// The answer to the AAAA query.
    aaaa: Result<R::Answer, io::Error>,

    /// The answer to the A query.
    a: Result<R::Answer, io::Error>,
}

impl<R: Resolver> FoundHosts<R> {
    pub fn new(
        aaaa: Result<R::Answer, io::Error>,
        a: Result<R::Answer, io::Error>
    ) -> Result<Self, io::Error> {
        if aaaa.is_err() && a.is_err() {
            match aaaa {
                Err(err) => return Err(err),
                _ => unreachable!()
            }
        }
        Ok(FoundHosts { aaaa, a })
    }

    pub fn is_empty(&self) -> bool {
        if let Ok(ref aaaa) = self.aaaa {
            if aaaa.as_ref().header_counts().ancount() > 0 {
                return false
            }
        }
        if let Ok(ref a) = self.a {
            if a.as_ref().header_counts().ancount() > 0 {
                return false
            }
        }
        true
    }

    /// Returns a reference to one of the answers.
    fn answer(&self) -> &R::Answer {
        match self.aaaa.as_ref() {
            Ok(answer) => answer,
            Err(_) => unwrap!(self.a.as_ref())
        }
    }
}

impl<R: Resolver> FoundHosts<R>
where for<'a> &'a R::Octets: OctetsRef {
    pub fn qname(&self) -> ParsedDname<&R::Octets> {
        unwrap!(self.answer().as_ref().first_question()).into_qname()
    }

    /// Returns a reference to the canonical name for the host.
    pub fn canonical_name(&self) -> ParsedDname<&R::Octets> {
        unwrap!(self.answer().as_ref().canonical_name())
    }

    /// Returns an iterator over the IP addresses returned by the lookup.
    pub fn iter(&self) -> FoundHostsIter<&R::Octets> {
        FoundHostsIter {
            name: self.canonical_name(),
            aaaa: {
                self.aaaa.as_ref().ok()
                .and_then(|msg| msg.as_ref().answer().ok())
                .map(|answer| answer.limit_to::<Aaaa>())
            },
            a: {
                self.a.as_ref().ok()
                .and_then(|msg| msg.as_ref().answer().ok())
                .map(|answer| answer.limit_to::<A>())
            }
        }
    }

    /// Returns an iterator over socket addresses gained from the lookup.
    ///
    /// The socket addresses are gained by combining the IP addresses with
    /// `port`. The returned iterator implements `ToSocketAddrs` and thus
    /// can be used where `std::net` wants addresses right away.
    pub fn port_iter(&self, port: u16) -> FoundHostsSocketIter<&R::Octets> {
        FoundHostsSocketIter { iter: self.iter(), port }
    }

}


//------------ FoundHostsIter ------------------------------------------------

/// An iterator over the IP addresses returned by a host lookup.
#[derive(Clone, Debug)]
pub struct FoundHostsIter<Ref: OctetsRef> {
    name: ParsedDname<Ref>,
    aaaa: Option<RecordIter<Ref, Aaaa>>,
    a: Option<RecordIter<Ref, A>>
}

impl<Ref: OctetsRef> Iterator for FoundHostsIter<Ref> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        while let Some(res) = self.aaaa.as_mut().and_then(Iterator::next) {
            if let Ok(record) = res {
                if *record.owner() == self.name {
                    return Some(record.data().addr().into())
                }
            }
        }
        while let Some(res) = self.a.as_mut().and_then(Iterator::next) {
            if let Ok(record) = res {
                if *record.owner() == self.name {
                    return Some(record.data().addr().into())
                }
            }
        }
        None
    }
}


//------------ FoundHostsSocketIter ------------------------------------------

/// An iterator over socket addresses derived from a host lookup.
#[derive(Clone, Debug)]
pub struct FoundHostsSocketIter<Ref: OctetsRef> {
    iter: FoundHostsIter<Ref>,
    port: u16,
}

impl<Ref: OctetsRef> Iterator for FoundHostsSocketIter<Ref> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<SocketAddr> {
        self.iter.next().map(|addr| SocketAddr::new(addr, self.port))
    }
}

impl<Ref: OctetsRef> ToSocketAddrs for FoundHostsSocketIter<Ref> {
    type Iter = Self;

    fn to_socket_addrs(&self) -> io::Result<Self> {
        Ok(self.clone())
    }
}

