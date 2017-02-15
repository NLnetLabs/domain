//! Looking up raw records.

use futures::{Async, Future, Poll};
use ::bits::{DNameSlice, MessageBuf};
use ::iana::{Rtype, Class};
use super::super::{Query, Resolver};
use super::super::error::Error;
use super::search::SearchIter;


//------------ lookup_records ------------------------------------------------

/// Creates a future that looks up DNS records.
///
/// The future will use the given resolver to perform a DNS query for the
/// records of type `rtype` associated with `name` in `class`.
/// This differs from calling `resolv.query()` directly in that it can treat
/// relative names. In this case, the resolver configuration is considered
/// to translate the name into a series of absolute names. If you want to
/// find out the name that resulted in a successful answer, you can look at
/// the query in the resulting message.
pub fn lookup_records<N>(resolver: Resolver, name: N, rtype: Rtype,
                         class: Class) -> LookupRecords
                      where N: AsRef<DNameSlice> {
    let name = name.as_ref();
    let mut search = SearchIter::new(resolver.clone(), name);
    let search_name = search.as_mut().map(|s| s.next().unwrap());
    let query_name = match search_name {
        Some(ref name) => name,
        None => name
    };
    let query = resolver.clone().query((query_name, rtype, class));
    LookupRecords {
        resolver: resolver,
        query: query,
        search: search,
        rtype: rtype,
        class: class
    }
}


//------------ LookupRecords -------------------------------------------------

/// The future returned by [`lookup_records()`].
///
/// [`lookup_records()`]: fn.lookup_records.html
pub struct LookupRecords {
    /// The resolver to run queries on.
    resolver: Resolver,

    /// The current querry.
    query: Query,

    /// An optional search list iterator for searching a name.
    search: Option<SearchIter>,

    /// The resource record type to search for.
    rtype: Rtype,

    /// The class to search for.
    class: Class,
}


//--- Future

impl Future for LookupRecords {
    type Item = MessageBuf;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let err = match self.query.poll() {
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Ok(Async::Ready(item)) => return Ok(Async::Ready(item)),
            Err(err) => err
        };
        let name = match self.search {
            None => return Err(err),
            Some(ref mut search) => {
                match search.next() {
                    None => return Err(err),
                    Some(name) => name,
                }
            }
        };
        self.query = self.resolver.clone()
                         .query((name, self.rtype, self.class));
        self.poll()
    }
}

