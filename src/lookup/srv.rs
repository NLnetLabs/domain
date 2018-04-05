//! Looking up SRV records.

use futures::{Async, Future, Poll, Stream};
use std::net::IpAddr;
use ::bits::{DName, DNameBuf, DNameSlice, MessageBuf, ParsedDName, ParseResult, ComposeError};
use ::iana::{Rtype, Class};
use ::rdata::{Srv, A, Aaaa};
use super::host::{lookup_host, LookupHost, FoundHosts, FoundHostsSocketIter};
use super::super::{Query, Resolver};
use super::super::error::{Error, Result};
use super::search::SearchIter;
use rand;
use rand::distributions::{IndependentSample, Range};


//------------ lookup_records ------------------------------------------------

/// Creates a future that looks up SRV records.
///
/// The future will use the resolver given in `resolv` to query the
/// DNS for SRV records associated with domain name `name` and service `txt_service`.
/// If `name` is a relative domain name, it is being translated into a series of
/// absolute names according to the resolver’s configuration.
///
/// The value returned upon success can be turned into a Stream of `SRVItem` items
/// corresponding to the found SRV records, ordered as per the usage rules defined
/// in RFC 2782. If no matching SRV record is found, A/AAAA queries on the bare
/// domain name `name` will be attempted, yielding a single element upon success.
/// Each of those item can be turned into an iterator over socket addresses.
///
/// The future resolves to `None` whenever the request service is “decidedly not
/// available” at the requested domain.
pub fn lookup_srv<N>(resolver: Resolver, txt_service: N, name: N, fallback_port: u16)
                     -> LookupSrv
                  where N: AsRef<DNameSlice> {
    let name : &DNameSlice = name.as_ref();
    let txt_service : &DNameSlice = txt_service.as_ref();
    let full_name = match txt_service.join(&name) {
        Ok(full_name) => full_name,
        Err(_) => return LookupSrv {
            resolver: resolver.clone(),
            host: name.to_cow().into_owned(),
            fallback_port: fallback_port,
            txt_service: txt_service.to_cow().into_owned(),
            query: None,
            search: None}
    };
    let mut search = SearchIter::new(resolver.clone(), &full_name);
    let search_name = search.as_mut().map(|s| s.next().unwrap());
    let query_name = match search_name {
        Some(ref name) => name,
        None => &full_name
    };
    let query = resolver.clone().query((query_name, Rtype::Srv, Class::In));
    LookupSrv {
        resolver: resolver.clone(),
        host: name.to_cow().into_owned(),
        fallback_port: fallback_port,
        txt_service: txt_service.to_cow().into_owned(),
        query: Some(query),
        search: search
    }
}


//------------ LookupSrvs -------------------------------------------------

/// The future returned by [`lookup_srv()`].
///
/// [`lookup_srv()`]: fn.lookup_srv.html
pub struct LookupSrv {
    /// The resolver to run queries on.
    resolver: Resolver,

    /// Bare host to be queried, used for fallback if no SRV records are found
    host: DNameBuf,

    /// Service name
    txt_service: DNameBuf,

    /// Fallback port, used if no SRV records are found
    fallback_port: u16,

    /// The current SRV query
    query: Option<Query>,

    /// An optional search list iterator for searching a name.
    search: Option<SearchIter>,
}

//--- Future

impl LookupSrv {
    fn poll_helper(&mut self) -> Poll<Option<FoundSrvs>, Error> {
        let err = if let Some(ref mut query) = self.query {
            match query.poll() {
                Ok(Async::NotReady) =>
                    return Ok(Async::NotReady),
                Ok(Async::Ready(item)) =>
                    return Ok(Async::Ready(FoundSrvs::new(item, &self.txt_service)?)),
                Err(err) => err
            }
        }
        else {
            Error::Question(ComposeError::LongName)
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
        self.query = Some(self.resolver.clone()
                              .query((name, Rtype::Srv, Class::In)));
        self.poll_helper()
    }
}

impl Future for LookupSrv {
    type Item = Option<FoundSrvs>;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        if let Ok(item) = self.poll_helper() {
            Ok(item)
        }
        else {
            Ok(Async::Ready(Some(FoundSrvs::new_dummy(&self.host, self.fallback_port))))
        }
    }
}

//------------ LookupSrvStream -----------------------------------------------------

/// Stream over SrvItem elements.
///
/// SrvItem elements are resolved as needed, skipping them in case of failure.
/// It is therefore guaranteed to yield only SrvItem structs that have
/// a SrvItemState::Resolved state.
pub struct LookupSrvStream {
    /// The resolver to use for A/AAAA requests.
    resolver: Resolver,

    /// A vector of (potentially unresolved) SrvItem elements.
    results: Vec<SrvItem>,

    /// Index in `results` of the next `SrvItem` to be yielded.
    current_idx: usize,

    /// A/AAAA lookup for the `SrvItem` at `current_idx` if it is unresolved.
    lookup: Option<LookupHost>
}

//--- Stream

impl Stream for LookupSrvStream {
    type Item = SrvItem;
    type Error = Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        let res = if let Some(ref mut query) = self.lookup {
            match query.poll() {
                Ok(Async::NotReady) =>
                    return Ok(Async::NotReady),
                Ok(Async::Ready(found)) => {
                    let ref item = self.results[self.current_idx];
                    self.current_idx += 1;
                    Ok(Async::Ready(Some(SrvItem{state: SrvItemState::Resolved(found),
                                                 port: item.port,
                                                 txt_service: item.txt_service.clone(),
                                                 priority: item.priority,
                                                 weight: item.weight})))
                },
                Err(_) =>
                    Ok(Async::NotReady)
            }
        }
        else {
            if let Some(item) = self.results.get(self.current_idx).cloned() {
                if let SrvItemState::Unresolved(host) = item.state {
                    self.lookup = Some(lookup_host(self.resolver.clone(), &host));
                    return self.poll()
                }
                else {
                    Ok(Async::Ready(Some(item)))
                }
            }
            else {
                Ok(Async::Ready(None))
            }
        };
        self.lookup = None;
        res
    }
}


//------------ FoundSrvs ----------------------------------------------------

/// The value returned by a successful SRV lookup.
///
/// You can use `to_stream()` to get a stream of `SrvItem` elements,
/// ordered as per RFC 2782's usage rules, resolving target A/AAAA records
/// on demand.
///
/// You can use `merge()` to merge the results from another query, so that
/// you can iter on elements ordered as if they were from a single query.
#[derive(Clone, Debug)]
pub struct FoundSrvs {
    /// All the SRV RRs we’ve got, optionally with IP addresses.
    results: Vec<SrvItem>
}

#[derive(Clone, Debug)]
pub enum SrvItemState {
    Unresolved(DNameBuf),
    Resolved(FoundHosts)
}

#[derive(Clone, Debug)]
pub struct SrvItem {
    priority: u16,
    weight: u16,
    port: u16,
    txt_service: Option<DNameBuf>,
    state: SrvItemState
}

impl SrvItem {
    /// Returns an iterator over socket addresses matching a resolved SRV record.
    ///
    /// SrvItem does not implement the ToSocketAddrs Trait as the result
    /// of `to_socket_addrs()` does not have a static lifetime.
    ///
    /// # Panics
    ///
    /// Panics if the SRV Item is not resolved.
    pub fn to_socket_addrs(&self) -> FoundHostsSocketIter {
        if let SrvItemState::Resolved(ref hosts) = self.state {
            hosts.port_iter(self.port)
        }
        else {
            panic!("Unresolved SRVItem!")
        }
    }

    /// Returns a reference to the service + proto part of the domain name.
    ///
    /// Useful when mixing results from different SRV queries.
    pub fn txt_service(&self) -> Option<&DNameSlice> {
        match self.txt_service {
            Some(ref name) => Some(name),
            None => None
        }
    }

    /// Returns a reference to the name of the target.
    pub fn target(&self) -> &DNameSlice {
        match self.state {
            SrvItemState::Unresolved(ref target) => target,
            SrvItemState::Resolved(ref found_hosts) => found_hosts.canonical_name()
        }
    }
}

impl FoundSrvs {
    /// Creates a new value from the results of the SRV queries.
    ///
    /// The results get ordered as per RFC 2782 and any relevant A/AAAA
    /// record provided in the additional data section is used to pre-resolve
    /// SRV targets, while any remaining one is left unresolved.
    fn new<N>(result: MessageBuf, txt_service: N)
              -> Result<Option<Self>>
              where N : AsRef<DNameSlice> {
        let name = result.canonical_name().unwrap();
        let mut rrs = Vec::new();
        Self::process_records(&mut rrs, &result, &name)?;

        if rrs.len() == 0 {
            // Return an error, falling back to resolving the base host
            return Err(Error::NoName);
        };
        if rrs.len() == 1 && rrs[0].target().eq(&DNameBuf::root()) {
            // Abort if there is exactly one record and its target is "."
            return Ok(None);
        }

        // Build results including potentially resolved IP addresses
        let mut items = Vec::with_capacity(rrs.len());
        Self::items_from_rrs(&rrs, &result, &mut items, txt_service)?;

        // Reorder records following the usage rules defined in RFC 2782
        Self::reorder_items(&mut items);

        Ok(Some(FoundSrvs{results: items}))
    }

    fn new_dummy<N : AsRef<DNameSlice>> (name : N, port : u16) -> Self {
        let name : &DNameSlice = name.as_ref();
        let items = vec![SrvItem{state: SrvItemState::Unresolved(name.to_cow().into_owned()),
                                 port: port,
                                 txt_service: None,
                                 priority: 0,
                                 weight: 0}];
        FoundSrvs{results: items}
    }

    /// Moves all results from `other` into `Self`, leaving `other` empty.
    ///
    /// Reorders merged results as if they were from a single query.
    pub fn merge(&mut self, other : &mut FoundSrvs) {
        self.results.append(&mut other.results);
        Self::reorder_items(&mut self.results);
    }

    /// Processes the records of a response message.
    ///
    /// Adds all SRV records contained in `msg`’s answer to `addrs`,
    /// assuming they domain name in the record matches `name`.
    fn process_records<'a>(rrs: &mut Vec<Srv<ParsedDName<'a>>>, msg: &'a MessageBuf,
                       name: &ParsedDName) -> ParseResult<()> {
        for record in try!(msg.answer()).limit_to::<Srv<ParsedDName>>() {
            if let Ok(record) = record {
                if record.name() == name {
                    rrs.push(record.data().clone())
                }
            }
        }
        Ok(())
    }

    /// Reorders items as per RFC 2782 usage rules.
    fn reorder_items(items: &mut [SrvItem]) {
        // First, reorder by priority and weight, effectively
        // grouping by priority, with weight 0 records at the beginning of
        // each group.
        items.sort_by_key(|k| (k.priority, k.weight));

        // Find each group and reorder them using reorder_by_weight
        let mut current_prio = 0;
        let mut weight_sum = 0;
        let mut first_index = 0;
        for i in 0 .. items.len() {
            if current_prio != items[i].priority {
                current_prio = items[i].priority;
                Self::reorder_by_weight(&mut items[first_index..i], weight_sum);
                weight_sum = 0;
                first_index = i;
            }
            weight_sum += items[i].weight as u32;
        }
        Self::reorder_by_weight(&mut items[first_index..], weight_sum);
    }

    /// Reorders items in a priority level based on their weight
    fn reorder_by_weight(items: &mut [SrvItem], weight_sum : u32) {
        let mut rng = rand::thread_rng();
        let mut weight_sum = weight_sum;
        for i in 0 .. items.len() {
            let range = Range::new(0, weight_sum + 1);
            let mut sum : u32 = 0;
            let pick = range.ind_sample(&mut rng);
            for j in 0 .. items.len() {
                sum += items[j].weight as u32;
                if sum >= pick {
                    weight_sum -= items[j].weight as u32;
                    items.swap(i, j);
                    break;
                }
            }
        }
    }

    /// Builds a `SrvItem` element for each `Srv` record in `rrs`, using
    /// pre-resolving them using the A/AAAA records provided in the additional data
    /// section of `msg`.
    fn items_from_rrs<N>(rrs: &[Srv<ParsedDName>], msg: &MessageBuf, result: &mut Vec<SrvItem>, txt_service: N)
                         -> ParseResult<()>
                         where N : AsRef<DNameSlice> {
        for rr in rrs {
            let mut addrs = Vec::new();
            let name = rr.target();
            for record in try!(msg.additional()).limit_to::<A>() {
                if let Ok(record) = record {
                    if record.name() == name {
                        addrs.push(IpAddr::V4(record.data().addr()))
                    }
                }
            }
            for record in try!(msg.additional()).limit_to::<Aaaa>() {
                if let Ok(record) = record {
                    if record.name() == name {
                        addrs.push(IpAddr::V6(record.data().addr()))
                    }
                }
            }
            let state = if addrs.is_empty() {
                SrvItemState::Unresolved(name.to_cow().into_owned())
            }
            else {
                SrvItemState::Resolved(FoundHosts::new(name.to_cow().into_owned(), addrs))
            };
            result.push(SrvItem{priority: rr.priority(),
                                weight: rr.weight(),
                                state: state,
                                port: rr.port(),
                                txt_service: Some(txt_service.as_ref().to_cow().into_owned())})
        }
        Ok(())
    }

    /// Produce a Stream of `SrvItem` elements, resolving any unresolved one on demand
    pub fn to_stream(&self, resolver: Resolver) -> LookupSrvStream {
        LookupSrvStream{results: self.results.clone(), current_idx: 0, resolver: resolver.clone(), lookup: None}
    }
}
