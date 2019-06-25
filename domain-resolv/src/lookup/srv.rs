//! Looking up SRV records.

use std::io;
use domain_core::name::{
    Dname, ParsedDname, ParsedDnameError, ToRelativeDname, ToDname
};
use domain_core::iana::Rtype;
use domain_core::rdata::parsed::{A, Aaaa, Srv};
use rand;
use rand::distributions::{Distribution, Uniform};
use tokio::prelude::{Async, Future, Poll, Stream};
use crate::resolver::Resolver;
use super::host::{FoundHosts, FoundHostsSocketIter, LookupHost, lookup_host};


//------------ lookup_srv ----------------------------------------------------

/// Creates a future that looks up SRV records.
///
/// The future will use the resolver given in `resolver` to query the
/// DNS for SRV records associated with domain name `name` and service
/// `service`. 
///
/// The value returned upon success can be turned into a stream of
/// `ResolvedSrvItem`s corresponding to the found SRV records, ordered as per
/// the usage rules defined in [RFC 2782]. If no matching SRV record is found,
/// A/AAAA queries on the bare domain name `name` will be attempted, yielding
/// a single element upon success using the port given by `fallback_port`,
/// typcially the standard port for the service in question.
///
/// Each item in the stream can be turned into an iterator over socket
/// addresses as accepted by, for instance, `TcpStream::connect`.
///
/// The future resolves to `None` whenever the request service is
/// “decidedly not available” at the requested domain, that is there is a
/// single SRV record with the root label as its target.
pub fn lookup_srv<R, S, N>(
    resolver: R,
    service: S,
    name: N,
    fallback_port: u16
) -> LookupSrv<R, S, N>
where
    R: Resolver,
    S: ToRelativeDname + Clone + Send + 'static,
    N: ToDname + Send + 'static
{
    let query = {
        let full_name = match (&service).chain(&name) {
            Ok(name) => name,
            Err(_) => {
                return LookupSrv {
                    data: None,
                    query: Err(Some(SrvError::LongName))
                }
            }
        };
        resolver.query((full_name, Rtype::Srv))
    };
    LookupSrv {
        data: Some(LookupData {
            resolver,
            host: name,
            service,
            fallback_port
        }),
        query: Ok(query)
    }
}


//------------ LookupData ----------------------------------------------------

#[derive(Debug)]
struct LookupData<R, S, N> {
    /// The resolver to run queries on.
    resolver: R,

    /// Bare host to be queried.
    ///
    /// This is kept for fallback if no SRV records are found.
    host: N,

    /// Service name
    service: S,

    /// Fallback port, used if no SRV records are found
    fallback_port: u16,
}


//------------ LookupSrv -----------------------------------------------------

/// The future returned by [`lookup_srv()`].
///
/// [`lookup_srv()`]: fn.lookup_srv.html
pub struct LookupSrv<R: Resolver, S, N> {
    data: Option<LookupData<R, S, N>>,
    query: Result<R::Query, Option<SrvError>>,
}


impl<R, S, N> Future for LookupSrv<R, S, N>
where
    R: Resolver,
    S: ToRelativeDname + Clone + Send + 'static,
    N: ToDname + Send + 'static
{
    type Item = Option<FoundSrvs<R, S>>;
    type Error = SrvError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.query {
            Ok(ref mut query) => match query.poll() {
                Ok(Async::NotReady) => Ok(Async::NotReady),
                Ok(Async::Ready(answer)) => {
                    Ok(Async::Ready(
                        FoundSrvs::new(
                            answer,
                            self.data.take().expect("polled resolved future")
                        )?
                    ))
                }
                Err(_) => {
                    Ok(Async::Ready(Some(
                        FoundSrvs::new_dummy(
                            self.data.take().expect("polled resolved future"))
                    )))
                }
            }
            Err(ref mut err) => {
                Err(err.take().expect("polled resolved future"))
            }
        }
    }
}


//------------ LookupSrvStream -----------------------------------------------

/// Stream over SrvItem elements.
///
/// SrvItem elements are resolved as needed, skipping them in case of failure.
/// It is therefore guaranteed to yield only SrvItem structs that have
/// a `SrvItemState::Resolved` state.
pub struct LookupSrvStream<R: Resolver, S> {
    /// The resolver to use for A/AAAA requests.
    resolver: R,

    /// A vector of (potentially unresolved) SrvItem elements.
    ///
    /// Note that we take items from this via `pop`, so it needs to be ordered
    /// backwards.
    items: Vec<SrvItem<S>>,

    /// A/AAAA lookup for the last `SrvItem`  in `items`.
    lookup: Option<LookupHost<R>>
}

impl<R: Resolver, S> LookupSrvStream<R, S> {
    fn new(found: FoundSrvs<R, S>) -> Self {
        LookupSrvStream {
            resolver: found.resolver,
            items: found.items.into_iter().rev().collect(),
            lookup: None,
        }
    }
}


//--- Stream

impl<R, S> Stream for LookupSrvStream<R, S>
where R: Resolver, S: ToRelativeDname + Clone + Send + 'static {
    type Item = ResolvedSrvItem<S>;
    type Error = SrvError;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // See if we have a query result. We need to break this in to because
        // of the mut ref on the inside of self.lookup.
        let res = if let Some(ref mut query) = self.lookup {
            match query.poll() {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(found)) => {
                    Some(ResolvedSrvItem::from_item_and_hosts(
                        self.items.pop().unwrap(),
                        found
                    ))
                }
                Err(_) => None
            }
        }
        else {
            None
        };

        // We have a query result. Clear lookup and return.
        if let Some(res) = res {
            self.lookup = None;
            return Ok(Async::Ready(Some(res)))
        }

        // Start a new query if necessary. Return if we are done.
        match self.items.last() {
            Some(item) => match item.state {
                SrvItemState::Unresolved(ref host) => {
                    self.lookup = Some(lookup_host(&self.resolver, host));
                }
                _ => { }
            }
            None => return Ok(Async::Ready(None)) // we are done.
        }

        if self.lookup.is_some() {
            self.poll()
        }
        else {
            Ok(Async::Ready(Some(
                ResolvedSrvItem::from_item(self.items.pop().unwrap()).unwrap()
            )))
        }
    }
}


//------------ FoundSrvs -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct FoundSrvs<R, S> {
    resolver: R,
    items: Vec<SrvItem<S>>,
}

impl<R, S> FoundSrvs<R, S> {
    pub fn into_stream(self) -> LookupSrvStream<R, S>
    where R: Resolver {
        LookupSrvStream::new(self)
    }

    /// Moves all results from `other` into `Self`, leaving `other` empty.
    ///
    /// Reorders merged results as if they were from a single query.
    pub fn merge(&mut self, other : &mut Self) {
        self.items.append(&mut other.items);
        Self::reorder_items(&mut self.items);
    }
}

impl<R: Resolver, S: Clone> FoundSrvs<R, S> {
    fn new<N: ToDname>(
        answer: R::Answer,
        data: LookupData<R, S, N>
    ) -> Result<Option<Self>, SrvError> {
        let name = answer.as_ref().canonical_name().unwrap();
        let mut rrs = Vec::new();
        Self::process_records(&mut rrs, &answer, &name)?;

        if rrs.len() == 0 {
            return Ok(Some(Self::new_dummy(data)))
        }
        if rrs.len() == 1 && rrs[0].target().is_root() {
            // Exactly one record with target "." indicates no service.
            return Ok(None)
        }

        // Build results including potentially resolved IP addresses
        let mut items = Vec::with_capacity(rrs.len());
        Self::items_from_rrs(&rrs, &answer, &mut items, &data)?;
        Self::reorder_items(&mut items);

        Ok(Some(FoundSrvs {
            resolver: data.resolver,
            items
        }))
    }

    fn new_dummy<N: ToDname>(data: LookupData<R, S, N>) -> Self {
        FoundSrvs {
            resolver: data.resolver,
            items: vec![
                SrvItem {
                    priority: 0,
                    weight: 0,
                    port: data.fallback_port,
                    service: None,
                    state: SrvItemState::Unresolved(data.host.to_name())
                }
            ]
        }
    }

    fn process_records(
        rrs: &mut Vec<Srv>,
        answer: &R::Answer,
        name: &ParsedDname
    ) -> Result<(), SrvError> {
        for record in answer.as_ref().answer()?.limit_to::<Srv>() {
            if let Ok(record) = record {
                if record.owner() == name {
                    rrs.push(record.data().clone())
                }
            }
        }
        Ok(())
    }

    fn items_from_rrs<N>(
        rrs: &[Srv],
        answer: &R::Answer,
        result: &mut Vec<SrvItem<S>>,
        data: &LookupData<R, S, N>,
    ) -> Result<(), SrvError> {
        for rr in rrs {
            let mut addrs = Vec::new();
            let name = rr.target().to_name();
            for record in answer.as_ref().additional()?.limit_to::<A>() {
                if let Ok(record) = record {
                    if record.owner() == &name {
                        addrs.push(record.data().addr().into())
                    }
                }
            }
            for record in answer.as_ref().additional()?.limit_to::<Aaaa>() {
                if let Ok(record) = record {
                    if record.owner() == &name {
                        addrs.push(record.data().addr().into())
                    }
                }
            }
            let state = if addrs.is_empty() {
                SrvItemState::Unresolved(name)
            }
            else {
                SrvItemState::Resolved(FoundHosts::new(name, addrs))
            };
            result.push(SrvItem  {
                priority: rr.priority(),
                weight: rr.weight(),
                state: state,
                port: rr.port(),
                service: Some(data.service.clone())
            })
        }
        Ok(())
    }
}

impl<R, S> FoundSrvs<R, S> {
    fn reorder_items(items: &mut [SrvItem<S>]) {
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
    fn reorder_by_weight(items: &mut [SrvItem<S>], weight_sum : u32) {
        let mut rng = rand::thread_rng();
        let mut weight_sum = weight_sum;
        for i in 0 .. items.len() {
            let range = Uniform::new(0, weight_sum + 1);
            let mut sum : u32 = 0;
            let pick = range.sample(&mut rng);
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
}


//------------ SrvItem -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SrvItem<S> {
    priority: u16,
    weight: u16,
    port: u16,
    service: Option<S>,
    state: SrvItemState
}

#[derive(Clone, Debug)]
pub enum SrvItemState {
    Unresolved(Dname),
    Resolved(FoundHosts)
}

impl<S> SrvItem<S> {

    /// Returns a reference to the service + proto part of the domain name.
    ///
    /// Useful when mixing results from different SRV queries.
    pub fn txt_service(&self) -> Option<&S> {
        self.service.as_ref()
    }

    /// Returns a reference to the name of the target.
    pub fn target(&self) -> &Dname {
        match self.state {
            SrvItemState::Unresolved(ref target) => target,
            SrvItemState::Resolved(ref found_hosts) => found_hosts.canonical_name()
        }
    }
}


//------------ ResolvedSrvItem -----------------------------------------------

#[derive(Clone, Debug)]
pub struct ResolvedSrvItem<S> {
    priority: u16,
    weight: u16,
    port: u16,
    service: Option<S>,
    hosts: FoundHosts,
}

impl<S> ResolvedSrvItem<S> {
    /// Returns an iterator over socket addresses matching an SRV record.
    ///
    /// SrvItem does not implement the `ToSocketAddrs` trait as the result
    /// of `to_socket_addrs()` does not have a static lifetime.
    pub fn to_socket_addrs(&self) -> FoundHostsSocketIter {
        self.hosts.port_iter(self.port)
    }

    fn from_item(item: SrvItem<S>) -> Option<Self> {
        if let SrvItemState::Resolved(hosts) = item.state {
            Some(ResolvedSrvItem {
            priority: item.priority,
            weight: item.weight,
            port: item.port,
            service: item.service,
            hosts: hosts
            })
        }
        else {
            None
        }
    }

    fn from_item_and_hosts(item: SrvItem<S>, hosts: FoundHosts) -> Self {
        ResolvedSrvItem {
            priority: item.priority,
            weight: item.weight,
            port: item.port,
            service: item.service,
            hosts: hosts
        }
    }
}


//------------ SrvError ------------------------------------------------------

#[derive(Debug)]
pub enum SrvError {
    LongName,
    MalformedAnswer,
    Query(io::Error),
}

impl From<io::Error> for SrvError {
    fn from(err: io::Error) -> SrvError {
        SrvError::Query(err)
    }
}

impl From<ParsedDnameError> for SrvError {
    fn from(_: ParsedDnameError) -> SrvError {
        SrvError::MalformedAnswer
    }
}

