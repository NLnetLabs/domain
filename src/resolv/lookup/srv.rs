//! Looking up SRV records.

use super::host::lookup_host;
use crate::base::iana::{Class, Rtype};
use crate::base::message::Message;
use crate::base::name::{Dname, ToDname, ToRelativeDname};
use crate::base::wire::ParseError;
use crate::rdata::{Aaaa, Srv, A};
use crate::resolv::resolver::Resolver;
use futures::stream;
use futures::stream::{Stream, StreamExt};
use octseq::octets::Octets;
use rand::distributions::{Distribution, Uniform};
use std::net::{IpAddr, SocketAddr};
use std::vec::Vec;
use std::{io, mem, ops};

// Look up SRV record. Three outcomes:
//
// *  at least one SRV record with a regular target,
// *  one single SRV record with the root target -- no such service,
// *  no SRV records at all.
//
// In the first case we have a set of (target, port) pairs which we need to
// resolve further if there was no address records for the target in the
// additional section.
//
// In the second case we have nothing.
//
// In the third case we have a single (target, port) pair with the original
// host and the fallback port which we need to resolve further.

//------------ OctetsVec -----------------------------------------------------

#[cfg(feature = "smallvec")]
type OctetsVec = octseq::octets::SmallOctets;

#[cfg(not(feature = "smallvec"))]
type OctetsVec = Vec<u8>;

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
pub async fn lookup_srv(
    resolver: &impl Resolver,
    service: impl ToRelativeDname,
    name: impl ToDname,
    fallback_port: u16,
) -> Result<Option<FoundSrvs>, SrvError> {
    let full_name = match (&service).chain(&name) {
        Ok(name) => name,
        Err(_) => return Err(SrvError::LongName),
    };
    let answer = resolver.query((full_name, Rtype::Srv)).await?;
    FoundSrvs::new(answer.as_ref().for_slice(), name, fallback_port)
}

//------------ FoundSrvs -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct FoundSrvs {
    /// The SRV items we found.
    ///
    /// If this is `Ok(some)`, there were SRV records. If this is `Err(some)`,
    /// there wasn’t any SRV records and the sole item is the bare host and
    /// fallback port.
    items: Result<Vec<SrvItem>, SrvItem>,
}

impl FoundSrvs {
    pub fn into_stream<R: Resolver>(
        self,
        resolver: &R,
    ) -> impl Stream<Item = Result<ResolvedSrvItem, io::Error>> + '_
    where
        R::Octets: Octets,
    {
        // Let’s make a somewhat elaborate single iterator from self.items
        // that we can use as the base for the stream: We turn the result into
        // two options of the two cases and chain those up.
        let iter = match self.items {
            Ok(vec) => {
                Some(vec.into_iter()).into_iter().flatten().chain(None)
            }
            Err(one) => None.into_iter().flatten().chain(Some(one)),
        };
        stream::iter(iter).then(move |item| item.resolve(resolver))
    }

    /// Moves all results from `other` into `Self`, leaving `other` empty.
    ///
    /// Reorders merged results as if they were from a single query.
    pub fn merge(&mut self, other: &mut Self) {
        if self.items.is_err() {
            let one =
                mem::replace(&mut self.items, Ok(Vec::new())).unwrap_err();
            self.items.as_mut().unwrap().push(one);
        }
        match self.items {
            Ok(ref mut items) => {
                match other.items {
                    Ok(ref vec) => items.extend_from_slice(vec),
                    Err(ref one) => items.push(one.clone()),
                }
                Self::reorder_items(items);
            }
            Err(_) => unreachable!(),
        }
    }
}

impl FoundSrvs {
    fn new(
        answer: &Message<[u8]>,
        fallback_name: impl ToDname,
        fallback_port: u16,
    ) -> Result<Option<Self>, SrvError> {
        let name =
            answer.canonical_name().ok_or(SrvError::MalformedAnswer)?;
        let mut items = Self::process_records(answer, &name)?;

        if items.is_empty() {
            return Ok(Some(FoundSrvs {
                items: Err(SrvItem::fallback(fallback_name, fallback_port)),
            }));
        }
        if items.len() == 1 && items[0].target().is_root() {
            // Exactly one record with target "." indicates no service.
            return Ok(None);
        }

        // Build results including potentially resolved IP addresses
        Self::process_additional(&mut items, answer)?;
        Self::reorder_items(&mut items);
        Ok(Some(FoundSrvs { items: Ok(items) }))
    }

    fn process_records(
        answer: &Message<[u8]>,
        name: &impl ToDname,
    ) -> Result<Vec<SrvItem>, SrvError> {
        let mut res = Vec::new();
        // XXX We could also error out if any SRV error is broken?
        for record in answer.answer()?.limit_to_in::<Srv<_>>().flatten() {
            if record.owner() == name {
                res.push(SrvItem::from_rdata(record.data()))
            }
        }
        Ok(res)
    }

    fn process_additional(
        items: &mut [SrvItem],
        answer: &Message<[u8]>,
    ) -> Result<(), SrvError> {
        let additional = answer.additional()?;
        for item in items {
            let mut addrs = Vec::new();
            for record in additional {
                let record = match record {
                    Ok(record) => record,
                    Err(_) => continue,
                };
                if record.class() != Class::In
                    || record.owner() != item.target()
                {
                    continue;
                }
                if let Ok(Some(record)) = record.to_record::<A>() {
                    addrs.push(record.data().addr().into())
                }
                if let Ok(Some(record)) = record.to_record::<Aaaa>() {
                    addrs.push(record.data().addr().into())
                }
            }
            if !addrs.is_empty() {
                item.resolved = Some(addrs)
            }
        }
        Ok(())
    }

    fn reorder_items(items: &mut [SrvItem]) {
        // First, reorder by priority and weight, effectively
        // grouping by priority, with weight 0 records at the beginning of
        // each group.
        items.sort_by_key(|k| (k.priority(), k.weight()));

        // Find each group and reorder them using reorder_by_weight
        let mut current_prio = 0;
        let mut weight_sum = 0;
        let mut first_index = 0;
        for i in 0..items.len() {
            if current_prio != items[i].priority() {
                current_prio = items[i].priority();
                Self::reorder_by_weight(
                    &mut items[first_index..i],
                    weight_sum,
                );
                weight_sum = 0;
                first_index = i;
            }
            weight_sum += u32::from(items[i].weight());
        }
        Self::reorder_by_weight(&mut items[first_index..], weight_sum);
    }

    /// Reorders items in a priority level based on their weight
    fn reorder_by_weight(items: &mut [SrvItem], weight_sum: u32) {
        let mut rng = rand::thread_rng();
        let mut weight_sum = weight_sum;
        for i in 0..items.len() {
            let range = Uniform::new(0, weight_sum + 1);
            let mut sum: u32 = 0;
            let pick = range.sample(&mut rng);
            for j in 0..items.len() {
                sum += u32::from(items[j].weight());
                if sum >= pick {
                    weight_sum -= u32::from(items[j].weight());
                    items.swap(i, j);
                    break;
                }
            }
        }
    }
}

//------------ SrvItem -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct SrvItem {
    /// The SRV record.
    srv: Srv<Dname<OctetsVec>>,

    /// Fall back?
    #[allow(dead_code)] // XXX Check if we can actually remove it.
    fallback: bool,

    /// A resolved answer if we have one.
    resolved: Option<Vec<IpAddr>>,
}

impl SrvItem {
    fn from_rdata(srv: &Srv<impl ToDname>) -> Self {
        SrvItem {
            srv: Srv::new(
                srv.priority(),
                srv.weight(),
                srv.port(),
                srv.target().to_dname().unwrap(),
            ),
            fallback: false,
            resolved: None,
        }
    }

    fn fallback(name: impl ToDname, fallback_port: u16) -> Self {
        SrvItem {
            srv: Srv::new(0, 0, fallback_port, name.to_dname().unwrap()),
            fallback: true,
            resolved: None,
        }
    }

    // Resolves the target.
    pub async fn resolve<R: Resolver>(
        self,
        resolver: &R,
    ) -> Result<ResolvedSrvItem, io::Error>
    where
        R::Octets: Octets,
    {
        let port = self.port();
        if let Some(resolved) = self.resolved {
            return Ok(ResolvedSrvItem {
                srv: self.srv,
                resolved: {
                    resolved
                        .into_iter()
                        .map(|addr| SocketAddr::new(addr, port))
                        .collect()
                },
            });
        }
        let resolved = lookup_host(resolver, self.target()).await?;
        Ok(ResolvedSrvItem {
            srv: self.srv,
            resolved: {
                resolved
                    .iter()
                    .map(|addr| SocketAddr::new(addr, port))
                    .collect()
            },
        })
    }
}

impl AsRef<Srv<Dname<OctetsVec>>> for SrvItem {
    fn as_ref(&self) -> &Srv<Dname<OctetsVec>> {
        &self.srv
    }
}

impl ops::Deref for SrvItem {
    type Target = Srv<Dname<OctetsVec>>;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

//------------ ResolvedSrvItems ----------------------------------------------

#[derive(Clone, Debug)]
pub struct ResolvedSrvItem {
    srv: Srv<Dname<OctetsVec>>,
    resolved: Vec<SocketAddr>,
}

impl ResolvedSrvItem {
    pub fn resolved(&self) -> &[SocketAddr] {
        &self.resolved
    }
}

impl AsRef<Srv<Dname<OctetsVec>>> for ResolvedSrvItem {
    fn as_ref(&self) -> &Srv<Dname<OctetsVec>> {
        &self.srv
    }
}

impl ops::Deref for ResolvedSrvItem {
    type Target = Srv<Dname<OctetsVec>>;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
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

impl From<ParseError> for SrvError {
    fn from(_: ParseError) -> SrvError {
        SrvError::MalformedAnswer
    }
}
