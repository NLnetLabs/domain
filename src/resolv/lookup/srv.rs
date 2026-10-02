//! Looking up SRV records.

use super::host::lookup_host;
use crate::base::iana::{Class, Rtype};
use crate::base::message::Message;
use crate::base::name::{Name, ToName, ToRelativeName};
use crate::base::wire::ParseError;
use crate::rdata::{A, Aaaa, Srv};
use crate::resolv::resolver::Resolver;
use alloc::vec;
use alloc::vec::Vec;
use core::net::{IpAddr, SocketAddr};
use core::{fmt, mem, ops};
use futures_util::stream::{self, Stream, StreamExt};
use octseq::octets::Octets;
use rand::distr::{Distribution, Uniform};
use std::collections::HashMap;
use std::io;

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
/// [`ResolvedSrvItem`]s corresponding to the found SRV records, ordered as per
/// the usage rules defined in [RFC 2782]. If no matching SRV record is found,
/// A/AAAA queries on the bare domain name `name` will be attempted, yielding
/// a single element upon success using the port given by `fallback_port`,
/// typcially the standard port for the service in question.
///
/// Each item in the stream can be turned into an iterator over socket
/// addresses as accepted by, for instance, [`TcpStream::connect`].
///
/// The future resolves to `None` whenever the request service is
/// “decidedly not available” at the requested domain, that is there is a
/// single SRV record with the root label as its target.
///
///[`TcpStream::connect`]: tokio::net::TcpStream::connect
pub async fn lookup_srv(
    resolver: &impl Resolver,
    service: impl ToRelativeName,
    name: impl ToName,
    fallback_port: u16,
) -> Result<Option<FoundSrvs>, SrvError> {
    let full_name = match (&service).chain(&name) {
        Ok(name) => name,
        Err(_) => return Err(SrvError::LongName),
    };
    let answer = resolver.query((full_name, Rtype::SRV)).await?;
    FoundSrvs::new(answer.as_ref().for_slice(), name, fallback_port)
}

//------------ FoundSrvs -----------------------------------------------------

/// This is the return type for [`lookup_srv`].
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
    /// Converts the found SRV records into socket addresses.
    ///
    /// The method takes a reference to a resolver and returns a stream of
    /// socket addresses in the order prescribed by the SRV records. Each
    /// returned item provides the set of addresses for one host.
    ///
    /// Note that if you are using the
    /// [`StubResolver`][crate::resolv::stub::StubResolver], you will have to
    /// pass in a double reference since [`Resolver`] is implemented for a
    /// reference to it and this method requires a reference to that impl
    /// being passed. This quirk will be fixed in future versions.
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

    /// Converts the value into an iterator over the found SRV records.
    ///
    /// If results were found, this returns them in the order prescribed by
    /// the SRV records.
    ///
    /// If not results were found, the iterator will yield a single entry
    /// with the bare host and the default fallback port.
    pub fn into_srvs(self) -> impl Iterator<Item = Srv<Name<OctetsVec>>> {
        let (left, right) = match self.items {
            Ok(ok) => (Some(ok.into_iter()), None),
            Err(err) => (None, Some(core::iter::once(err))),
        };
        left.into_iter()
            .flatten()
            .chain(right.into_iter().flatten())
            .map(|item| item.srv)
    }

    /// Merges all results from `other` into `self`.
    ///
    /// Reorders merged results as if they were from a single query.
    pub fn merge(&mut self, other: &Self) {
        let mut items = match mem::replace(&mut self.items, Ok(Vec::new())) {
            Ok(items) => items,
            Err(one) => vec![one],
        };

        match other.items {
            Ok(ref vec) => items.extend_from_slice(vec),
            Err(ref one) => items.push(one.clone()),
        }

        Self::reorder_items(&mut items);
        self.items = Ok(items);
    }
}

impl FoundSrvs {
    fn new(
        answer: &Message<[u8]>,
        fallback_name: impl ToName,
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
        name: &impl ToName,
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

        // Create a map with all the targets we are looking for.
        let mut targets = items
            .iter()
            .map(|item| (item.target(), Vec::new()))
            .collect::<HashMap<_, _>>();

        // Go over all additional records and add addresses to targets.
        for record in additional {
            let record = match record {
                Ok(record) => record,
                Err(_) => continue,
            };
            if record.class() != Class::IN {
                continue;
            }

            let addr = if let Ok(Some(record)) = record.to_record::<A>() {
                IpAddr::from(record.data().addr())
            } else if let Ok(Some(record)) = record.to_record::<Aaaa>() {
                IpAddr::from(record.data().addr())
            } else {
                continue;
            };

            // XXX This conversion here could be avoided if we use a
            //     hashbrown::HashTable instead of an std::HashMap. However,
            //     this would mean changing the required features for resolv
            //     which I don’t want to do in a non-breaking release.
            //
            //     So, TODO for the next breaking release: Use a HashTable.
            let owner = record.owner().to_name::<OctetsVec>();

            if let Some(target) = targets.get_mut(&owner) {
                target.push(addr)
            }
        }

        // Write back the collected targets.
        //
        // We can’t put things directly into `items` because that is still
        // locked by serving as `targets` keys.
        let mut addrs = vec![None; items.len()];
        for (idx, item) in items.iter().enumerate() {
            if let Some(res) = targets.get(item.target()) {
                if !res.is_empty() {
                    addrs[idx] = Some(res.clone())
                }
            }
        }
        drop(targets);
        for (item, addr) in items.iter_mut().zip(addrs) {
            item.resolved = addr;
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

    /// Reorders items in a priority level based on their weight.
    ///
    /// `items` contains a slice of items with the same priority ordered by
    /// their weight. `weight_sum` is the sum of all the weights of the items
    /// in `items`.
    fn reorder_by_weight(items: &mut [SrvItem], weight_sum: u32) {
        let mut rng = rand::rng();
        let mut weight_sum = weight_sum;
        for i in 0..items.len() {
            #[allow(clippy::unwrap_used)]
            let range = Uniform::new(0, weight_sum + 1).unwrap();
            let mut sum: u32 = 0;
            let pick = range.sample(&mut rng);
            for j in i..items.len() {
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
    srv: Srv<Name<OctetsVec>>,

    /// Fall back?
    #[allow(dead_code)] // XXX Check if we can actually remove it.
    fallback: bool,

    /// A resolved answer if we have one.
    resolved: Option<Vec<IpAddr>>,
}

impl SrvItem {
    fn from_rdata(srv: &Srv<impl ToName>) -> Self {
        SrvItem {
            srv: Srv::new(
                srv.priority(),
                srv.weight(),
                srv.port(),
                srv.target().to_name(),
            ),
            fallback: false,
            resolved: None,
        }
    }

    fn fallback(name: impl ToName, fallback_port: u16) -> Self {
        SrvItem {
            srv: Srv::new(0, 0, fallback_port, name.to_name()),
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

impl AsRef<Srv<Name<OctetsVec>>> for SrvItem {
    fn as_ref(&self) -> &Srv<Name<OctetsVec>> {
        &self.srv
    }
}

impl ops::Deref for SrvItem {
    type Target = Srv<Name<OctetsVec>>;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

//------------ ResolvedSrvItems ----------------------------------------------

/// An SRV record which has itself been resolved into a [`SocketAddr`].
#[derive(Clone, Debug)]
pub struct ResolvedSrvItem {
    srv: Srv<Name<OctetsVec>>,
    resolved: Vec<SocketAddr>,
}

impl ResolvedSrvItem {
    /// Returns the resolved address for this record.
    pub fn resolved(&self) -> &[SocketAddr] {
        &self.resolved
    }
}

impl AsRef<Srv<Name<OctetsVec>>> for ResolvedSrvItem {
    fn as_ref(&self) -> &Srv<Name<OctetsVec>> {
        &self.srv
    }
}

impl ops::Deref for ResolvedSrvItem {
    type Target = Srv<Name<OctetsVec>>;

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

impl fmt::Display for SrvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrvError::LongName => write!(f, "name too long"),
            SrvError::MalformedAnswer => write!(f, "malformed answer"),
            SrvError::Query(e) => write!(f, "error executing query {}", e),
        }
    }
}

impl core::error::Error for SrvError {}

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

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use crate::base::name::Name;
    use crate::base::{
        MessageBuilder, Rtype, StaticCompressor, StreamTarget,
    };
    use crate::rdata::{A, Srv};
    use alloc::vec::Vec;
    use core::str::FromStr;

    #[test]
    fn process_srv_response() {
        let example_com = Name::<Vec<u8>>::from_str("example.com").unwrap();
        // Make an SRV response.
        let mut msg = MessageBuilder::from_target(StaticCompressor::new(
            StreamTarget::new_vec(),
        ))
        .unwrap();
        msg.header_mut().set_qr(true);
        let mut msg = msg.question();
        msg.push((&example_com, Rtype::SRV)).unwrap();
        let mut msg = msg.answer();
        let srv20 = Srv::new(
            20,
            100,
            1000,
            Name::<Vec<u8>>::from_str("20.example.com").unwrap(),
        );
        msg.push((&example_com, 100, &srv20)).unwrap();
        let srv101 = Srv::new(
            10,
            100,
            1000,
            Name::<Vec<u8>>::from_str("100.10.example.com").unwrap(),
        );
        msg.push((&example_com, 100, &srv101)).unwrap();
        let srv15 = Srv::new(
            15,
            100,
            1000,
            Name::<Vec<u8>>::from_str("15.example.com").unwrap(),
        );
        msg.push((&example_com, 100, &srv15)).unwrap();
        let srv102 = Srv::new(
            10,
            200,
            1000,
            Name::<Vec<u8>>::from_str("200.10.example.com").unwrap(),
        );
        msg.push((&example_com, 100, &srv102)).unwrap();
        let mut msg = msg.additional();
        msg.push((
            Name::<Vec<u8>>::from_str("20.example.com").unwrap(),
            100,
            A::from_octets(192, 0, 2, 20),
        ))
        .unwrap();
        msg.push((
            Name::<Vec<u8>>::from_str("200.10.example.com").unwrap(),
            100,
            A::from_octets(192, 0, 2, 210),
        ))
        .unwrap();
        msg.push((
            Name::<Vec<u8>>::from_str("15.example.com").unwrap(),
            100,
            A::from_octets(192, 0, 2, 15),
        ))
        .unwrap();
        msg.push((
            Name::<Vec<u8>>::from_str("100.10.example.com").unwrap(),
            100,
            A::from_octets(192, 0, 2, 110),
        ))
        .unwrap();
        let target = msg.finish().into_target();
        let message = Message::from_slice(target.as_dgram_slice()).unwrap();

        let srvs = FoundSrvs::new(
            message,
            Name::<Vec<u8>>::from_str("target4.example.com").unwrap(),
            6000,
        )
        .unwrap()
        .unwrap()
        .items
        .unwrap();

        assert_eq!(srvs.len(), 4);

        if srvs[0].srv == srv101 {
            assert_eq!(
                srvs[0].resolved,
                Some(vec![IpAddr::from_str("192.0.2.110").unwrap()])
            );

            assert_eq!(srvs[1].srv, srv102);
            assert_eq!(
                srvs[1].resolved,
                Some(vec![IpAddr::from_str("192.0.2.210").unwrap()])
            );
        } else if srvs[0].srv == srv102 {
            assert_eq!(
                srvs[0].resolved,
                Some(vec![IpAddr::from_str("192.0.2.210").unwrap()])
            );

            assert_eq!(srvs[1].srv, srv101);
            assert_eq!(
                srvs[1].resolved,
                Some(vec![IpAddr::from_str("192.0.2.110").unwrap()])
            );
        } else {
            panic!("srv[0] is not srv101 or srv102");
        }

        assert_eq!(srvs[2].srv, srv15);
        assert_eq!(
            srvs[2].resolved,
            Some(vec![IpAddr::from_str("192.0.2.15").unwrap()])
        );

        assert_eq!(srvs[3].srv, srv20);
        assert_eq!(
            srvs[3].resolved,
            Some(vec![IpAddr::from_str("192.0.2.20").unwrap()])
        );
    }
}
