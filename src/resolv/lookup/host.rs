//! Looking up host names.

use crate::base::iana::Rtype;
use crate::base::message::RecordIter;
use crate::base::name::{ParsedDname, ToDname, ToRelativeDname};
use crate::rdata::{Aaaa, A};
use crate::resolv::resolver::{Resolver, SearchNames};
use octseq::octets::Octets;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

//------------ lookup_host ---------------------------------------------------

/// Creates a future that resolves a host name into its IP addresses.
///
/// The future will use the resolver given in `resolv` to query the
/// DNS for the IPv4 and IPv6 addresses associated with `name`.
///
/// The value returned upon success can be turned into an iterator over
/// IP addresses or even socket addresses. Since the lookup may determine that
/// the host name is in fact an alias for another name, the value will also
/// return the canonical name.
pub async fn lookup_host<R: Resolver>(
    resolver: &R,
    qname: impl ToDname,
) -> Result<FoundHosts<R>, io::Error> {
    let (a, aaaa) = tokio::join!(
        resolver.query((&qname, Rtype::A)),
        resolver.query((&qname, Rtype::Aaaa)),
    );
    FoundHosts::new(aaaa, a)
}

//------------ search_host ---------------------------------------------------

pub async fn search_host<R: Resolver + SearchNames>(
    resolver: &R,
    qname: impl ToRelativeDname,
) -> Result<FoundHosts<R>, io::Error> {
    for suffix in resolver.search_iter() {
        if let Ok(name) = (&qname).chain(suffix) {
            if let Ok(answer) = lookup_host(resolver, name).await {
                if !answer.is_empty() {
                    return Ok(answer);
                }
            }
        }
    }
    lookup_host(resolver, qname.chain_root()).await
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
        a: Result<R::Answer, io::Error>,
    ) -> Result<Self, io::Error> {
        if aaaa.is_err() && a.is_err() {
            match aaaa {
                Err(err) => return Err(err),
                _ => unreachable!(),
            }
        }

        Ok(FoundHosts { aaaa, a })
    }

    pub fn is_empty(&self) -> bool {
        if let Ok(ref aaaa) = self.aaaa {
            if aaaa.as_ref().header_counts().ancount() > 0 {
                return false;
            }
        }
        if let Ok(ref a) = self.a {
            if a.as_ref().header_counts().ancount() > 0 {
                return false;
            }
        }
        true
    }

    /// Returns a reference to one of the answers.
    fn answer(&self) -> &R::Answer {
        match self.aaaa.as_ref() {
            Ok(answer) => answer,
            Err(_) => self.a.as_ref().unwrap(),
        }
    }
}

impl<R: Resolver> FoundHosts<R>
where
    R::Octets: Octets,
{
    pub fn qname(&self) -> ParsedDname<<R::Octets as Octets>::Range<'_>> {
        self.answer()
            .as_ref()
            .first_question()
            .unwrap()
            .into_qname()
    }

    /// Returns a reference to the canonical name for the host.
    ///
    /// # Notes
    ///
    /// This method expects the canonical name to be same in both A/AAAA
    /// responses, if it isn't, it's going to return a canonical name for
    /// one of them.
    pub fn canonical_name(
        &self,
    ) -> ParsedDname<<R::Octets as Octets>::Range<'_>> {
        self.answer().as_ref().canonical_name().unwrap()
    }

    /// Returns an iterator over the IP addresses returned by the lookup.
    pub fn iter(&self) -> FoundHostsIter {
        FoundHostsIter {
            aaaa_name: self
                .aaaa
                .as_ref()
                .ok()
                .and_then(|msg| msg.as_ref().for_slice().canonical_name()),
            a_name: self
                .a
                .as_ref()
                .ok()
                .and_then(|msg| msg.as_ref().for_slice().canonical_name()),
            aaaa: {
                self.aaaa
                    .as_ref()
                    .ok()
                    .and_then(|msg| msg.as_ref().for_slice().answer().ok())
                    .map(|answer| answer.limit_to::<Aaaa>())
            },
            a: {
                self.a
                    .as_ref()
                    .ok()
                    .and_then(|msg| msg.as_ref().for_slice().answer().ok())
                    .map(|answer| answer.limit_to::<A>())
            },
        }
    }

    /// Returns an iterator over socket addresses gained from the lookup.
    ///
    /// The socket addresses are gained by combining the IP addresses with
    /// `port`. The returned iterator implements `ToSocketAddrs` and thus
    /// can be used where `std::net` wants addresses right away.
    pub fn port_iter(
        &self,
        port: u16,
    ) -> FoundHostsSocketIter {
        FoundHostsSocketIter {
            iter: self.iter(),
            port,
        }
    }
}

//------------ FoundHostsIter ------------------------------------------------

/// An iterator over the IP addresses returned by a host lookup.
pub struct FoundHostsIter<'a> {
    aaaa_name: Option<ParsedDname<&'a [u8]>>,
    a_name: Option<ParsedDname<&'a [u8]>>,
    aaaa: Option<RecordIter<'a, [u8], Aaaa>>,
    a: Option<RecordIter<'a, [u8], A>>,
}

impl<'a> Clone for FoundHostsIter<'a> {
    fn clone(&self) -> Self {
        FoundHostsIter {
            aaaa_name: self.aaaa_name.clone(),
            a_name: self.a_name.clone(),
            aaaa: self.aaaa.clone(),
            a: self.a.clone(),
        }
    }
}

impl<'a> Iterator for FoundHostsIter<'a> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        while let Some(res) = self.aaaa.as_mut().and_then(Iterator::next) {
            if let Ok(record) = res {
                if Some(record.owner()) == self.aaaa_name.as_ref() {
                    return Some(record.data().addr().into());
                }
            }
        }
        while let Some(res) = self.a.as_mut().and_then(Iterator::next) {
            if let Ok(record) = res {
                if Some(record.owner()) == self.a_name.as_ref() {
                    return Some(record.data().addr().into());
                }
            }
        }
        None
    }
}

//------------ FoundHostsSocketIter ------------------------------------------

/// An iterator over socket addresses derived from a host lookup.
pub struct FoundHostsSocketIter<'a> {
    iter: FoundHostsIter<'a>,
    port: u16,
}

impl<'a> Clone for FoundHostsSocketIter<'a> {
    fn clone(&self) -> Self {
        FoundHostsSocketIter {
            iter: self.iter.clone(),
            port: self.port,
        }
    }
}

impl<'a> Iterator for FoundHostsSocketIter<'a> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<SocketAddr> {
        self.iter
            .next()
            .map(|addr| SocketAddr::new(addr, self.port))
    }
}

impl<'a> ToSocketAddrs for FoundHostsSocketIter<'a> {
    type Iter = Self;

    fn to_socket_addrs(&self) -> io::Result<Self> {
        Ok(self.clone())
    }
}

