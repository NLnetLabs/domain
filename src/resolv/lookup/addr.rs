//! Looking up host names for addresses.

use std::borrow::Cow;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use futures::{BoxFuture, Future};
use ::bits::name::{DName, DNameBuf, DNameSlice, Label};
use ::bits::message::{MessageBuf, RecordIter};
use ::iana::{Class, RRType};
use ::rdata::Ptr;
use super::super::conf::ResolvOptions;
use super::super::error::Error;
use super::super::resolver::ResolverTask;


//------------ lookup_addr ---------------------------------------------------

/// Creates a future that resolves into the host names for an IP address. 
///
/// The future will query DNS using the resolver represented by `resolv`.
/// It will query DNS only and not consider any other database the system
/// may have.
/// 
/// The value returned upon success can be turned into an iterator over
/// host names via its `iter()` method. This is due to lifetime issues.
pub fn lookup_addr(resolv: ResolverTask, addr: IpAddr)
                    -> BoxFuture<LookupAddr, Error> {
    let ptr = resolv.query(dname_from_addr(addr, &resolv.conf().options),
                           RRType::Ptr, Class::In);
    let res = ptr.map(LookupAddr);
    res.boxed()
}


//------------ LookupAddr ---------------------------------------------------

/// The success type of the `lookup_addr()` function.
///
/// The only purpose of this type is to return an iterator over host names
/// via its `iter()` method.
pub struct LookupAddr(MessageBuf);

impl LookupAddr {
    /// Returns an iterator over the host names.
    pub fn iter(&self) -> LookupAddrIter {
        LookupAddrIter {
            name: self.0.canonical_name(),
            answer: self.0.answer().ok().map(|sec| sec.iter::<Ptr>())
        }
    }
}


//------------ LookupAddrIter -----------------------------------------------

/// An iterator over host names returned by address lookup.
pub struct LookupAddrIter<'a> {
    name: Option<Cow<'a, DNameSlice>>,
    answer: Option<RecordIter<'a, Ptr<'a>>>
}

impl<'a> Iterator for LookupAddrIter<'a> {
    type Item = DName<'a>;

    #[allow(while_let_on_iterator)]
    fn next(&mut self) -> Option<Self::Item> {
        let name = if let Some(ref name) = self.name { name }
                   else { return None };
        let answer = if let Some(ref mut answer) = self.answer { answer }
                     else { return None };
        while let Some(Ok(record)) = answer.next() {
            if record.name() == name {
                return Some(record.rdata().ptrdname())
            }
        }
        None
    }
}


//------------ Helper Functions ---------------------------------------------

/// Translates an IP address into a domain name.
fn dname_from_addr(addr: IpAddr, opts: &ResolvOptions) -> DNameBuf {
    match addr {
        IpAddr::V4(addr) => dname_from_v4(addr),
        IpAddr::V6(addr) => dname_from_v6(addr, opts)
    }
}

/// Translates an IPv4 address into a domain name.
fn dname_from_v4(addr: Ipv4Addr) -> DNameBuf {
    let octets = addr.octets();
    DNameBuf::from_str(&format!("{}.{}.{}.{}.in-addr.arpa.", octets[3],
                                octets[2], octets[1], octets[0])).unwrap()
}

/// Translate an IPv6 address into a domain name.
///
/// As there are several ways to do this, the functions depends on
/// resolver options, namely `use_bstring` and `use_ip6dotin`.
fn dname_from_v6(addr: Ipv6Addr, opts: &ResolvOptions) -> DNameBuf {
    let mut res = DNameBuf::new();
    if opts.use_bstring {
        // XXX Use Ipv6Addr::octets once that is stable.
        let mut segments = addr.segments();
        for item in &mut segments {
            *item = item.to_be()
        }
        let bytes: [u8; 16] = unsafe { mem::transmute(segments) };
        res.push(&Label::octo_binary(&bytes));
    }
    else {
        for item in addr.segments().iter().rev() {
            let text = format!("{:04x}", item);
            let text = text.as_bytes();
            res.push(&Label::normal(&text[3..4]));
            res.push(&Label::normal(&text[2..3]));
            res.push(&Label::normal(&text[1..2]));
            res.push(&Label::normal(&text[0..1]));
        }
    }
    res.push(&Label::normal(b"ip6"));
    if opts.use_ip6dotint {
        res.push(&Label::normal(b"int"));
    }
    else {
        res.push(&Label::normal(b"arpa"));
    }
    res.push(&Label::root());
    res
}

