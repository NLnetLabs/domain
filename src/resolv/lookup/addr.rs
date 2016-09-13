//! Looking up host names for addresses.

use std::borrow::Cow;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use futures::{BoxFuture, Future};
use ::bits::name::{DNameBuf, DNameSlice, Label};
use ::bits::message::{MessageBuf, RecordIter};
use ::iana::{Class, RRType};
use ::rdata::Ptr;
use super::super::conf::ResolvOptions;
use super::super::error::Error;
use super::super::resolver::Resolver;


pub fn lookup_addr(resolv: Resolver, addr: IpAddr)
                    -> BoxFuture<LookupAddr, Error> {
    let ptr = resolv.query(dname_from_addr(addr, &resolv.options()),
                           RRType::Ptr, Class::In);
    let res = ptr.map(|msg| LookupAddr(msg));
    res.boxed()
}


pub struct LookupAddr(MessageBuf);

impl LookupAddr {
    pub fn iter(&self) -> LookupAddrIter {
        LookupAddrIter {
            name: self.0.canonical_name(),
            answer: self.0.answer().ok().map(|sec| sec.iter::<Ptr>())
        }
    }
}

pub struct LookupAddrIter<'a> {
    name: Option<Cow<'a, DNameSlice>>,
    answer: Option<RecordIter<'a, Ptr<'a>>>
}

impl<'a> Iterator for LookupAddrIter<'a> {
    type Item = DNameBuf;

    fn next(&mut self) -> Option<Self::Item> {
        let name = if let Some(ref name) = self.name { name }
                   else { return None };
        let answer = if let Some(ref mut answer) = self.answer { answer }
                     else { return None };
        while let Some(Ok(record)) = answer.next() {
            if record.name() == name {
                if let Ok(name) = record.rdata().ptrdname().to_owned() {
                    return Some(name)
                }
            }
        }
        None
    }
}


//------------ Helper Functions ---------------------------------------------

fn dname_from_addr(addr: IpAddr, opts: &ResolvOptions) -> DNameBuf {
    match addr {
        IpAddr::V4(addr) => dname_from_v4(addr),
        IpAddr::V6(addr) => dname_from_v6(addr, opts)
    }
}

fn dname_from_v4(addr: Ipv4Addr) -> DNameBuf {
    let octets = addr.octets();
    DNameBuf::from_str(&format!("{}.{}.{}.{}.in-addr.arpa.", octets[3],
                                octets[2], octets[1], octets[0])).unwrap()
}

/// Translate an IPv6 address into a domain name.
///
/// As there are several ways to do this, the functions depends on
/// resolver options, name `use_bstring` and `use_ip6dotin`.
fn dname_from_v6(addr: Ipv6Addr, opts: &ResolvOptions) -> DNameBuf {
    let mut res = DNameBuf::new();
    if opts.use_bstring {
        // XXX Use Ipv6Addr::octets once that is stable.
        let mut segments = addr.segments();
        for i in 0..8 {
            segments[i] = segments[i].to_be()
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
