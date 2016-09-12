//! Looking up host names.

use std::net::IpAddr;
use std::slice;
use futures::{BoxFuture, Future};
use ::bits::{DNameBuf, DNameSlice, MessageBuf, ParseResult};
use ::iana::{RRType, Class};
use ::rdata::{A, Aaaa};
use super::super::error::{Error, Result};
use super::super::resolver::Resolver;
use super::search::search;


pub fn lookup_host<N>(resolv: Resolver, name: N)
                      -> BoxFuture<LookupHost, Error>
                   where N: AsRef<DNameSlice> {
    search(resolv, name, |resolv, name| {
        let a = resolv.query(&name, RRType::A, Class::In);
        let both = a.select(resolv.query(name, RRType::Aaaa, Class::In));
        let res = both.then(|res| {
            let (a, b) = match res {
                Ok((a, b)) => (Ok(a), b),
                Err((a, b)) => (Err(a), b)
            };
            b.then(move |b| LookupHost::new(a, b))
        });
        res.boxed()
    }).boxed()
}


pub struct LookupHost {
    canonical: DNameBuf,
    addrs: Vec<IpAddr>
}

impl LookupHost {
    fn new(a: Result<MessageBuf>, b: Result<MessageBuf>) -> Result<Self> {
        let (a, b) = match (a, b) {
            (Ok(a), b) => (a, b),
            (a, Ok(b)) => (b, a),
            (Err(a), Err(b)) => return Err(a.merge(b))
        };
        let name = a.canonical_name().unwrap();
        let mut addrs = Vec::new();
        Self::process_records(&mut addrs, &a, &name).ok();
        if let Ok(b) = b {
            Self::process_records(&mut addrs, &b, &name).ok();
        }
        Ok(LookupHost{canonical: name.into_owned(), addrs: addrs})
    }

    fn process_records(addrs: &mut Vec<IpAddr>, msg: &MessageBuf,
                       name: &DNameSlice) -> ParseResult<()> {
        for record in try!(msg.answer()).iter::<A>() {
            if let Ok(record) = record {
                if record.name() == name {
                    addrs.push(IpAddr::V4(record.rdata().addr()))
                }
            }
        }
        for record in try!(msg.answer()).iter::<Aaaa>() {
            if let Ok(record) = record {
                if record.name() == name {
                    addrs.push(IpAddr::V6(record.rdata().addr()))
                }
            }
        }
        Ok(())
    }

    pub fn canonical_name(&self) -> &DNameSlice {
        &self.canonical
    }

    pub fn iter(&self) -> slice::Iter<IpAddr> {
        self.addrs.iter()
    }
}

