//! Looking up host names.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::slice;
use futures::{BoxFuture, Future};
use ::bits::{DNameBuf, DNameSlice, MessageBuf, ParseResult};
use ::iana::{RRType, Class};
use ::rdata::{A, Aaaa};
use super::super::error::Result;
use super::super::resolver::ResolverTask;
use super::search::search;


//------------ lookup_host ---------------------------------------------------

pub fn lookup_host<N>(resolv: ResolverTask, name: N)
                      -> BoxFuture<LookupHost, io::Error>
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


//------------ LookupHost ----------------------------------------------------


pub struct LookupHost {
    canonical: DNameBuf,
    addrs: Vec<IpAddr>
}

impl LookupHost {
    fn new(a: Result<MessageBuf>, b: Result<MessageBuf>) -> io::Result<Self> {
        let (a, b) = match (a, b) {
            (Ok(a), b) => (a, b),
            (a, Ok(b)) => (b, a),
            (Err(a), Err(b)) => return Err(a.merge(b).into())
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

    pub fn iter(&self) -> LookupHostIter {
        LookupHostIter(self.addrs.iter())
    }

    pub fn port_iter(&self, port: u16) -> LookupHostSocketIter {
        LookupHostSocketIter(self.addrs.iter(), port)
    }
}


pub struct LookupHostIter<'a>(slice::Iter<'a, IpAddr>);

impl<'a> Iterator for LookupHostIter<'a> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        self.0.next().map(|item| *item)
    }
}


#[derive(Clone)]
pub struct LookupHostSocketIter<'a>(slice::Iter<'a, IpAddr>, u16);

impl<'a> Iterator for LookupHostSocketIter<'a> {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<SocketAddr> {
        self.0.next().map(|addr| SocketAddr::new(*addr, self.1))
    }
}

impl<'a> ToSocketAddrs for LookupHostSocketIter<'a> {
    type Iter = Self;

    fn to_socket_addrs(&self) -> io::Result<Self> {
        Ok(self.clone())
    }
}

