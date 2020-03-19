//! Looking up host names for addresses.

use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use futures::{Async, Future, Poll, try_ready};
use unwrap::unwrap;
use crate::base::iana::Rtype;
use crate::base::message::RecordIter;
use crate::base::name::{Dname, DnameBuilder, ParsedDname};
use crate::base::octets::{Octets128, OctetsRef};
use crate::rdata::Ptr;
use crate::resolv::resolver::Resolver;


//------------ lookup_addr ---------------------------------------------------

/// Creates a future that resolves into the host names for an IP address. 
///
/// The future will query DNS using the resolver represented by `resolv`.
/// It will query DNS only and not consider any other database the system
/// may have.
/// 
/// The value returned upon success can be turned into an iterator over
/// host names via its `iter()` method. This is due to lifetime issues.
pub fn lookup_addr<R: Resolver>(resolv: &R, addr: IpAddr) -> LookupAddr<R> {
    let name = dname_from_addr(addr);
    LookupAddr(resolv.query((name, Rtype::Ptr)))
}


//------------ LookupAddr ----------------------------------------------------

/// The future for [`lookup_addr()`].
///
/// [`lookup_addr()`]: fn.lookup_addr.html
pub struct LookupAddr<R: Resolver>(R::Query);

impl<R: Resolver> Future for LookupAddr<R> {
    type Item = FoundAddrs<R>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        Ok(Async::Ready(FoundAddrs(try_ready!(self.0.poll()))))
    }
}


//------------ FoundAddrs ----------------------------------------------------

/// The success type of the `lookup_addr()` function.
///
/// The only purpose of this type is to return an iterator over host names
/// via its `iter()` method.
pub struct FoundAddrs<R: Resolver>(R::Answer);

impl<R: Resolver> FoundAddrs<R> {
    /// Returns an iterator over the host names.
    pub fn iter(
        &self
    ) -> FoundAddrsIter<&R::Octets>
    where for<'a> &'a R::Octets: OctetsRef {
        FoundAddrsIter {
            name: self.0.as_ref().canonical_name(),
            answer: {
                self.0.as_ref().answer().ok().map(
                    |sec| sec.limit_to::<Ptr<_>>()
                )
            }
        }
    }
}

impl<'a, R: Resolver> IntoIterator for &'a FoundAddrs<R>
where for<'x> &'x R::Octets: OctetsRef {
    type Item = ParsedDname<&'a R::Octets>;
    type IntoIter = FoundAddrsIter<&'a R::Octets>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}


//------------ FoundAddrsIter ------------------------------------------------

/// An iterator over host names returned by address lookup.
pub struct FoundAddrsIter<Ref: OctetsRef> {
    name: Option<ParsedDname<Ref>>,
    answer: Option<RecordIter<Ref, Ptr<ParsedDname<Ref>>>>,
}

impl<Ref: OctetsRef> Iterator for FoundAddrsIter<Ref> {
    type Item = ParsedDname<Ref>;

    #[allow(clippy::while_let_on_iterator)]
    fn next(&mut self) -> Option<Self::Item> {
        let name = if let Some(ref name) = self.name { name }
                   else { return None };
        let answer = if let Some(ref mut answer) = self.answer { answer }
                     else { return None };
        while let Some(Ok(record)) = answer.next() {
            if record.owner() == name {
                return Some(record.into_data().into_ptrdname())
            }
        }
        None
    }
}



//------------ Helper Functions ---------------------------------------------

/// Translates an IP address into a domain name.
fn dname_from_addr(addr: IpAddr) -> Dname<Octets128> {
    match addr {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            unwrap!(Dname::from_str(
                &format!(
                    "{}.{}.{}.{}.in-addr.arpa.", octets[3],
                    octets[2], octets[1], octets[0]
                )
            ))
        }
        IpAddr::V6(addr) => {
            let mut res = DnameBuilder::<Octets128>::new();
            for &item in addr.octets().iter().rev() {
                res.append_label(&[hexdigit(item >> 4)]).unwrap();
                res.append_label(&[hexdigit(item)]).unwrap();
            }
            res.append_label(b"ip6").unwrap();
            res.append_label(b"arpa").unwrap();
            unwrap!(res.into_dname())
        }
    }
}

fn hexdigit(nibble: u8) -> u8 {
    match nibble % 0x0F {
        0 => b'0',
        1 => b'1',
        2 => b'2',
        3 => b'3',
        4 => b'4',
        5 => b'5',
        6 => b'6',
        7 => b'7',
        8 => b'8',
        10 => b'A',
        11 => b'B',
        12 => b'C',
        13 => b'D',
        14 => b'E',
        15 => b'F',
        _ => unreachable!()
    }
}


