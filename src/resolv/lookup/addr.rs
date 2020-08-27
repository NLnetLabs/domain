//! Looking up host names for addresses.

use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use crate::base::iana::Rtype;
use crate::base::message::RecordIter;
use crate::base::name::{Dname, DnameBuilder, ParsedDname};
use crate::base::octets::{Octets128, OctetsRef};
use crate::rdata::Ptr;
use crate::resolv::resolver::Resolver;


//------------ lookup_addr ---------------------------------------------------

/// Resolves the host names of an IP address.
///
/// The function will query DNS using the resolver represented by `resolv`.
/// It will query DNS only and not consider any other database the system
/// may have.
/// 
/// The value returned upon success can be turned into an iterator over
/// host names via its `iter()` method. This is due to lifetime issues.
pub async fn lookup_addr<R: Resolver>(
    resolv: &R, addr: IpAddr
) -> Result<FoundAddrs<R>, io::Error> {
    let name = dname_from_addr(addr);
    resolv.query((name, Rtype::Ptr)).await.map(FoundAddrs)
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
        let name = self.name.as_ref()?;
        let answer = self.answer.as_mut()?;
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
            Dname::from_str(
                &format!(
                    "{}.{}.{}.{}.in-addr.arpa.", octets[3],
                    octets[2], octets[1], octets[0]
                )
            ).unwrap()
        }
        IpAddr::V6(addr) => {
            let mut res = DnameBuilder::<Octets128>::new();
            for &item in addr.octets().iter().rev() {
                res.append_label(&[hexdigit(item >> 4)]).unwrap();
                res.append_label(&[hexdigit(item)]).unwrap();
            }
            res.append_label(b"ip6").unwrap();
            res.append_label(b"arpa").unwrap();
            res.into_dname().unwrap()
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

