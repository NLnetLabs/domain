//! Looking up host names for addresses.

use crate::base::iana::Rtype;
use crate::base::message::RecordIter;
use crate::base::name::{Dname, DnameBuilder, ParsedDname};
use crate::rdata::Ptr;
use crate::resolv::resolver::Resolver;
use octseq::octets::Octets;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;

//------------ Octets128 -----------------------------------------------------

type Octets128 = octseq::array::Array<128>;

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
    resolv: &R,
    addr: IpAddr,
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
    pub fn iter(&self) -> FoundAddrsIter<'_, R::Octets>
    where
        R::Octets: Octets,
    {
        FoundAddrsIter {
            name: self.0.as_ref().canonical_name(),
            answer: {
                self.0
                    .as_ref()
                    .answer()
                    .ok()
                    .map(|sec| sec.limit_to::<Ptr<_>>())
            },
        }
    }
}

impl<'a, R: Resolver> IntoIterator for &'a FoundAddrs<R>
where
    R::Octets: Octets,
{
    type Item = ParsedDname<<<R as Resolver>::Octets as Octets>::Range<'a>>;
    type IntoIter = FoundAddrsIter<'a, R::Octets>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//------------ FoundAddrsIter ------------------------------------------------

/// An iterator over host names returned by address lookup.
pub struct FoundAddrsIter<'a, Octs: Octets> {
    name: Option<ParsedDname<Octs::Range<'a>>>,
    answer: Option<RecordIter<'a, Octs, Ptr<ParsedDname<Octs::Range<'a>>>>>,
}

impl<'a, Octs: Octets> Iterator for FoundAddrsIter<'a, Octs> {
    type Item = ParsedDname<Octs::Range<'a>>;

    #[allow(clippy::while_let_on_iterator)]
    fn next(&mut self) -> Option<Self::Item> {
        let name = self.name.as_ref()?;
        let answer = self.answer.as_mut()?;
        while let Some(Ok(record)) = answer.next() {
            if record.owner() == name {
                return Some(record.into_data().into_ptrdname());
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
            Dname::from_str(&format!(
                "{}.{}.{}.{}.in-addr.arpa.",
                octets[3], octets[2], octets[1], octets[0]
            ))
            .unwrap()
        }
        IpAddr::V6(addr) => {
            let mut res = DnameBuilder::<Octets128>::new();
            for &item in addr.octets().iter().rev() {
                res.append_label(&[hexdigit(item)]).unwrap();
                res.append_label(&[hexdigit(item >> 4)]).unwrap();
            }
            res.append_label(b"ip6").unwrap();
            res.append_label(b"arpa").unwrap();
            res.into_dname().unwrap()
        }
    }
}

fn hexdigit(nibble: u8) -> u8 {
    match nibble & 0x0F {
        0 => b'0',
        1 => b'1',
        2 => b'2',
        3 => b'3',
        4 => b'4',
        5 => b'5',
        6 => b'6',
        7 => b'7',
        8 => b'8',
        9 => b'9',
        10 => b'A',
        11 => b'B',
        12 => b'C',
        13 => b'D',
        14 => b'E',
        15 => b'F',
        _ => unreachable!(),
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;
    use core::str::FromStr;

    #[test]
    fn test_dname_from_addr() {
        assert_eq!(
            dname_from_addr([192, 0, 2, 12].into()),
            Dname::<Octets128>::from_str("12.2.0.192.in-addr.arpa").unwrap()
        );
        assert_eq!(
            dname_from_addr(
                [0x2001, 0xdb8, 0x1234, 0x0, 0x5678, 0x1, 0x9abc, 0xdef]
                    .into()
            ),
            Dname::<Octets128>::from_str(
                "f.e.d.0.c.b.a.9.1.0.0.0.8.7.6.5.\
                 0.0.0.0.4.3.2.1.8.b.d.0.1.0.0.2.\
                 ip6.arpa"
            )
            .unwrap()
        );
    }
}
