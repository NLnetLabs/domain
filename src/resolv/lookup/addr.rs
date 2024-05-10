//! Looking up host names for addresses.

use crate::base::iana::Rtype;
use crate::base::message::RecordIter;
use crate::base::name::{Name, ParsedName};
use crate::rdata::Ptr;
use crate::resolv::resolver::Resolver;
use octseq::octets::Octets;
use std::io;
use std::net::IpAddr;

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
    let name = Name::<Octets128>::reverse_from_addr(addr)
        .expect("address domain name too long");
    resolv.query((name, Rtype::PTR)).await.map(FoundAddrs)
}

//------------ FoundAddrs ----------------------------------------------------

/// The success type of the `lookup_addr()` function.
///
/// The only purpose of this type is to return an iterator over host names
/// via its `iter()` method.
pub struct FoundAddrs<R: Resolver>(R::Answer);

impl<R: Resolver> FoundAddrs<R> {
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn len(&self) -> usize {
        self.0.as_ref().header_counts().ancount() as usize
    }

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
    type Item = ParsedName<<<R as Resolver>::Octets as Octets>::Range<'a>>;
    type IntoIter = FoundAddrsIter<'a, R::Octets>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

//------------ FoundAddrsIter ------------------------------------------------

/// An iterator over host names returned by address lookup.
pub struct FoundAddrsIter<'a, Octs: Octets> {
    name: Option<ParsedName<Octs::Range<'a>>>,
    answer: Option<RecordIter<'a, Octs, Ptr<ParsedName<Octs::Range<'a>>>>>,
}

impl<'a, Octs: Octets> Iterator for FoundAddrsIter<'a, Octs> {
    type Item = ParsedName<Octs::Range<'a>>;

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
