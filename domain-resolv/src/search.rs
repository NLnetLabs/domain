
use std::ops;
use domain_core::bits::name::{Chain, Dname, ToRelativeDname};
use tokio::prelude::{Async, Future, Poll};
use ::resolver::Resolver;

//------------ search --------------------------------------------------------

pub fn search<N, F, R>(
    resolver: &Resolver,
    name: N,
    op: F
) -> Search<N, F, R>
where
    N: ToRelativeDname + Clone,
    F: Fn(&Resolver, Chain<N, Dname>) -> R,
    R: Future
{
    Search::new(resolver, name, op)
}


//------------ SearchList ----------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct SearchList {
    search: Vec<Dname>,
}

impl SearchList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, name: Dname) {
        if !name.is_root() && !self.search.contains(&name) {
            self.search.push(name)
        }
    }

    pub fn as_slice(&self) -> &[Dname] {
        self.as_ref()
    }
}

impl From<Dname> for SearchList {
    fn from(name: Dname) -> Self {
        let mut res = Self::new();
        res.push(name);
        res
    }
}


//--- AsRef and Deref

impl AsRef<[Dname]> for SearchList {
    fn as_ref(&self) -> &[Dname] {
        self.search.as_ref()
    }
}

impl ops::Deref for SearchList {
    type Target = [Dname];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}


//------------ SearchIter ----------------------------------------------------

/// An iterator gained from applying a search list to a domain name.
///
/// The iterator represents how a resolver attempts to derive an absolute
/// domain name from a relative name.
/// 
/// For this purpose, the resolver’s configuration contains a search list,
/// a list of absolute domain names that are appened in turn to the domain
/// name. In addition, if the name contains enough dots (specifically,
/// `ResolvConf::ndots` which defaults to just one) it is first tried as if
/// it were an absolute by appending the root labels.
#[derive(Clone, Debug)]
pub struct SearchIter<N> {
    name: N,
    resolver: Resolver,
    pos: Option<usize>,
}

impl<N> SearchIter<N> {
    pub fn new(resolver: &Resolver, name: N) -> Self {
        SearchIter {
            name,
            resolver: resolver.clone(),
            pos: Some(0),
        }
    }
}

impl<N: ToRelativeDname + Clone> Iterator for SearchIter<N> {
    type Item = Chain<N, Dname>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(pos) = self.pos {
            if pos >= self.resolver.options().search.len() {
                self.pos = None;
                return Some(self.name.clone().chain_root())
            }
            else {
                self.pos = Some(pos + 1);
                let name = self.name.clone()
                    .chain(self.resolver.options().search[pos].clone());
                if let Ok(name) = name {
                    return Some(name)
                }
            }
        }
        None
    }
}


//------------ SearchFuture --------------------------------------------------

#[derive(Debug)]
pub struct Search<N, F, R>
where
    N: ToRelativeDname + Clone,
    F: Fn(&Resolver, Chain<N, Dname>) -> R,
    R: Future
{
    iter: SearchIter<N>,
    op: F,
    pending: Option<R>,
}

impl<N, F, R> Search<N, F, R>
where
    N: ToRelativeDname + Clone,
    F: Fn(&Resolver, Chain<N, Dname>) -> R,
    R: Future
{
    fn new(resolver: &Resolver, name: N, op: F) -> Self {
        let mut iter = SearchIter::new(resolver, name);
        match iter.next() {
            Some(name) => {
                Search {
                    iter,
                    pending: Some(op(resolver, name)),
                    op
                }
            }
            None => {
                Search {
                    iter,
                    op,
                    pending: None
                }
            }
        }
    }
}

impl<N, F, R> Future for Search<N, F, R>
where
    N: ToRelativeDname + Clone,
    F: Fn(&Resolver, Chain<N, Dname>) -> R,
    R: Future
{
    type Item = R::Item;
    type Error = R::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let err = match self.pending {
            Some(ref mut pending) => match pending.poll() {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(res)) => return Ok(Async::Ready(res)),
                Err(err) => err
            }
            None => panic!("polled a resolved future"),
        };

        match self.iter.next() {
            Some(name) => {
                self.pending = Some((self.op)(&self.iter.resolver, name));
                self.poll()
            }
            None => {
                Err(err)
            }
        }
    }
}

