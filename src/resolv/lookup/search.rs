//! Working with the search list.

use futures::{Async, Future, Poll};
use ::bits::{DNameBuf, DNameSlice};
use super::super::resolver::ResolverTask;

/// Creates a future as a sequence of lookups according to the search list.
///
/// The search list contains a list of domain name suffixes to be appended
/// to relative domain names with fewer than a certain number of dots in
/// them. If the name has more dots, the root domain is added and that’s it.
///
/// The closure `f` is used to create lookups trying to find the first
/// name for which that lookup succeeds.
pub fn search<N, R, F>(resolv: ResolverTask, name: N, f: F) -> Search<R, F>
              where N: AsRef<DNameSlice>,
                    R: Future,
                    F: Fn(&ResolverTask, &DNameSlice) -> R + Send + 'static {
    let name = name.as_ref();
    match name.ndots() {
        None => {
            let current = f(&resolv, &name);
            Search { current: current, data: None }
        }
        Some(n) if n > resolv.conf().ndots => {
            let name = name.join(DNameSlice::root());
            let current = f(&resolv, &name);
            Search { current: current, data: None }
        }
        _ => {
            Search::new(resolv, f, name.to_owned())
        }
    }
}

pub struct Search<R, F>
                  where R: Future, F: Fn(&ResolverTask, &DNameSlice) -> R {
    current: R,
    data: Option<SearchData<R,F>>
}

pub struct SearchData<R, F>
                  where R: Future, F: Fn(&ResolverTask, &DNameSlice) -> R {
    resolv: ResolverTask,
    op: F,
    name: DNameBuf,
    pos: usize,
}


impl<R, F> Search<R, F>
     where R: Future, F: Fn(&ResolverTask, &DNameSlice) -> R {
    pub fn new(resolv: ResolverTask, op: F, name: DNameBuf) -> Self {
        let mut abs_name = name.clone();
        abs_name.append(&resolv.conf().search[0]);
        let current = op(&resolv, &abs_name);
        Search {
            current: current,
            data: Some(SearchData {
                resolv: resolv, op: op, name: name,
                pos: 0
            })
        }
    }
}


//--- Future

impl<R, F> Future for Search<R, F>
     where R: Future, F: Fn(&ResolverTask, &DNameSlice) -> R {
    type Item = R::Item;
    type Error = R::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let err = match self.current.poll() {
            Ok(Async::Ready(some)) => return Ok(Async::Ready(some)),
            Ok(Async::NotReady) => return Ok(Async::NotReady),
            Err(err) => err
        };
        if let Some(ref mut data) = self.data {
            data.pos += 1;
            if data.pos == data.resolv.conf().search.len() {
                return Err(err)
            }
            let mut name = data.name.clone();
            name.append(&data.resolv.conf().search[data.pos]);
            self.current = (data.op)(&data.resolv, &name);
        }
        else {
            return Err(err)
        }
        self.poll()
    }
}

