//! Working with the search list.

use ::bits::{DNameBuf, DNameSlice};
use super::super::Resolver;


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
pub struct SearchIter {
    /// The base name to work with.
    name: DNameBuf,

    /// The resolver to use for looking up the search list.
    resolv: Resolver,

    /// The state of working through the search list.
    state: SearchState,
}

enum SearchState {
    /// The next value is to be the name treated as an absolute name.
    Absolute,

    /// The next value is to be item with the contained value as index in
    /// the resolver’s search list.
    Search(usize), 
    
    /// All options are exhausted.
    Done,
}


impl SearchIter {
    /// Creates a new search iterator.
    ///
    /// The iterator will yield absolute domain names for `name` based on
    /// the configuration of the given resolver.
    pub fn new(resolv: Resolver, name: &DNameSlice) -> Option<Self> {
        let state = match name.ndots() {
            None => {
                // The name is absolute, no searching is necessary.
                return None
            }
            Some(n) if n >= resolv.conf().ndots => {
                // We have the required amount of dots to start with treating
                // the name as an absolute.
                SearchState::Absolute
            }
            _ => {
                // We don’t have enough dots. Start with the search list
                // right away.
                SearchState::Search(0)
            }
        };
        Some(SearchIter {
            name: name.to_owned(),
            resolv: resolv,
            state: state
        })
    }
}
            
impl Iterator for SearchIter {
    type Item = DNameBuf;

    fn next(&mut self) -> Option<Self::Item> {
        // The loop is here to quietly skip over all names where joining
        // fails.
        loop {
            let (res, state) = match self.state {
                SearchState::Absolute => {
                    match self.name.join(&DNameSlice::root()) {
                        Ok(name) => (Some(name), SearchState::Search(0)),
                        Err(_) => continue,
                    }
                }
                SearchState::Search(pos) => {
                    if pos >= self.resolv.conf().search.len() {
                        (None, SearchState::Done)
                    }
                    else {
                        match self.name.join(&self.resolv.conf()
                                                         .search[pos]) {
                            Ok(name) => {
                                (Some(name), SearchState::Search(pos + 1))
                            }
                            Err(_) => continue,
                        }
                    }
                }
                SearchState::Done => return None
            };
            self.state = state;
            return res
        }
    }
}

