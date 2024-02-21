//! Types that differ per flavor.

use std::vec::Vec;
use serde::{Deserialize, Serialize};

//------------ Flavor --------------------------------------------------------

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Flavor {
    index: usize,
}

impl Flavor {
    pub fn new(index: usize) -> Self {
        Flavor { index }
    }
}


//------------ Flavored ------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Flavored<T> {
    flavors: Vec<Option<T>>,
}

impl<T> Flavored<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, flavor: Flavor) -> Option<&T> {
        self.flavors.get(flavor.index).and_then(Option::as_ref)
    }

    pub fn get_or_default(&mut self, flavor: Flavor) -> &mut T
    where T: Default {
        while self.flavors.len() <= flavor.index {
            self.flavors.push(None)
        }
        {
            let item = &mut self.flavors[flavor.index];
            if item.is_none() {
                *item = Some(T::default());
            }
        }
        self.flavors[flavor.index].as_mut().unwrap()
    }

    pub fn iter(&self) -> impl Iterator<Item = (Flavor, &'_ T)> + '_ {
        self.flavors.iter().enumerate().filter_map(|(idx, item)| {
            item.as_ref().map(|item| (Flavor::new(idx), item))
        })
    }

    pub fn values_mut(&mut self) -> impl Iterator<Item = &'_ mut T> + '_ {
        self.flavors.iter_mut().filter_map(|item| item.as_mut())
    }
}

impl<T> Default for Flavored<T> {
    fn default() -> Self {
        Flavored {
            flavors: Vec::new()
        }
    }
}

