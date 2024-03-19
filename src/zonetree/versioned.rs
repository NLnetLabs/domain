use super::flavor::{Flavor, Flavored};
use crate::base::serial::Serial;
use serde::{Deserialize, Serialize};
use std::vec::Vec;

//------------ Version -------------------------------------------------------

#[derive(
    Clone,
    Copy,
    Debug,
    Deserialize,
    Eq,
    Hash,
    PartialEq,
    PartialOrd,
    Serialize,
)]
pub struct Version(Serial);

impl Version {
    pub fn next(self) -> Version {
        Version(self.0.add(1))
    }
}

impl Default for Version {
    fn default() -> Self {
        Version(0.into())
    }
}

//------------ Versioned -----------------------------------------------------

#[derive(Clone, Debug)]
pub struct Versioned<T> {
    data: Vec<(Version, Option<T>)>,
}

impl<T> Versioned<T> {
    pub fn new() -> Self {
        Versioned { data: Vec::new() }
    }

    pub fn get(&self, version: Version) -> Option<&T> {
        self.data.iter().rev().find_map(|item| {
            if item.0 <= version {
                item.1.as_ref()
            } else {
                None
            }
        })
    }

    pub fn update(&mut self, version: Version, value: T) {
        if let Some(last) = self.data.last_mut() {
            if last.0 == version {
                last.1 = Some(value);
                return;
            }
        }
        self.data.push((version, Some(value)))
    }

    /// Drops the last version if it is `version`.
    pub fn rollback(&mut self, version: Version) {
        if self.data.last().map(|item| item.0) == Some(version) {
            self.data.pop();
        }
    }

    pub fn clean(&mut self, version: Version) {
        self.data.retain(|item| item.0 >= version)
    }
}

impl<T> Default for Versioned<T> {
    fn default() -> Self {
        Self::new()
    }
}

//------------ FlavorVersioned -----------------------------------------------

#[derive(Clone, Debug)]
pub struct FlavorVersioned<T> {
    /// The unflavored value.
    default: Versioned<T>,

    /// The alternative values for the flavors.
    flavors: Flavored<Versioned<T>>,
}

impl<T> FlavorVersioned<T> {
    pub fn new() -> Self {
        FlavorVersioned {
            default: Versioned::new(),
            flavors: Flavored::new(),
        }
    }

    pub fn get(
        &self,
        flavor: Option<Flavor>,
        version: Version,
    ) -> Option<&T> {
        if let Some(flavor) = flavor {
            if let Some(res) =
                self.flavors.get(flavor).and_then(|flvr| flvr.get(version))
            {
                return Some(res);
            }
        }
        self.default.get(version)
    }

    pub fn iter_version(
        &self,
        version: Version,
    ) -> impl Iterator<Item = (Option<Flavor>, &T)> {
        self.default
            .get(version)
            .map(|item| (None, item))
            .into_iter()
            .chain(self.flavors.iter().filter_map(move |(flavor, item)| {
                item.get(version).map(|item| (Some(flavor), item))
            }))
    }

    pub fn update(
        &mut self,
        flavor: Option<Flavor>,
        version: Version,
        value: T,
    ) {
        match flavor {
            Some(flavor) => {
                self.flavors.get_or_default(flavor).update(version, value)
            }
            None => self.default.update(version, value),
        }
    }

    /// Drops the last version if it is `version`.
    pub fn rollback(&mut self, version: Version) {
        self.default.rollback(version);
        for flavor in self.flavors.values_mut() {
            flavor.rollback(version)
        }
    }

    pub fn clean(&mut self, version: Version) {
        self.default.clean(version);
        for flavor in self.flavors.values_mut() {
            flavor.clean(version)
        }
    }
}

impl<T> Default for FlavorVersioned<T> {
    fn default() -> Self {
        Self::new()
    }
}
