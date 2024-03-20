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
