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

    pub fn remove(&mut self, version: Version) {
        // We can't just remove the value for the specified version because if
        // it should be a new version of the zone and a value exists for a
        // previous version, then we have to mask the old value so that it
        // isn't seen by consumers of the newer version of the zone.
        let len = self.data.len();
        if let Some(last) = self.data.last_mut() {
            if last.1.is_none() {
                // If it was already marked as removed in the last version
                // we don't need to mark it removed again.
                return;
            }
            if last.0 == version {
                if len == 1 {
                    // If this new version is the only version, we can
                    // remove it entirely rather than mark it as deleted.
                    let _ = self.data.pop();
                } else {
                    last.1 = None;
                }
                return;
            }
        }

        // If there's nothing here, we don't need to explicitly mark that
        // there is nothing here.
        if !self.data.is_empty() {
            self.data.push((version, None))
        }
    }
}

impl<T> Default for Versioned<T> {
    fn default() -> Self {
        Self::new()
    }
}

//------------ VersionMarker -------------------------------------------------

#[derive(Debug)]
pub struct VersionMarker;
