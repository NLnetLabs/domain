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
        // WARNING: This isn't safe to do while updating a zone, e.g. via an
        // AXFR that lacks some records that were in the previous version of
        // the zone, as the effects are immediately visible to users of the
        // zone!
        //
        //   self.data.retain(|item| item.0 >= version)
        //
        // When updating a Zone via ZoneStore::write(), the new version of the
        // zone that is created will be one higher than the highest version of
        // data currently in the zone.
        //
        // So adding an empty value at the new version will cause current
        // clients to continue seeing the old version, but clients of the zone
        // after it is committed will see the new version, i.e. the empty
        // value which will cause get() to return None.
        if self.data.last().map(|item| item.0).is_some() {
            self.data.push((version, None));
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
