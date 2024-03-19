use super::flavor::Flavor;
use super::nodes::ZoneApex;
use super::read::ReadZone;
use super::rrset::StoredDname;
use super::versioned::Version;
use crate::base::iana::Class;
use parking_lot::RwLock;
use std::sync::{Arc, Weak};
use std::vec::Vec;

//------------ Zone ----------------------------------------------------------

pub struct Zone {
    apex: Arc<ZoneApex>,
    versions: Arc<RwLock<ZoneVersions>>,
}

impl Zone {
    pub fn new(apex: Arc<ZoneApex>) -> Self {
        Zone {
            apex,
            versions: Default::default(),
        }
    }

    // Note: This should not be made pub because then anyone with access to
    // this Zone would be able to reach ZoneApex::rrsets() or
    // ZoneApex::children() via which modifications can be made while a call
    // to read() is in progress. Modifications to the tree should only be
    // made via write(). This avoids the need to lock the entire tree when
    // making changes.
    pub(super) fn apex(&self) -> &ZoneApex {
        &self.apex
    }

    pub fn class(&self) -> Class {
        self.apex.class()
    }

    pub fn apex_name(&self) -> &StoredDname {
        self.apex.apex_name()
    }

    pub fn read(&self, flavor: Option<Flavor>) -> ReadZone {
        let (version, marker) = self.versions.read().current.clone();
        ReadZone::new(self.apex.clone(), flavor, version, marker)
    }
}

//------------ ZoneVersions --------------------------------------------------

pub(super) struct ZoneVersions {
    current: (Version, Arc<VersionMarker>),
    all: Vec<(Version, Weak<VersionMarker>)>,
}

impl ZoneVersions {
    pub fn update_current(&mut self, version: Version) -> Arc<VersionMarker> {
        let marker = Arc::new(VersionMarker);
        self.current = (version, marker.clone());
        marker
    }

    pub fn push_version(
        &mut self,
        version: Version,
        marker: Arc<VersionMarker>,
    ) {
        self.all.push((version, Arc::downgrade(&marker)))
    }

    pub fn clean_versions(&mut self) -> Option<Version> {
        let mut max_version = None;
        self.all.retain(|item| {
            if item.1.strong_count() > 0 {
                true
            } else {
                match max_version {
                    Some(old) => {
                        if item.0 > old {
                            max_version = Some(item.0)
                        }
                    }
                    None => max_version = Some(item.0),
                }
                false
            }
        });
        max_version
    }
}

impl Default for ZoneVersions {
    fn default() -> Self {
        let marker = Arc::new(VersionMarker);
        let weak_marker = Arc::downgrade(&marker);
        ZoneVersions {
            current: (Version::default(), marker),
            all: vec![(Version::default(), weak_marker)],
        }
    }
}

//------------ VersionMarker -------------------------------------------------

pub(super) struct VersionMarker;
