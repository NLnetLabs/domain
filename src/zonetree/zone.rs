use super::read::ReadableZone;
use super::rrset::StoredDname;
use super::versioned::Version;
use super::write::WriteableZone;
use crate::base::iana::Class;
use parking_lot::RwLock;
use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::vec::Vec;

//------------ ZoneMeta ------------------------------------------------------

pub trait ZoneData: Sync + Send {
    /// Returns the class of the zone.
    fn class(&self) -> Class;

    /// Returns the apex name of the zone.
    fn apex_name(&self) -> &StoredDname;

    fn read(
        self: Arc<Self>,
        current: (Version, Arc<VersionMarker>),
    ) -> Box<dyn ReadableZone>;

    fn write(
        self: Arc<Self>,
        version: Version,
        zone_versions: Arc<RwLock<ZoneVersions>>,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WriteableZone>>>>;
}

//------------ Zone ----------------------------------------------------------

pub struct Zone {
    data: Arc<dyn ZoneData>,
    versions: Arc<RwLock<ZoneVersions>>,
}

impl Zone {
    pub fn new(data: impl ZoneData + 'static) -> Self {
        Zone {
            data: Arc::new(data),
            versions: Default::default(),
        }
    }

    pub fn class(&self) -> Class {
        self.data.class()
    }

    pub fn apex_name(&self) -> &StoredDname {
        self.data.apex_name()
    }

    pub fn read(&self) -> Box<dyn ReadableZone> {
        let current = self.versions.read().current.clone();
        self.data.clone().read(current)
    }

    pub fn write(
        &self,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WriteableZone>>>> {
        let version = self.versions.read().current.0.next();
        let zone_versions = self.versions.clone();
        self.data.clone().write(version, zone_versions)
    }
}

//------------ ZoneVersions --------------------------------------------------

pub struct ZoneVersions {
    current: (Version, Arc<VersionMarker>),
    all: Vec<(Version, Weak<VersionMarker>)>,
}

impl ZoneVersions {
    #[allow(unused)]
    pub fn update_current(&mut self, version: Version) -> Arc<VersionMarker> {
        let marker = Arc::new(VersionMarker);
        self.current = (version, marker.clone());
        marker
    }

    #[allow(unused)]
    pub fn push_version(
        &mut self,
        version: Version,
        marker: Arc<VersionMarker>,
    ) {
        self.all.push((version, Arc::downgrade(&marker)))
    }

    #[allow(unused)]
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

pub struct VersionMarker;
