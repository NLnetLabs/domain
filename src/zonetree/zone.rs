use super::read::ReadableZone;
use super::rrset::StoredDname;
use super::versioned::Version;
use super::write::WriteableZone;
use super::ZoneBuilder;
use crate::base::iana::Class;
use crate::zonefile::{inplace, parsed};
use parking_lot::RwLock;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::vec::Vec;

//------------ ZoneMeta ------------------------------------------------------

pub trait ZoneData: Debug + Sync + Send {
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

#[derive(Debug)]
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

//--- TryFrom<ZoneBuilder>

impl From<ZoneBuilder> for Zone {
    fn from(builder: ZoneBuilder) -> Self {
        builder.finalize()
    }
}

//--- TryFrom<parsed::Zonefile>

impl TryFrom<parsed::Zonefile> for Zone {
    type Error = parsed::ZoneError;

    fn try_from(source: parsed::Zonefile) -> Result<Self, Self::Error> {
        Ok(Zone::from(ZoneBuilder::try_from(source)?))
    }
}

//--- TryFrom<inplace::Zonefile>

impl TryFrom<inplace::Zonefile> for Zone {
    type Error = parsed::RecordError;

    fn try_from(source: inplace::Zonefile) -> Result<Self, Self::Error> {
        parsed::Zonefile::try_from(source)?
            .try_into()
            .map_err(|err| Self::Error::InvalidRecord(err))
    }
}

//------------ ZoneVersions --------------------------------------------------

#[derive(Debug)]
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

#[derive(Debug)]
pub struct VersionMarker;
