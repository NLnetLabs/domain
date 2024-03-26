use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::base::iana::Class;
use crate::zonefile::{inplace, parsed};

use super::in_memory::ZoneBuilder;
use super::traits::WriteableZone;
use super::{ReadableZone, StoredDname, ZoneStore};

// TODO: Delete Zone, rename ZoneStore to Zone (and make ZoneSetNode generic?)
//------------ Zone ----------------------------------------------------------

#[derive(Debug)]
pub struct Zone {
    store: Arc<dyn ZoneStore>,
}

impl Zone {
    pub fn new(data: impl ZoneStore + 'static) -> Self {
        Zone {
            store: Arc::new(data),
        }
    }

    pub fn class(&self) -> Class {
        self.store.class()
    }

    pub fn apex_name(&self) -> &StoredDname {
        self.store.apex_name()
    }

    pub fn read(&self) -> Box<dyn ReadableZone> {
        self.store.clone().read()
    }

    pub fn write(
        &self,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WriteableZone>>>> {
        self.store.clone().write()
    }
}

//--- TryFrom<inplace::Zonefile>

impl TryFrom<inplace::Zonefile> for Zone {
    type Error = parsed::RecordError;

    fn try_from(source: inplace::Zonefile) -> Result<Self, Self::Error> {
        parsed::Zonefile::try_from(source)?
            .try_into()
            .map_err(Self::Error::InvalidRecord)
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

// //------------ ZoneVersions --------------------------------------------------

// #[derive(Debug)]
// pub struct ZoneVersions {
//     current: (Version, Arc<VersionMarker>),
//     all: Vec<(Version, Weak<VersionMarker>)>,
// }

// impl ZoneVersions {
//     #[allow(unused)]
//     pub fn update_current(&mut self, version: Version) -> Arc<VersionMarker> {
//         let marker = Arc::new(VersionMarker);
//         self.current = (version, marker.clone());
//         marker
//     }

//     #[allow(unused)]
//     pub fn push_version(
//         &mut self,
//         version: Version,
//         marker: Arc<VersionMarker>,
//     ) {
//         self.all.push((version, Arc::downgrade(&marker)))
//     }

//     #[allow(unused)]
//     pub fn clean_versions(&mut self) -> Option<Version> {
//         let mut max_version = None;
//         self.all.retain(|item| {
//             if item.1.strong_count() > 0 {
//                 true
//             } else {
//                 match max_version {
//                     Some(old) => {
//                         if item.0 > old {
//                             max_version = Some(item.0)
//                         }
//                     }
//                     None => max_version = Some(item.0),
//                 }
//                 false
//             }
//         });
//         max_version
//     }
// }

// impl Default for ZoneVersions {
//     fn default() -> Self {
//         let marker = Arc::new(VersionMarker);
//         let weak_marker = Arc::downgrade(&marker);
//         ZoneVersions {
//             current: (Version::default(), marker),
//             all: vec![(Version::default(), weak_marker)],
//         }
//     }
// }

// //------------ VersionMarker -------------------------------------------------

// #[derive(Debug)]
// pub struct VersionMarker;
