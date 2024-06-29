use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::base::iana::Class;
use crate::zonefile::inplace;

use super::error::{RecordError, ZoneErrors};
use super::in_memory::ZoneBuilder;
use super::traits::WritableZone;
use super::types::StoredName;
use super::{parsed, ReadableZone, ZoneStore};

//------------ ZoneKey -------------------------------------------------------

/// TODO
pub type ZoneKey = (StoredName, Class);

//------------ Zone ----------------------------------------------------------

/// A single DNS zone.
#[derive(Clone, Debug)]
pub struct Zone {
    store: Arc<dyn ZoneStore>,
}

impl AsRef<dyn ZoneStore> for Zone {
    fn as_ref(&self) -> &dyn ZoneStore {
        self.store.as_ref()
    }
}

impl Zone {
    /// Creates a new [`Zone`] instance with the given data.
    pub fn new(data: impl ZoneStore + 'static) -> Self {
        Zone {
            store: Arc::new(data),
        }
    }

    /// TODO
    pub fn into_inner(self) -> Arc<dyn ZoneStore> {
        self.store
    }
}

impl Zone {
    /// Gets the CLASS of this zone.
    pub fn class(&self) -> Class {
        self.store.class()
    }

    /// Gets the apex name of this zone.
    pub fn apex_name(&self) -> &StoredName {
        self.store.apex_name()
    }

    /// Gets a read interface to this zone.
    pub fn read(&self) -> Box<dyn ReadableZone> {
        self.store.clone().read()
    }

    /// Gets a write interface to this zone.
    pub fn write(
        &self,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>> + Send + Sync>>
    {
        self.store.clone().write()
    }

    /// Gets a key that uniquely identifies this zone.
    ///
    /// Note: Assumes that there is only ever one instance of a zone with a
    /// given apex name and class in a set of zones.
    pub fn key(&self) -> ZoneKey {
        (self.apex_name().clone(), self.class())
    }
}

//--- TryFrom<inplace::Zonefile>

impl TryFrom<inplace::Zonefile> for Zone {
    type Error = RecordError;

    fn try_from(source: inplace::Zonefile) -> Result<Self, Self::Error> {
        parsed::Zonefile::try_from(source)?
            .try_into()
            .map_err(Self::Error::InvalidRecord)
    }
}

//--- TryFrom<ZoneBuilder>

impl From<ZoneBuilder> for Zone {
    fn from(builder: ZoneBuilder) -> Self {
        builder.build()
    }
}

//--- TryFrom<parsed::Zonefile>

impl TryFrom<parsed::Zonefile> for Zone {
    type Error = ZoneErrors;

    fn try_from(source: parsed::Zonefile) -> Result<Self, Self::Error> {
        Ok(Zone::from(ZoneBuilder::try_from(source)?))
    }
}
