use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::base::iana::Class;
use crate::zonefile::error::{RecordError, ZoneErrors};
use crate::zonefile::{inplace, parsed};

use super::in_memory::ZoneBuilder;
use super::traits::WritableZone;
use super::{ReadableZone, StoredDname, ZoneStore};

//------------ Zone ----------------------------------------------------------

/// A single DNS zone.
#[derive(Debug)]
pub struct Zone<T> {
    store: Arc<dyn ZoneStore<Meta = T>>,
}

impl<T> Zone<T> {
    /// Creates a new [`Zone`] instance with the given data.
    pub fn new(data: impl ZoneStore<Meta = T> + 'static) -> Self {
        Zone {
            store: Arc::new(data),
        }
    }

    /// Gets the CLASS of this zone.
    pub fn class(&self) -> Class {
        self.store.class()
    }

    /// Gets the apex name of this zone.
    pub fn apex_name(&self) -> &StoredDname {
        self.store.apex_name()
    }

    /// Gets a read interface to this zone.
    pub fn read(&self) -> Box<dyn ReadableZone<Meta = T>> {
        self.store.clone().read()
    }

    /// Gets a write interface to this zone.
    pub fn write(
        &self,
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>>>> {
        self.store.clone().write()
    }
}

//--- TryFrom<inplace::Zonefile>

impl<T: Clone + Debug + Sync + Send + 'static> TryFrom<inplace::Zonefile> for Zone<T> {
    type Error = RecordError;

    fn try_from(source: inplace::Zonefile) -> Result<Self, Self::Error> {
        parsed::Zonefile::try_from(source)?
            .try_into()
            .map_err(Self::Error::InvalidRecord)
    }
}

//--- TryFrom<ZoneBuilder>

impl<T: Clone + Debug + Sync + Send + 'static> From<ZoneBuilder<T>> for Zone<T> {
    fn from(builder: ZoneBuilder<T>) -> Self {
        builder.build()
    }
}

//--- TryFrom<parsed::Zonefile>

impl<T: Clone + Debug + Sync + Send + 'static> TryFrom<parsed::Zonefile> for Zone<T> {
    type Error = ZoneErrors;

    fn try_from(source: parsed::Zonefile) -> Result<Self, Self::Error> {
        Ok(Zone::from(ZoneBuilder::try_from(source)?))
    }
}
