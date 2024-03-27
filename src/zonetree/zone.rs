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
    ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>>>> {
        self.store.clone().write()
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
