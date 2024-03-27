use std::boxed::Box;
use std::fmt::Debug;

use crate::base::iana::Class;
use crate::zonefile::error::{RecordError, ZoneErrors};
use crate::zonefile::{inplace, parsed};

use super::in_memory::ZoneBuilder;
use super::{StorableZoneApex, StoredDname};
use crate::base::{Dname, Rtype};
use bytes::Bytes;
use super::traits::ZoneStore;

//------------ Zone ----------------------------------------------------------

#[derive(Debug)]
pub struct Zone<T: ZoneStore> {
    store: T,
}

impl<T: ZoneStore + 'static> Zone<T> {
    pub fn new(store: T) -> Self {
        Zone { store }
    }

    pub fn class(&self) -> Class {
        self.store.class()
    }

    pub fn apex_name(&self) -> &StoredDname {
        self.store.apex_name()
    }

    pub fn query(&self, qname: Dname<Bytes>, qtype: Rtype) -> T::QueryFut {
        self.store.query(qname, qtype)
    }

    pub fn iter(&self) -> T::IterFut {
        self.store.iter()
    }

    // pub fn write(
    //     &self,
    // ) -> Pin<Box<dyn Future<Output = Box<dyn WritableZone>>>> {
    //     // self.store.clone().write()
    //     todo!()
    // }

    pub fn into_box(
        self,
    ) -> Zone<Box<dyn ZoneStore<QueryFut = T::QueryFut, IterFut = T::IterFut>>>
    {
        Zone::new(Box::new(self.store))
    }
}

//--- TryFrom<inplace::Zonefile>

impl TryFrom<inplace::Zonefile> for Zone<StorableZoneApex> {
    type Error = RecordError;

    fn try_from(source: inplace::Zonefile) -> Result<Self, Self::Error> {
        parsed::Zonefile::try_from(source)?
            .try_into()
            .map_err(Self::Error::InvalidRecord)
    }
}

//--- TryFrom<ZoneBuilder>

impl From<ZoneBuilder> for Zone<StorableZoneApex> {
    fn from(builder: ZoneBuilder) -> Self {
        builder.finalize()
    }
}

//--- TryFrom<parsed::Zonefile>

impl TryFrom<parsed::Zonefile> for Zone<StorableZoneApex> {
    type Error = ZoneErrors;

    fn try_from(source: parsed::Zonefile) -> Result<Self, Self::Error> {
        Ok(Zone::from(ZoneBuilder::try_from(source)?))
    }
}
