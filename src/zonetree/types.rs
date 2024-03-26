use crate::base::name::Dname;
use crate::base::rdata::RecordData;
use crate::base::record::Record;
use crate::base::{iana::Rtype, Ttl};
use crate::rdata::ZoneRecordData;
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::ops;
use std::sync::Arc;
use std::vec::Vec;

//------------ Type Aliases --------------------------------------------------

pub type StoredDname = Dname<Bytes>;
pub type StoredRecordData = ZoneRecordData<Bytes, StoredDname>;
pub type StoredRecord = Record<StoredDname, StoredRecordData>;

//------------ SharedRr ------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SharedRr {
    ttl: Ttl,
    data: StoredRecordData,
}

impl SharedRr {
    pub fn new(ttl: Ttl, data: StoredRecordData) -> Self {
        SharedRr { ttl, data }
    }

    pub fn rtype(&self) -> Rtype {
        self.data.rtype()
    }

    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    pub fn data(&self) -> &StoredRecordData {
        &self.data
    }
}

impl From<StoredRecord> for SharedRr {
    fn from(record: StoredRecord) -> Self {
        SharedRr {
            ttl: record.ttl(),
            data: record.into_data(),
        }
    }
}

//------------ Rrset ---------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rrset {
    rtype: Rtype,
    ttl: Ttl,
    data: Vec<StoredRecordData>,
}

impl Rrset {
    /*
    fn is_delegation(rtype: Rtype) -> bool {
        matches!(rtype, Rtype::Ns | Rtype::Ds)
    }
    */

    pub fn new(rtype: Rtype, ttl: Ttl) -> Self {
        Rrset {
            rtype,
            ttl,
            data: Vec::new(),
        }
    }

    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    pub fn data(&self) -> &[StoredRecordData] {
        &self.data
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn first(&self) -> Option<SharedRr> {
        self.data.first().map(|data| SharedRr {
            ttl: self.ttl,
            data: data.clone(),
        })
    }

    pub fn set_ttl(&mut self, ttl: Ttl) {
        self.ttl = ttl;
    }

    pub fn limit_ttl(&mut self, ttl: Ttl) {
        if self.ttl > ttl {
            self.ttl = ttl
        }
    }

    pub fn push_data(&mut self, data: StoredRecordData) {
        assert_eq!(data.rtype(), self.rtype);
        self.data.push(data);
    }

    pub fn push_record(&mut self, record: StoredRecord) {
        self.limit_ttl(record.ttl());
        self.push_data(record.into_data());
    }

    pub fn into_shared(self) -> SharedRrset {
        SharedRrset::new(self)
    }
}

impl From<StoredRecord> for Rrset {
    fn from(record: StoredRecord) -> Self {
        Rrset {
            rtype: record.rtype(),
            ttl: record.ttl(),
            data: vec![record.into_data()],
        }
    }
}

//------------ SharedRrset ---------------------------------------------------

/// An RRset behind an arc.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedRrset(Arc<Rrset>);

impl SharedRrset {
    pub fn new(rrset: Rrset) -> Self {
        SharedRrset(Arc::new(rrset))
    }

    pub fn as_rrset(&self) -> &Rrset {
        self.0.as_ref()
    }
}

//--- Deref, AsRef, Borrow

impl ops::Deref for SharedRrset {
    type Target = Rrset;

    fn deref(&self) -> &Self::Target {
        self.as_rrset()
    }
}

impl AsRef<Rrset> for SharedRrset {
    fn as_ref(&self) -> &Rrset {
        self.as_rrset()
    }
}

//--- Deserialize and Serialize

impl<'de> Deserialize<'de> for SharedRrset {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self, D::Error> {
        Rrset::deserialize(deserializer).map(SharedRrset::new)
    }
}

impl Serialize for SharedRrset {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        self.as_rrset().serialize(serializer)
    }
}

//------------ ZoneCut -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ZoneCut {
    pub name: StoredDname,
    pub ns: SharedRrset,
    pub ds: Option<SharedRrset>,
    pub glue: Vec<StoredRecord>,
}
