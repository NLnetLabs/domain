//! Zone tree related types.

use std::collections::HashMap;
use std::ops;
use std::sync::Arc;
use std::vec::Vec;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::base::name::Name;
use crate::base::rdata::RecordData;
use crate::base::record::Record;
use crate::base::Serial;
use crate::base::{iana::Rtype, Ttl};
use crate::rdata::ZoneRecordData;

//------------ Type Aliases --------------------------------------------------

/// A [`Bytes`] backed [`Name`].
pub type StoredName = Name<Bytes>;

/// A [`Bytes`] backed [`ZoneRecordData`].
pub type StoredRecordData = ZoneRecordData<Bytes, StoredName>;

/// A [`Bytes`] backed [`Record`].`
pub type StoredRecord = Record<StoredName, StoredRecordData>;

//------------ SharedRr ------------------------------------------------------

/// A cheaply clonable resource record.
///
/// A [`Bytes`] backed resource record which is cheap to [`Clone`] because
/// [`Bytes`] is cheap to clone.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SharedRr {
    ttl: Ttl,
    data: StoredRecordData,
}

impl SharedRr {
    /// Create a new [`SharedRr`] instance.
    pub fn new(ttl: Ttl, data: StoredRecordData) -> Self {
        SharedRr { ttl, data }
    }

    /// Gets the type of this resource record.
    pub fn rtype(&self) -> Rtype {
        self.data.rtype()
    }

    /// Gets the TTL of this resource record.
    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// Gets a reference to the data of this resource record.
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

/// A set of related resource records for use with [`Zone`]s.
///
/// This type should be used to create and edit one or more resource records
/// for use with a [`Zone`]. RRset records should all have the same type and
/// TTL but differing data, as defined by [RFC 9499 section 5.1.3].
///
/// [`Zone`]: crate::zonetree::Zone
/// [RFC 9499 section 5.1.3]:
///     https://datatracker.ietf.org/doc/html/rfc9499#section-5-1.3
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Rrset {
    rtype: Rtype,
    ttl: Ttl,
    data: Vec<StoredRecordData>,
}

impl Rrset {
    /// Creates a new RRset.
    pub fn new(rtype: Rtype, ttl: Ttl) -> Self {
        Rrset {
            rtype,
            ttl,
            data: Vec::new(),
        }
    }

    /// Gets the common type of each record in the RRset.
    pub fn rtype(&self) -> Rtype {
        self.rtype
    }

    /// Gets the common TTL of each record in the RRset.
    pub fn ttl(&self) -> Ttl {
        self.ttl
    }

    /// Gets the data for each record in the RRset.
    pub fn data(&self) -> &[StoredRecordData] {
        &self.data
    }

    /// Returns true if this RRset has no resource records, false otherwise.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Gets the first RRset record, if any.
    pub fn first(&self) -> Option<SharedRr> {
        self.data.first().map(|data| SharedRr {
            ttl: self.ttl,
            data: data.clone(),
        })
    }

    /// Changesthe TTL of every record in the RRset.
    pub fn set_ttl(&mut self, ttl: Ttl) {
        self.ttl = ttl;
    }

    /// Limits the TTL of every record in the RRSet.
    ///
    /// If the TTL currently exceeds the given limit it will be set to the
    /// limit.
    pub fn limit_ttl(&mut self, ttl: Ttl) {
        if self.ttl > ttl {
            self.ttl = ttl
        }
    }

    /// Adds a resource record to the RRset.
    ///
    /// # Panics
    ///
    /// This function will panic if the provided record data is for a
    /// different type than the RRset.
    pub fn push_data(&mut self, data: StoredRecordData) {
        assert_eq!(data.rtype(), self.rtype);
        self.data.push(data);
    }

    /// Adds a resource record to the RRset, limiting the TTL to that of the
    /// new record.
    ///
    /// See [`Self::limit_ttl`] and [`Self::push_data`].
    pub fn push_record(&mut self, record: StoredRecord) {
        self.limit_ttl(record.ttl());
        self.push_data(record.into_data());
    }

    /// Converts this [`Rrset`] to an [`SharedRrset`].
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

/// An RRset behind an [`Arc`] for use with [`Zone`]s.
///
/// See [`Rrset`] for more information.
///
/// [`Zone`]: crate::zonetree::Zone
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SharedRrset(Arc<Rrset>);

impl SharedRrset {
    /// Creates a new RRset.
    pub fn new(rrset: Rrset) -> Self {
        SharedRrset(Arc::new(rrset))
    }

    /// Gets a reference to the inner [`Rrset`].
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

/// The representation of a zone cut within a zone tree.
#[derive(Clone, Debug)]
pub struct ZoneCut {
    /// The owner name where the zone cut occurs.
    pub name: StoredName,

    /// The NS record at the zone cut.
    pub ns: SharedRrset,

    /// The DS record at the zone cut (optional).
    pub ds: Option<SharedRrset>,

    /// Zero or more glue records at the zone cut.
    pub glue: Vec<StoredRecord>,
}

//------------ ZoneDiff ------------------------------------------------------

/// The differences between one serial and another for a Zone.
#[derive(Clone, Debug, Default)]
pub struct ZoneDiff {
    /// The serial number of the Zone which was modified.
    ///
    /// For a completed diff this must be Some.
    pub start_serial: Option<Serial>,

    /// The serial number of the Zone that resulted from the modifications.
    ///
    /// For a completed diff this must be Some.
    pub end_serial: Option<Serial>,

    /// The records added to the Zone.
    pub added: HashMap<(StoredName, Rtype), SharedRrset>,

    /// The records removed from the Zone.
    pub removed: HashMap<(StoredName, Rtype), SharedRrset>,
}

impl ZoneDiff {
    /// Creates a new empty diff.
    pub fn new() -> Self {
        Self::default()
    }
}
