//! Zone tree related types.

use core::future::{ready, Future};
use core::pin::Pin;
use core::task::{Context, Poll};

use std::boxed::Box;
use std::collections::{hash_map, HashMap};
use std::ops;
use std::sync::Arc;
use std::vec::Vec;

use bytes::Bytes;
use futures_util::stream;
use serde::{Deserialize, Serialize};
use tracing::trace;

use super::traits::{ZoneDiff, ZoneDiffItem};
use crate::base::name::Name;
use crate::base::rdata::RecordData;
use crate::base::record::Record;
use crate::base::{iana::Rtype, Ttl};
use crate::base::{Serial, ToName};
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

//------------ InMemoryZoneDiffBuilder ----------------------------------------

/// An [`InMemoryZoneDiff`] builder.
///
/// Removes are assumed to occur before adds.
#[derive(Debug, Default)]
pub struct InMemoryZoneDiffBuilder {
    /// The records added to the Zone.
    added: HashMap<(StoredName, Rtype), SharedRrset>,

    /// The records removed from the Zone.
    removed: HashMap<(StoredName, Rtype), SharedRrset>,
}

impl InMemoryZoneDiffBuilder {
    /// Creates a new instance of the builder.
    pub fn new() -> Self {
        Default::default()
    }

    /// Record in the diff that a resource record was added.
    pub fn add(
        &mut self,
        owner: StoredName,
        rtype: Rtype,
        rrset: SharedRrset,
    ) {
        self.added.insert((owner, rtype), rrset);
    }

    /// Record in the diff that a resource record was removed.
    pub fn remove(
        &mut self,
        owner: StoredName,
        rtype: Rtype,
        rrset: SharedRrset,
    ) {
        self.removed.insert((owner, rtype), rrset);
    }

    /// Exchange this builder instnace for an immutable [`ZoneDiff`].
    ///
    /// The start serial should be the zone version to which the diffs should
    /// be applied. The end serial denotes the zone version that results from
    /// applying this diff.
    ///
    /// Note: No check is currently done that the start and end serials match
    /// the SOA records in the removed and added records contained within the
    /// diff.
    pub fn build(self) -> Result<InMemoryZoneDiff, ZoneDiffError> {
        InMemoryZoneDiff::new(self.added, self.removed)
    }
}

//------------ InMemoryZoneDiff -----------------------------------------------

/// The differences between one serial and another for a DNS zone.
///
/// Removes are assumed to occur before adds.
#[derive(Clone, Debug)]
pub struct InMemoryZoneDiff {
    /// The serial number of the zone which was modified.
    pub start_serial: Serial,

    /// The serial number of the zone that resulted from the modifications.
    pub end_serial: Serial,

    /// The RRsets added to the zone.
    pub added: Arc<HashMap<(StoredName, Rtype), SharedRrset>>,

    /// The RRsets removed from the zone.
    pub removed: Arc<HashMap<(StoredName, Rtype), SharedRrset>>,
}

impl InMemoryZoneDiff {
    /// Creates a new immutable zone diff.
    ///
    /// Returns `Err(ZoneDiffError::MissingStartSoa)` If the removed records
    /// do not include a zone SOA.
    ///
    /// Returns `Err(ZoneDiffError::MissingEndSoa)` If the added records do
    /// not include a zone SOA.
    ///
    /// Returns Ok otherwise.
    fn new(
        added: HashMap<(Name<Bytes>, Rtype), SharedRrset>,
        removed: HashMap<(Name<Bytes>, Rtype), SharedRrset>,
    ) -> Result<Self, ZoneDiffError> {
        // Determine the old and new SOA serials by looking at the added and
        // removed records.
        let start_serial = removed
            .iter()
            .find_map(|((_, rtype), rrset)| {
                if *rtype == Rtype::SOA {
                    if let Some(ZoneRecordData::Soa(soa)) =
                        rrset.data().first()
                    {
                        return Some(soa.serial());
                    }
                }
                None
            })
            .ok_or(ZoneDiffError::MissingStartSoa)?;

        let end_serial = added
            .iter()
            .find_map(|((_, rtype), rrset)| {
                if *rtype == Rtype::SOA {
                    if let Some(ZoneRecordData::Soa(soa)) =
                        rrset.data().first()
                    {
                        return Some(soa.serial());
                    }
                }
                None
            })
            .ok_or(ZoneDiffError::MissingEndSoa)?;

        if start_serial == end_serial || end_serial < start_serial {
            trace!("Diff construction error: serial {start_serial} -> serial {end_serial}:\nremoved: {removed:#?}\nadded: {added:#?}\n");
            return Err(ZoneDiffError::InvalidSerialRange);
        }

        trace!(
            "Built diff from serial {start_serial} to serial {end_serial}"
        );

        Ok(Self {
            start_serial,
            end_serial,
            added: added.into(),
            removed: removed.into(),
        })
    }
}

//--- impl ZoneDiff

impl<'a> ZoneDiffItem for (&'a (StoredName, Rtype), &'a SharedRrset) {
    fn key(&self) -> &(StoredName, Rtype) {
        self.0
    }

    fn value(&self) -> &SharedRrset {
        self.1
    }
}

impl ZoneDiff for InMemoryZoneDiff {
    type Item<'a> = (&'a (StoredName, Rtype), &'a SharedRrset)
    where
        Self: 'a;

    type Stream<'a> = futures_util::stream::Iter<hash_map::Iter<'a, (StoredName, Rtype), SharedRrset>>
    where
        Self: 'a;

    fn start_serial(
        &self,
    ) -> Pin<Box<dyn Future<Output = Serial> + Send + '_>> {
        Box::pin(ready(self.start_serial))
    }

    fn end_serial(
        &self,
    ) -> Pin<Box<dyn Future<Output = Serial> + Send + '_>> {
        Box::pin(ready(self.end_serial))
    }

    fn added(&self) -> Self::Stream<'_> {
        stream::iter(self.added.iter())
    }

    fn removed(&self) -> Self::Stream<'_> {
        stream::iter(self.removed.iter())
    }

    fn get_added(
        &self,
        name: impl ToName,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Option<&SharedRrset>> + Send + '_>> {
        Box::pin(ready(self.added.get(&(name.to_name(), rtype))))
    }

    fn get_removed(
        &self,
        name: impl ToName,
        rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Option<&SharedRrset>> + Send + '_>> {
        Box::pin(ready(self.removed.get(&(name.to_name(), rtype))))
    }
}

/// TODO
pub struct EmptyZoneDiffItem;

impl ZoneDiffItem for EmptyZoneDiffItem {
    fn key(&self) -> &(StoredName, Rtype) {
        unreachable!()
    }

    fn value(&self) -> &SharedRrset {
        unreachable!()
    }
}

/// TODO
#[derive(Debug)]
pub struct EmptyZoneDiffStream;

impl futures_util::stream::Stream for EmptyZoneDiffStream {
    type Item = EmptyZoneDiffItem;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

/// TODO
#[derive(Debug)]
pub struct EmptyZoneDiff;

impl ZoneDiff for EmptyZoneDiff {
    type Item<'a> = EmptyZoneDiffItem
    where
        Self: 'a;

    type Stream<'a> = EmptyZoneDiffStream
    where
        Self: 'a;

    fn start_serial(
        &self,
    ) -> Pin<Box<dyn Future<Output = Serial> + Send + '_>> {
        Box::pin(ready(Serial(0)))
    }

    fn end_serial(
        &self,
    ) -> Pin<Box<dyn Future<Output = Serial> + Send + '_>> {
        Box::pin(ready(Serial(0)))
    }

    fn added(&self) -> Self::Stream<'_> {
        EmptyZoneDiffStream
    }

    fn removed(&self) -> Self::Stream<'_> {
        EmptyZoneDiffStream
    }

    fn get_added(
        &self,
        _name: impl ToName,
        _rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Option<&SharedRrset>> + Send + '_>> {
        Box::pin(ready(None))
    }

    fn get_removed(
        &self,
        _name: impl ToName,
        _rtype: Rtype,
    ) -> Pin<Box<dyn Future<Output = Option<&SharedRrset>> + Send + '_>> {
        Box::pin(ready(None))
    }
}

//------------ ZoneDiffError --------------------------------------------------

/// Creating a [`ZoneDiff`] failed for some reason.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ZoneDiffError {
    /// Missing start SOA.
    ///
    /// A zone diff requires a starting SOA.
    MissingStartSoa,

    /// Missing end SOA.
    ///
    /// A zone diff requires a starting SOA.
    MissingEndSoa,

    /// End SOA serial is equal to or less than the start SOA serial.
    InvalidSerialRange,
}

//--- Display

impl std::fmt::Display for ZoneDiffError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZoneDiffError::MissingStartSoa => f.write_str("MissingStartSoa"),
            ZoneDiffError::MissingEndSoa => f.write_str("MissingEndSoa"),
            ZoneDiffError::InvalidSerialRange => {
                f.write_str("InvalidSerialRange")
            }
        }
    }
}

//------------ ZoneUpdate -----------------------------------------------------

/// An update to be applied to a [`Zone`].
///
/// # Design
///
/// The variants of this enum are modelled after the way the AXFR and IXFR
/// protocols represent updates to zones.
///
/// AXFR responses can be represented as a sequence of
/// [`ZoneUpdate::AddRecord`]s.
///
/// IXFR responses can be represented as a sequence of batches, each
/// consisting of:
/// - [`ZoneUpdate::BeginBatchDelete`]
/// - [`ZoneUpdate::DeleteRecord`]s _(zero or more)_
/// - [`ZoneUpdate::BeginBatchAdd`]
/// - [`ZoneUpdate::AddRecord`]s _(zero or more)_
///
/// Both AXFR and IXFR responses encoded using this enum are terminated by a
/// final [`ZoneUpdate::Finished`].
///
/// # Use within this crate
///  
/// [`XfrResponseInterpreter`] can convert received XFR responses into
/// sequences of [`ZoneUpdate`]s. These can then be consumed by a
/// [`ZoneUpdater`] to effect changes to an existing [`Zone`].
///
/// # Future extensions
///
/// This enum is marked as `#[non_exhaustive]` to permit addition of more
/// update operations in future, e.g. to support RFC 2136 Dynamic Updates
/// operations.
///
/// [`XfrResponseInterpreter`]:
///     crate::net::xfr::protocol::XfrResponseInterpreter
/// [`Zone`]: crate::zonetree::zone::Zone
/// [`ZoneUpdater`]: crate::zonetree::update::ZoneUpdater
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZoneUpdate<R> {
    /// Delete all records in the zone.
    DeleteAllRecords,

    /// Delete record R from the zone.
    DeleteRecord(R),

    /// Add record R to the zone.
    AddRecord(R),

    /// Start a batch delete for the version of the zone with the given SOA
    /// record.
    ///
    /// If not already in batching mode, this signals the start of batching
    /// mode. In batching mode one or more batches of updates will be
    /// signalled, each consisting of the sequence:
    ///
    /// - ZoneUpdate::BeginBatchDelete
    /// - ZoneUpdate::DeleteRecord (zero or more)
    /// - ZoneUpdate::BeginBatchAdd
    /// - ZoneUpdate::AddRecord (zero or more)
    ///
    /// Batching mode can only be terminated by `UpdateComplete` or
    /// `UpdateIncomplete`.
    ///
    /// Batching mode makes updates more predictable for the receiver to work
    /// with by limiting the updates that can be signalled next, enabling
    /// receiver logic to be simpler and more efficient.
    ///
    /// The record must be a SOA record that matches the SOA record of the
    /// zone version in which the subsequent [`ZoneUpdate::DeleteRecord`]s
    /// should be deleted.
    BeginBatchDelete(R),

    /// Start a batch add for the version of the zone with the given SOA
    /// record.
    ///
    /// This can only be signalled when already in batching mode, i.e. when
    /// `BeginBatchDelete` has already been signalled.
    ///
    /// The record must be the SOA record to use for the new version of the
    /// zone under which the subsequent [`ZoneUpdate::AddRecord`]s will be
    /// added.
    ///
    /// See `BeginBatchDelete` for more information.
    BeginBatchAdd(R),

    /// In progress updates for the zone can now be finalized.
    ///
    /// This signals the end of a group of related changes for the given SOA
    /// record of the zone.
    ///
    /// For example this could be used to trigger an atomic commit of a set of
    /// related pending changes.
    Finished(R),
}

//--- Display

impl<R> std::fmt::Display for ZoneUpdate<R> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ZoneUpdate::DeleteAllRecords => f.write_str("DeleteAllRecords"),
            ZoneUpdate::DeleteRecord(_) => f.write_str("DeleteRecord"),
            ZoneUpdate::AddRecord(_) => f.write_str("AddRecord"),
            ZoneUpdate::BeginBatchDelete(_) => {
                f.write_str("BeginBatchDelete")
            }
            ZoneUpdate::BeginBatchAdd(_) => f.write_str("BeginBatchAdd"),
            ZoneUpdate::Finished(_) => f.write_str("Finished"),
        }
    }
}
