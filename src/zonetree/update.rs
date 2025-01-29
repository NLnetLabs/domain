//! High-level support for applying changes to a [`Zone`].
//!
//! This module provides a high-level interface for making alterations to the
//! content of zones without requiring knowledge of the low-level details of
//! how the [`WritableZone`] trait implemented by [`Zone`] works.
use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;

use std::boxed::Box;

use bytes::Bytes;
use tracing::trace;

use crate::base::name::{FlattenInto, Label};
use crate::base::scan::ScannerError;
use crate::base::{Name, Record, Rtype, ToName};
use crate::rdata::ZoneRecordData;
use crate::zonetree::{Rrset, SharedRrset};

use super::error::OutOfZone;
use super::types::ZoneUpdate;
use super::util::rel_name_rev_iter;
use super::{InMemoryZoneDiff, WritableZone, WritableZoneNode, Zone};

/// Apply a sequence of [`ZoneUpdate`]s to update the content of a [`Zone`].
///
/// For each version of the zone that is edited the zone will be opened for
/// writing, edits made and then the changes committed, only then becoming
/// visible for readers of the zone.
///
/// Changes to the zone are committed when [`ZoneUpdate::Finished`] is
/// received, or rolled back if [`ZoneUpdater`] is dropped before receiving
/// [`ZoneUpdate::Finished`].
///
/// For each commit of the zone a diff of the changes made is requested and,
/// if a diff was actually created, will be returned by [`apply()`].
///
/// # Usage
///
/// [`ZoneUpdater`] can be used manually, or in combination with a source of
/// [`ZoneUpdate`]s such as
/// [`XfrResponseInterpreter`][crate::net::xfr::protocol::XfrResponseInterpreter].
///
/// Pass updates to be applied to the zone one at a time to [`apply()`].
///
/// To completely replace the content of a zone pass
/// [`ZoneUpdate::DeleteAllRecords`] to [`apply()`] before any other updates.
///
/// # Replacing the content of a zone
///
/// ```
/// # use std::str::FromStr;
/// #
/// # use domain::base::iana::Class;
/// # use domain::base::MessageBuilder;
/// # use domain::base::Name;
/// # use domain::base::ParsedName;
/// # use domain::base::Record;
/// # use domain::base::Serial;
/// # use domain::base::Ttl;
/// # use domain::base::net::Ipv4Addr;
/// # use domain::net::xfr::protocol::XfrResponseInterpreter;
/// # use domain::rdata::A;
/// # use domain::rdata::Soa;
/// # use domain::rdata::ZoneRecordData;
/// # use domain::zonetree::ZoneBuilder;
/// # use domain::zonetree::types::ZoneUpdate;
/// # use domain::zonetree::update::ZoneUpdater;
/// #
/// # #[tokio::main]
/// # async fn main() {
/// #
/// # let builder = ZoneBuilder::new(Name::from_str("example.com").unwrap(), Class::IN);
/// # let zone = builder.build();
/// #
/// # // Prepare some records to pass to ZoneUpdater
/// # let serial = Serial::now();
/// # let mname = ParsedName::from(Name::from_str("mname").unwrap());
/// # let rname = ParsedName::from(Name::from_str("rname").unwrap());
/// # let ttl = Ttl::from_secs(0);
/// # let new_soa_rec = Record::new(
/// #     ParsedName::from(Name::from_str("example.com").unwrap()),
/// #     Class::IN,
/// #     Ttl::from_secs(0),
/// #     ZoneRecordData::Soa(Soa::new(mname, rname, serial, ttl, ttl, ttl, ttl)),
/// # );
/// #
/// # let a_data = A::new(Ipv4Addr::LOCALHOST);
/// # let a_rec = Record::new(
/// #     ParsedName::from(Name::from_str("a.example.com").unwrap()),
/// #     Class::IN,
/// #     Ttl::from_secs(0),
/// #     ZoneRecordData::A(A::new(Ipv4Addr::LOCALHOST)),
/// # );
/// #
/// let mut updater = ZoneUpdater::new(zone.clone()).await.unwrap();
/// updater.apply(ZoneUpdate::DeleteAllRecords);
/// updater.apply(ZoneUpdate::AddRecord(a_rec));
/// updater.apply(ZoneUpdate::Finished(new_soa_rec));
/// #
/// # }
/// ```
///
/// # Altering the content of a zone
///
/// ```rust
/// # use std::str::FromStr;
/// #
/// # use domain::base::iana::Class;
/// # use domain::base::MessageBuilder;
/// # use domain::base::Name;
/// # use domain::base::ParsedName;
/// # use domain::base::Record;
/// # use domain::base::Serial;
/// # use domain::base::Ttl;
/// # use domain::base::net::Ipv4Addr;
/// # use domain::base::net::Ipv6Addr;
/// # use domain::net::xfr::protocol::XfrResponseInterpreter;
/// # use domain::rdata::A;
/// # use domain::rdata::Aaaa;
/// # use domain::rdata::Soa;
/// # use domain::rdata::ZoneRecordData;
/// # use domain::zonetree::ZoneBuilder;
/// # use domain::zonetree::update::ZoneUpdater;
/// # use domain::zonetree::types::ZoneUpdate;
/// #
/// # #[tokio::main]
/// # async fn main() {
/// #
/// # let builder = ZoneBuilder::new(Name::from_str("example.com").unwrap(), Class::IN);
/// # let zone = builder.build();
/// #
/// # // Prepare some records to pass to ZoneUpdater
/// # let serial = Serial::now();
/// # let mname = ParsedName::from(Name::from_str("mname").unwrap());
/// # let rname = ParsedName::from(Name::from_str("rname").unwrap());
/// # let ttl = Ttl::from_secs(0);
/// # let new_soa_rec = Record::new(
/// #     ParsedName::from(Name::from_str("example.com").unwrap()),
/// #     Class::IN,
/// #     Ttl::from_secs(0),
/// #     ZoneRecordData::Soa(Soa::new(mname, rname, serial, ttl, ttl, ttl, ttl)),
/// # );
/// #
/// # let old_a_data = A::new(Ipv4Addr::LOCALHOST);
/// # let old_a_rec = Record::new(
/// #     ParsedName::from(Name::from_str("a.example.com").unwrap()),
/// #     Class::IN,
/// #     Ttl::from_secs(0),
/// #     ZoneRecordData::A(A::new(Ipv4Addr::LOCALHOST)),
/// # );
/// #
/// # let new_aaaa_data = Aaaa::new(Ipv6Addr::LOCALHOST);
/// # let new_aaaa_rec = Record::new(
/// #     ParsedName::from(Name::from_str("a.example.com").unwrap()),
/// #     Class::IN,
/// #     Ttl::from_secs(0),
/// #     ZoneRecordData::A(A::new(Ipv4Addr::LOCALHOST)),
/// # );
/// #
/// let mut updater = ZoneUpdater::new(zone.clone()).await.unwrap();
/// updater.apply(ZoneUpdate::DeleteRecord(old_a_rec));
/// updater.apply(ZoneUpdate::AddRecord(new_aaaa_rec));
/// updater.apply(ZoneUpdate::Finished(new_soa_rec));
/// #
/// # }
/// ```
///
/// # Applying XFR changes to a zone
///
/// ```no_run
/// # use std::str::FromStr;
/// #
/// # use domain::base::iana::Class;
/// # use domain::base::MessageBuilder;
/// # use domain::base::Name;
/// # use domain::base::Serial;
/// # use domain::net::xfr::protocol::XfrResponseInterpreter;
/// # use domain::zonetree::ZoneBuilder;
/// # use domain::zonetree::update::ZoneUpdater;
/// #
/// # #[tokio::main]
/// # async fn main() {
/// #
/// // Given a zone
/// let builder = ZoneBuilder::new(Name::from_str("example.com").unwrap(), Class::IN);
/// let zone = builder.build();
///
/// // And a ZoneUpdater
/// let mut updater = ZoneUpdater::new(zone.clone()).await.unwrap();
///
/// // And an XFR response interpreter
/// let mut interpreter = XfrResponseInterpreter::new();
///
/// // Iterate over the XFR responses applying the updates to the zone
/// while !interpreter.is_finished() {
///     // Get the next XFR response:
///     // For this example this is just a dummy response, which would cause
///     // Error::NotValidXfrResponse if this code were run.
///     let next_xfr_response = MessageBuilder::new_bytes().into_message();
///
///     // Convert it to an update iterator
///     let it = interpreter.interpret_response(next_xfr_response).unwrap();
///
///     // Iterate over the updates
///     for update in it {
///         // Apply each update to the zone
///         updater.apply(update.unwrap()).await.unwrap();
///     }
/// }
/// #
/// # }
/// ```
///
/// [`apply()`]: ZoneUpdater::apply()
pub struct ZoneUpdater<N> {
    /// The zone to be updated.
    zone: Zone,

    /// The current write handles in use.
    ///
    /// For each new zone version any old write state has to be committed and
    /// a new write state opened.
    write: ReopenableZoneWriter,

    /// The current state of the updater.
    state: ZoneUpdaterState,

    _phantom: PhantomData<N>,
}

impl<N> ZoneUpdater<N>
where
    N: ToName + Clone,
    ZoneRecordData<Bytes, N>: FlattenInto<ZoneRecordData<Bytes, Name<Bytes>>>,
{
    /// Creates a new [`ZoneUpdater`] that will update the given [`Zone`]
    /// content.
    ///
    /// Returns the new instance on success, or an error if the zone could not
    /// be opened for writing.
    ///
    /// Use [`apply`][Self::apply] to apply changes to the zone.
    pub fn new(
        zone: Zone,
    ) -> Pin<Box<dyn Future<Output = Result<Self, Error>> + Send>> {
        Box::pin(async move {
            let write = ReopenableZoneWriter::new(zone.clone()).await?;

            Ok(Self {
                zone,
                write,
                state: Default::default(),
                _phantom: PhantomData,
            })
        })
    }
}

impl<N> ZoneUpdater<N>
where
    N: ToName + Clone,
    ZoneRecordData<Bytes, N>: FlattenInto<ZoneRecordData<Bytes, Name<Bytes>>>,
{
    /// Apply the given [`ZoneUpdate`] to the [`Zone`] being updated.
    ///
    /// Returns `Ok` on success, `Err` otherwise. On success, if changes were
    /// committed then any diff made by the `Zone` backing store
    /// implementation will be returned.
    ///
    /// Changes to the zone are committed when [`ZoneUpdate::Finished`] is
    /// received, or rolled back if [`ZoneUpdater`] is dropped before
    /// receiving [`ZoneUpdate::Finished`].
    ///
    /// Passing [`ZoneUpdate::BeginBatchDelete`] will also commit any edits in
    /// progress and re-open the zone for editing again.
    pub async fn apply(
        &mut self,
        update: ZoneUpdate<Record<N, ZoneRecordData<Bytes, N>>>,
    ) -> Result<Option<InMemoryZoneDiff>, Error> {
        trace!("Update: {update}");

        if self.state == ZoneUpdaterState::Finished {
            return Err(Error::Finished);
        }

        match update {
            ZoneUpdate::DeleteAllRecords => {
                // To completely replace the content of the zone, i.e. with
                // something like an AXFR transfer, we can't add records from
                // a new version of the zone to an existing zone because if
                // the old version contained a record which the new version
                // does not, the record would remain in the zone. So in this
                // case we have to mark all of the existing records in the
                // zone as "removed" and then add new records. This allows the
                // old records to continue being served to current consumers
                // while the zone is being updated.
                self.write.remove_all().await?;
            }

            ZoneUpdate::DeleteRecord(rec) => {
                self.delete_record_from_rrset(rec).await?
            }

            ZoneUpdate::AddRecord(rec) => {
                self.add_record_to_rrset(rec).await?
            }

            // Batch deletion signals the start of a batch, and the end of any
            // batch addition that was in progress.
            ZoneUpdate::BeginBatchDelete(_old_soa) => {
                // Commit the previous batch.
                let diff = self.write.commit().await?;

                // Open a writer for the new batch.
                self.write.reopen().await?;

                self.state = ZoneUpdaterState::Batching;

                return Ok(diff);
            }

            ZoneUpdate::BeginBatchAdd(new_soa) => {
                // Update the SOA record.
                self.update_soa(new_soa).await?;
                self.state = ZoneUpdaterState::Batching;
            }

            ZoneUpdate::Finished(zone_soa) => {
                // Update the SOA record.
                self.update_soa(zone_soa).await?;

                // Commit the previous batch and return any diff produced.
                let diff = self.write.commit().await?;

                // Close this updater
                self.write.close()?;
                self.state = ZoneUpdaterState::Finished;

                return Ok(diff);
            }
        }

        Ok(None)
    }

    /// Has zone updating finished?
    ///
    /// If true, further calls to [`apply()`] will fail.
    ///
    /// [`apply()`]: Self::apply
    pub fn is_finished(&self) -> bool {
        self.state == ZoneUpdaterState::Finished
    }
}

impl<N> ZoneUpdater<N>
where
    N: ToName + Clone,
    ZoneRecordData<Bytes, N>: FlattenInto<ZoneRecordData<Bytes, Name<Bytes>>>,
{
    /// Given a zone record, obtain a [`WritableZoneNode`] for the owner.
    ///
    /// A [`Zone`] is a tree structure which can be modified by descending the
    /// tree from parent to child one (dot separated) label at a time.
    ///
    /// This function constructs an iterator over the labels of the owner name
    /// of the given record then descends the tree one label at a time,
    /// creating nodes if needed, until the appropriate end node has been
    /// reached.
    ///
    /// If the owner name of the given record is not overlapping with the apex
    /// name of the zone an out of zone error will occur.
    ///
    /// # Panics
    ///
    /// This function may panic if it is unable to create new tree nodes for
    /// the record owner name.
    async fn get_writable_child_node_for_owner(
        &mut self,
        rec: &Record<N, ZoneRecordData<Bytes, N>>,
    ) -> Result<Option<Box<dyn WritableZoneNode>>, Error> {
        let mut it = rel_name_rev_iter(self.zone.apex_name(), rec.owner())?;

        let Some(label) = it.next() else {
            return Ok(None);
        };

        let mut child_node = self.write.update_child(label).await?;

        // Find (create if missing) the tree node for the owner name
        // of the given record.
        for label in it {
            child_node = child_node.update_child(label).await?;
        }

        Ok(Some(child_node))
    }

    /// Create or update the SOA RRset using the given SOA record.
    async fn update_soa(
        &mut self,
        new_soa: Record<N, ZoneRecordData<Bytes, N>>,
    ) -> Result<(), Error> {
        if new_soa.rtype() != Rtype::SOA {
            return Err(Error::NotSoaRecord);
        }

        let mut rrset = Rrset::new(Rtype::SOA, new_soa.ttl());
        let Ok(flattened) = new_soa.data().clone().try_flatten_into() else {
            return Err(Error::IoError(std::io::Error::custom(
                "Unable to flatten bytes",
            )));
        };
        rrset.push_data(flattened);
        self.write
            .update_root_rrset(SharedRrset::new(rrset))
            .await?;

        Ok(())
    }

    /// Find and delete a resource record in the zone by exact match.
    async fn delete_record_from_rrset(
        &mut self,
        rec: Record<N, ZoneRecordData<Bytes, N>>,
    ) -> Result<(), Error> {
        // Find or create the point to edit in the node tree.
        let tree_node = self.get_writable_child_node_for_owner(&rec).await?;
        let tree_node = tree_node.as_ref().unwrap_or(self.write.root());

        // Prepare an RRset that contains all of the records of the existing
        // RRset in the tree except the one to delete.
        let mut rrset = Rrset::new(rec.rtype(), rec.ttl());
        let rtype = rec.rtype();
        let data = rec.data();

        if let Some(existing_rrset) = tree_node.get_rrset(rtype).await? {
            for existing_data in existing_rrset.data() {
                if existing_data != data {
                    rrset.push_data(existing_data.clone());
                }
            }
        }

        // Replace the RRset in the tree with the new smaller one.
        if rrset.is_empty() {
            tree_node.remove_rrset(rrset.rtype()).await?;
        } else {
            tree_node.update_rrset(SharedRrset::new(rrset)).await?;
        }

        Ok(())
    }

    /// Add a resource record to a new or existing RRset.
    async fn add_record_to_rrset(
        &mut self,
        rec: Record<N, ZoneRecordData<Bytes, N>>,
    ) -> Result<(), Error>
    where
        ZoneRecordData<Bytes, N>:
            FlattenInto<ZoneRecordData<Bytes, Name<Bytes>>>,
    {
        // Find or create the point to edit in the node tree.
        let tree_node = self.get_writable_child_node_for_owner(&rec).await?;
        let tree_node = tree_node.as_ref().unwrap_or(self.write.root());

        // Prepare an RRset that contains all of the records of the existing
        // RRset in the tree plus the one to add.
        let mut rrset = Rrset::new(rec.rtype(), rec.ttl());
        let rtype = rec.rtype();
        let Ok(data) = rec.into_data().try_flatten_into() else {
            return Err(Error::IoError(std::io::Error::custom(
                "Unable to flatten bytes",
            )));
        };

        rrset.push_data(data);

        if let Some(existing_rrset) = tree_node.get_rrset(rtype).await? {
            for existing_data in existing_rrset.data() {
                rrset.push_data(existing_data.clone());
            }
        }

        // Replace the Rrset in the tree with the new bigger one.
        tree_node.update_rrset(SharedRrset::new(rrset)).await?;

        Ok(())
    }
}

//------------ ZoneUpdaterState -----------------------------------------------

/// The current state of a [`ZoneUpdater`].
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
enum ZoneUpdaterState {
    #[default]
    Normal,

    /// IXFR-like batching mode.
    Batching,

    /// Finished.
    ///
    /// [`ZoneUpdate::Finished`] was encountered.
    ///
    /// The [`ZoneUpdater`] has closed the [`WritableZone`] and can no longer
    /// be used.
    Finished,
}

//------------ ReopenableZoneWriter -------------------------------------------

/// State for writing multiple zone versions in sequence.
///
/// This type provides write access to the next version of a zone and
/// convenience methods for working with the zone.
///
/// If needed after commiting one version of the zone being edited the writer
/// can be re-opened to write the next version of the zone.
struct ReopenableZoneWriter {
    /// A write interface to a zone.
    write: Option<Box<dyn WritableZone>>,

    /// A write interface to the root node of a zone for a particular zone
    /// version.
    writable: Option<Box<dyn WritableZoneNode>>,
}

impl ReopenableZoneWriter {
    /// Creates a writer for the given [`Zone`].
    async fn new(zone: Zone) -> std::io::Result<Self> {
        let write = zone.write().await;
        let writable = Some(write.open(true).await?);
        let write = Some(write);
        Ok(Self { write, writable })
    }

    /// Commits any pending changes to the [`Zone`] being written to.
    ///
    /// Returns the created diff, if any.
    async fn commit(&mut self) -> Result<Option<InMemoryZoneDiff>, Error> {
        // Commit the deletes and adds that just occurred
        if let Some(writable) = self.writable.take() {
            // Ensure that there are no dangling references to the created
            // diff (otherwise commit() will panic).
            drop(writable);

            let diff = self
                .write
                .as_mut()
                .ok_or(Error::Finished)?
                .commit(false)
                .await?;

            Ok(diff)
        } else {
            Ok(None)
        }
    }

    /// Replaces the current root node write interface with a new one.
    ///
    /// Call [`commit()`][Self::commit] before calling this method.
    async fn reopen(&mut self) -> Result<(), Error> {
        self.writable = Some(
            self.write
                .as_mut()
                .ok_or(Error::Finished)?
                .open(true)
                .await?,
        );
        Ok(())
    }

    /// Close all write state, if not closed already.
    fn close(&mut self) -> Result<(), Error> {
        self.writable.take();
        self.write.take().ok_or(Error::Finished)?;
        Ok(())
    }

    /// Convenience method to mark all nodes in the tree as removed.
    ///
    /// Current readers will not be affected until [`commit()`][Self::commit]
    /// is called.
    async fn remove_all(&mut self) -> std::io::Result<()> {
        if let Some(writable) = &mut self.writable {
            writable.remove_all().await?;
        }

        Ok(())
    }

    /// Get a write interface to a child node of the tree.
    ///
    /// Use this to modify child nodes in the tree.
    async fn update_child(
        &self,
        label: &Label,
    ) -> std::io::Result<Box<dyn WritableZoneNode>> {
        self.root().update_child(label).await
    }

    /// Replace the RRset at the root node with the given RRset.
    async fn update_root_rrset(
        &self,
        rrset: SharedRrset,
    ) -> std::io::Result<()> {
        self.root().update_rrset(rrset).await
    }

    /// Helper method to access the current root node zone writer.
    #[allow(clippy::borrowed_box)]
    fn root(&self) -> &Box<dyn WritableZoneNode> {
        // SAFETY: Writable is always Some so is safe to unwrap.
        self.writable.as_ref().unwrap()
    }
}

//------------ Tests ----------------------------------------------------------

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use std::sync::Arc;
    use std::vec::Vec;

    use bytes::BytesMut;
    use octseq::Octets;

    use crate::base::iana::{Class, Rcode};
    use crate::base::message_builder::{AnswerBuilder, QuestionBuilder};
    use crate::base::net::Ipv4Addr;
    use crate::base::rdata::ComposeRecordData;
    use crate::base::{
        Message, MessageBuilder, Name, ParsedName, Record, Serial, Ttl,
    };
    use crate::net::xfr::protocol::XfrResponseInterpreter;
    use crate::rdata::{Ns, Soa, A};
    use crate::zonetree::ZoneBuilder;

    use super::*;

    #[tokio::test]
    async fn write_soa_read_soa() {
        init_logging();

        let zone = mk_empty_zone("example.com");

        let mut updater = ZoneUpdater::new(zone.clone()).await.unwrap();

        let qname = Name::from_str("example.com").unwrap();

        let s = Serial::now();
        let soa = mk_soa(s);
        let soa_data = ZoneRecordData::Soa(soa.clone());
        let soa_rec = Record::new(
            ParsedName::from(qname.clone()),
            Class::IN,
            Ttl::from_secs(0),
            soa_data,
        );

        updater
            .apply(ZoneUpdate::AddRecord(soa_rec.clone()))
            .await
            .unwrap();

        let diff = updater
            .apply(ZoneUpdate::Finished(soa_rec.clone()))
            .await
            .unwrap();

        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        query.push((qname.clone(), Rtype::SOA)).unwrap();
        let message: Message<Vec<u8>> = query.into();

        let builder = MessageBuilder::new_bytes();
        let answer: Message<Bytes> = zone
            .read()
            .query(qname, Rtype::SOA)
            .unwrap()
            .to_message(&message, builder)
            .into();

        let found_soa_rec = answer
            .answer()
            .unwrap()
            .limit_to::<Soa<_>>()
            .next()
            .unwrap()
            .unwrap()
            .into_data();

        assert_eq!(found_soa_rec, soa);

        // No diff because there is no prior SOA serial
        assert!(diff.is_none());
    }

    #[tokio::test]
    async fn diff_check() {
        init_logging();

        let zone = mk_empty_zone("example.com");

        let mut updater = ZoneUpdater::new(zone.clone()).await.unwrap();

        let qname = Name::from_str("example.com").unwrap();

        let s = Serial(20240922);
        let soa = mk_soa(s);
        let soa_data = ZoneRecordData::Soa(soa.clone());
        let soa_rec = Record::new(
            ParsedName::from(qname.clone()),
            Class::IN,
            Ttl::from_secs(0),
            soa_data,
        );

        updater
            .apply(ZoneUpdate::AddRecord(soa_rec.clone()))
            .await
            .unwrap();

        let diff = updater
            .apply(ZoneUpdate::Finished(soa_rec.clone()))
            .await
            .unwrap();

        // No diff because there is no prior SOA serial
        assert!(diff.is_none());

        let soa = mk_soa(s.add(1));
        let soa_data = ZoneRecordData::Soa(soa.clone());
        let soa_rec = Record::new(
            ParsedName::from(qname.clone()),
            Class::IN,
            Ttl::from_secs(0),
            soa_data,
        );

        assert!(updater.is_finished());

        let res = updater.apply(ZoneUpdate::AddRecord(soa_rec.clone())).await;
        assert!(matches!(res, Err(crate::zonetree::update::Error::Finished)));

        let mut updater = ZoneUpdater::new(zone.clone()).await.unwrap();

        updater
            .apply(ZoneUpdate::AddRecord(soa_rec.clone()))
            .await
            .unwrap();

        let diff = updater
            .apply(ZoneUpdate::Finished(soa_rec.clone()))
            .await
            .unwrap();

        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        query.push((qname.clone(), Rtype::SOA)).unwrap();
        let message: Message<Vec<u8>> = query.into();

        let builder = MessageBuilder::new_bytes();
        let answer: Message<Bytes> = zone
            .read()
            .query(qname, Rtype::SOA)
            .unwrap()
            .to_message(&message, builder)
            .into();

        let found_soa_rec = answer
            .answer()
            .unwrap()
            .limit_to::<Soa<_>>()
            .next()
            .unwrap()
            .unwrap()
            .into_data();

        assert_eq!(found_soa_rec, soa);

        assert!(diff.is_some());
        let diff = diff.unwrap();

        assert_eq!(diff.start_serial, Serial(20240922));
        assert_eq!(diff.end_serial, Serial(20240923));
    }

    #[tokio::test]
    async fn axfr_response_generates_expected_events() {
        init_logging();

        let zone = mk_empty_zone("example.com");

        let mut updater = ZoneUpdater::new(zone.clone()).await.unwrap();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an XFR response interpreter.
        let mut interpreter = XfrResponseInterpreter::new();

        // Create an AXFR response.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        let serial = Serial::now();
        let soa = mk_soa(serial);
        add_answer_record(&req, &mut answer, soa.clone());
        let a_1 = A::new(Ipv4Addr::LOCALHOST);
        add_answer_record(&req, &mut answer, a_1.clone());
        let a_2 = A::new(Ipv4Addr::BROADCAST);
        add_answer_record(&req, &mut answer, a_2.clone());
        add_answer_record(&req, &mut answer, soa.clone());
        let resp = answer.into_message();

        // Process the response.
        let it = interpreter.interpret_response(resp).unwrap();

        for update in it {
            let update = update.unwrap();
            updater.apply(update).await.unwrap();
        }

        // --------------------------------------------------------------------
        // Check the contents of the constructed zone.
        // --------------------------------------------------------------------

        // example.com   SOA
        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        let qname = Name::from_str("example.com").unwrap();
        query.push((qname.clone(), Rtype::SOA)).unwrap();
        let message: Message<Vec<u8>> = query.into();

        let builder = MessageBuilder::new_bytes();
        let answer: Message<Bytes> = zone
            .read()
            .query(qname, Rtype::SOA)
            .unwrap()
            .to_message(&message, builder)
            .into();

        let mut answers = answer.answer().unwrap().limit_to::<Soa<_>>();
        assert_eq!(answers.next().unwrap().unwrap().into_data(), soa);
        assert_eq!(answers.next(), None);

        // example.   A
        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        let qname = Name::from_str("example.com").unwrap();
        query.push((qname.clone(), Rtype::A)).unwrap();
        let message: Message<Vec<u8>> = query.into();

        let builder = MessageBuilder::new_bytes();
        let answer: Message<Bytes> = zone
            .read()
            .query(qname, Rtype::A)
            .unwrap()
            .to_message(&message, builder)
            .into();

        let mut answers = answer.answer().unwrap().limit_to::<A>();
        assert_eq!(answers.next().unwrap().unwrap().into_data(), a_2);
        assert_eq!(answers.next().unwrap().unwrap().into_data(), a_1);
        assert_eq!(answers.next(), None);
    }

    #[tokio::test]
    async fn rfc_1995_ixfr_example() {
        fn mk_rfc_1995_ixfr_example_soa(
            serial: u32,
        ) -> Record<ParsedName<Bytes>, ZoneRecordData<Bytes, ParsedName<Bytes>>>
        {
            Record::new(
                ParsedName::from(Name::from_str("JAIN.AD.JP.").unwrap()),
                Class::IN,
                Ttl::from_secs(0),
                Soa::new(
                    ParsedName::from(
                        Name::from_str("NS.JAIN.AD.JP.").unwrap(),
                    ),
                    ParsedName::from(
                        Name::from_str("mohta.jain.ad.jp.").unwrap(),
                    ),
                    Serial(serial),
                    Ttl::from_secs(600),
                    Ttl::from_secs(600),
                    Ttl::from_secs(3600000),
                    Ttl::from_secs(604800),
                )
                .into(),
            )
        }

        init_logging();

        // --------------------------------------------------------------------
        // Construct a zone according to the example in RFC 1995 section 7.
        // --------------------------------------------------------------------

        // https://datatracker.ietf.org/doc/html/rfc1995#section-7
        // 7. Example
        //    "Given the following three generations of data with the current
        //     serial number of 3,"
        let zone = mk_empty_zone("JAIN.AD.JP.");

        let mut updater = ZoneUpdater::new(zone.clone()).await.unwrap();
        //    JAIN.AD.JP.         IN SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. (
        //                                      1 600 600 3600000 604800)
        let soa_1 = mk_rfc_1995_ixfr_example_soa(1);
        updater
            .apply(ZoneUpdate::AddRecord(soa_1.clone()))
            .await
            .unwrap();

        //                        IN NS  NS.JAIN.AD.JP.
        let ns_1 = Record::new(
            ParsedName::from(Name::<Bytes>::from_str("JAIN.AD.JP.").unwrap()),
            Class::IN,
            Ttl::from_secs(0),
            Ns::new(ParsedName::from(
                Name::from_str("NS.JAIN.AD.JP.").unwrap(),
            ))
            .into(),
        );
        updater
            .apply(ZoneUpdate::AddRecord(ns_1.clone()))
            .await
            .unwrap();

        //    NS.JAIN.AD.JP.      IN A   133.69.136.1
        let a_1 = Record::new(
            ParsedName::from(
                Name::<Bytes>::from_str("NS.JAIN.AD.JP.").unwrap(),
            ),
            Class::IN,
            Ttl::from_secs(0),
            A::new(Ipv4Addr::new(133, 69, 136, 1)).into(),
        );
        updater
            .apply(ZoneUpdate::AddRecord(a_1.clone()))
            .await
            .unwrap();

        //    NEZU.JAIN.AD.JP.    IN A   133.69.136.5
        let nezu = Record::new(
            ParsedName::from(
                Name::<Bytes>::from_str("NEZU.JAIN.AD.JP.").unwrap(),
            ),
            Class::IN,
            Ttl::from_secs(0),
            A::new(Ipv4Addr::new(133, 69, 136, 5)).into(),
        );
        updater
            .apply(ZoneUpdate::AddRecord(nezu.clone()))
            .await
            .unwrap();

        //    "NEZU.JAIN.AD.JP. is removed and JAIN-BB.JAIN.AD.JP. is added."
        let diff_1 = updater
            .apply(ZoneUpdate::BeginBatchDelete(soa_1.clone()))
            .await
            .unwrap();
        updater
            .apply(ZoneUpdate::DeleteRecord(nezu.clone()))
            .await
            .unwrap();
        let soa_2 = mk_rfc_1995_ixfr_example_soa(2);
        updater
            .apply(ZoneUpdate::BeginBatchAdd(soa_2.clone()))
            .await
            .unwrap();
        let a_2 = Record::new(
            ParsedName::from(
                Name::<Bytes>::from_str("JAIN-BB.JAIN.AD.JP.").unwrap(),
            ),
            Class::IN,
            Ttl::from_secs(0),
            A::new(Ipv4Addr::new(133, 69, 136, 4)).into(),
        );
        updater
            .apply(ZoneUpdate::AddRecord(a_2.clone()))
            .await
            .unwrap();
        let a_3 = Record::new(
            ParsedName::from(Name::from_str("JAIN-BB.JAIN.AD.JP.").unwrap()),
            Class::IN,
            Ttl::from_secs(0),
            A::new(Ipv4Addr::new(192, 41, 197, 2)).into(),
        );
        updater
            .apply(ZoneUpdate::AddRecord(a_3.clone()))
            .await
            .unwrap();

        // //    "One of the IP addresses of JAIN-BB.JAIN.AD.JP. is changed."
        let diff_2 = updater
            .apply(ZoneUpdate::BeginBatchDelete(soa_2.clone()))
            .await
            .unwrap();
        updater
            .apply(ZoneUpdate::DeleteRecord(a_2.clone()))
            .await
            .unwrap();
        let soa_3 = mk_rfc_1995_ixfr_example_soa(3);
        updater
            .apply(ZoneUpdate::BeginBatchAdd(soa_3.clone()))
            .await
            .unwrap();
        let a_4 = Record::new(
            ParsedName::from(
                Name::<Bytes>::from_str("JAIN-BB.JAIN.AD.JP.").unwrap(),
            ),
            Class::IN,
            Ttl::from_secs(0),
            A::new(Ipv4Addr::new(133, 69, 136, 3)).into(),
        );
        updater
            .apply(ZoneUpdate::AddRecord(a_4.clone()))
            .await
            .unwrap();

        let diff_3 = updater
            .apply(ZoneUpdate::Finished(soa_3.clone()))
            .await
            .unwrap();

        // --------------------------------------------------------------------
        // Check the contents of the constructed zone.
        // --------------------------------------------------------------------

        let count = Arc::new(AtomicUsize::new(0));
        let cloned_count = count.clone();
        zone.read()
            .walk(Box::new(move |_name, _rrset, _at_zone_cut| {
                cloned_count.fetch_add(1, Ordering::SeqCst);
            }));

        assert_eq!(count.load(Ordering::SeqCst), 4);

        // JAIN.AD.JP.   SOA
        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        let qname = Name::from_str("JAIN.AD.JP.").unwrap();
        query.push((qname.clone(), Rtype::SOA)).unwrap();
        let message: Message<Vec<u8>> = query.into();

        let builder = MessageBuilder::new_bytes();
        let answer: Message<Bytes> = zone
            .read()
            .query(qname, Rtype::SOA)
            .unwrap()
            .to_message(&message, builder)
            .into();

        let mut answers =
            answer.answer().unwrap().limit_to::<ZoneRecordData<_, _>>();
        assert_eq!(answers.next().unwrap().unwrap(), soa_3);
        assert_eq!(answers.next(), None);

        // JAIN.AD.JP.   NS
        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        let qname = Name::from_str("JAIN.AD.JP.").unwrap();
        query.push((qname.clone(), Rtype::NS)).unwrap();
        let message: Message<Vec<u8>> = query.into();

        let builder = MessageBuilder::new_bytes();
        let answer: Message<Bytes> = zone
            .read()
            .query(qname, Rtype::NS)
            .unwrap()
            .to_message(&message, builder)
            .into();

        let mut answers =
            answer.answer().unwrap().limit_to::<ZoneRecordData<_, _>>();
        assert_eq!(answers.next().unwrap().unwrap(), ns_1);
        assert_eq!(answers.next(), None);

        // NS.JAIN.AD.JP.   A
        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        let qname = Name::from_str("NS.JAIN.AD.JP.").unwrap();
        query.push((qname.clone(), Rtype::A)).unwrap();
        let message: Message<Vec<u8>> = query.into();

        let builder = MessageBuilder::new_bytes();
        let answer: Message<Bytes> = zone
            .read()
            .query(qname, Rtype::A)
            .unwrap()
            .to_message(&message, builder)
            .into();

        let mut answers =
            answer.answer().unwrap().limit_to::<ZoneRecordData<_, _>>();
        assert_eq!(answers.next().unwrap().unwrap(), a_1);
        assert_eq!(answers.next(), None);

        // JAIN-BB.JAIN.AD.JP.   A
        let query = MessageBuilder::new_vec();
        let mut query = query.question();
        let qname = Name::from_str("JAIN-BB.JAIN.AD.JP.").unwrap();
        query.push((qname.clone(), Rtype::A)).unwrap();
        let message: Message<Vec<u8>> = query.into();

        let builder = MessageBuilder::new_bytes();
        let answer: Message<Bytes> = zone
            .read()
            .query(qname, Rtype::A)
            .unwrap()
            .to_message(&message, builder)
            .into();

        let mut answers =
            answer.answer().unwrap().limit_to::<ZoneRecordData<_, _>>();
        assert_eq!(answers.next().unwrap().unwrap(), a_4);
        assert_eq!(answers.next().unwrap().unwrap(), a_3);
        assert_eq!(answers.next(), None);

        //    "or with the following incremental message:"

        // --------------------------------------------------------------------
        // Check the contents of diff 1:
        // --------------------------------------------------------------------

        // No prior SOA so no diff.
        assert!(diff_1.is_none());

        // --------------------------------------------------------------------
        // Check the contents of diff 2:
        // --------------------------------------------------------------------

        // Diff from SOA serial 1 to SOA serial 2
        assert!(diff_2.is_some());
        let diff_2 = diff_2.unwrap();
        assert_eq!(diff_2.start_serial, Serial(1));
        assert_eq!(diff_2.end_serial, Serial(2));

        // Removed: SOA and one A record at NEZU.JAIN.AD.JP.
        assert_eq!(diff_2.removed.len(), 2);
        let mut expected = vec![nezu.into_data()];
        let mut actual = diff_2
            .removed
            .get(&(Name::from_str("NEZU.JAIN.AD.JP.").unwrap(), Rtype::A))
            .unwrap()
            .data()
            .to_vec();
        expected.sort();
        actual.sort();
        assert_eq!(expected, actual);

        // Added: SOA and two A records at JAIN-BB.JAIN.AD.JP.
        assert_eq!(diff_2.added.len(), 2);
        let mut expected = vec![a_2.clone().into_data(), a_3.into_data()];
        let mut actual = diff_2
            .added
            .get(&(Name::from_str("JAIN-BB.JAIN.AD.JP.").unwrap(), Rtype::A))
            .unwrap()
            .data()
            .to_vec();
        expected.sort();
        actual.sort();
        assert_eq!(expected, actual);

        // --------------------------------------------------------------------
        // Check the contents of diff 3:
        // --------------------------------------------------------------------

        // Diff from SOA serial 2 to SOA serial 3
        assert!(diff_3.is_some());
        let diff_3 = diff_3.unwrap();
        assert_eq!(diff_3.start_serial, Serial(2));
        assert_eq!(diff_3.end_serial, Serial(3));

        // Removed: SOA and one A record at JAIN-BB.JAIN.AD.JP.
        assert_eq!(diff_3.removed.len(), 2);
        let mut expected = vec![a_2.into_data()];
        let mut actual = diff_3
            .removed
            .get(&(Name::from_str("JAIN-BB.JAIN.AD.JP.").unwrap(), Rtype::A))
            .unwrap()
            .data()
            .to_vec();
        expected.sort();
        actual.sort();
        assert_eq!(expected, actual);

        // Added: SOA and one A record at JAIN-BB.JAIN.AD.JP.
        assert_eq!(diff_3.added.len(), 2);
        let mut expected = vec![a_4.into_data()];
        let mut actual = diff_3
            .added
            .get(&(Name::from_str("JAIN-BB.JAIN.AD.JP.").unwrap(), Rtype::A))
            .unwrap()
            .data()
            .to_vec();
        expected.sort();
        actual.sort();
        assert_eq!(expected, actual);
    }

    #[tokio::test]
    async fn check_rollback() {
        init_logging();

        let zone = mk_empty_zone("example.com");

        let mut updater = ZoneUpdater::new(zone.clone()).await.unwrap();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an XFR response interpreter.
        let mut interpreter = XfrResponseInterpreter::new();

        // Create an AXFR response.
        let mut answer = mk_empty_answer(&req, Rcode::NOERROR);
        let serial = Serial::now();
        let soa = mk_soa(serial);
        add_answer_record(&req, &mut answer, soa.clone());
        let a_1 = A::new(Ipv4Addr::LOCALHOST);
        add_answer_record(&req, &mut answer, a_1.clone());
        let a_2 = A::new(Ipv4Addr::BROADCAST);
        add_answer_record(&req, &mut answer, a_2.clone());
        add_answer_record(&req, &mut answer, soa.clone());
        let resp = answer.into_message();

        // Process the response.
        let it = interpreter.interpret_response(resp).unwrap();

        for update in it {
            let update = update.unwrap();
            // Don't pass ZoneUpdate::Finished to ZoneUpdater thereby preventing
            // it from commiting the changes to the zone.
            if !matches!(update, ZoneUpdate::Finished(_)) {
                updater.apply(update).await.unwrap();
            }
        }

        // Drop the ZoneUpdater to show that it definitely doesn't commit.
        drop(updater);

        // --------------------------------------------------------------------
        // Check the contents of the constructed zone.
        // --------------------------------------------------------------------

        let count = Arc::new(AtomicUsize::new(0));
        let cloned_count = count.clone();
        zone.read()
            .walk(Box::new(move |_name, _rrset, _at_zone_cut| {
                cloned_count.fetch_add(1, Ordering::SeqCst);
            }));

        assert_eq!(count.load(Ordering::SeqCst), 0);
    }

    //------------ Helper functions -------------------------------------------

    fn init_logging() {
        // Initialize tracing based logging. Override with env var RUST_LOG, e.g.
        // RUST_LOG=trace. DEBUG level will show the .rpl file name, Stelline step
        // numbers and types as they are being executed.
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_thread_ids(true)
            .without_time()
            .try_init()
            .ok();
    }

    fn mk_empty_zone(apex_name: &str) -> Zone {
        ZoneBuilder::new(Name::from_str(apex_name).unwrap(), Class::IN)
            .build()
    }

    fn mk_soa(serial: Serial) -> Soa<ParsedName<Bytes>> {
        let mname = ParsedName::from(Name::from_str("mname").unwrap());
        let rname = ParsedName::from(Name::from_str("rname").unwrap());
        let ttl = Ttl::from_secs(0);
        Soa::new(mname, rname, serial, ttl, ttl, ttl, ttl)
    }

    fn mk_request(qname: &str, qtype: Rtype) -> QuestionBuilder<BytesMut> {
        let req = MessageBuilder::new_bytes();
        let mut req = req.question();
        req.push((Name::vec_from_str(qname).unwrap(), qtype))
            .unwrap();
        req
    }

    fn mk_empty_answer(
        req: &Message<Bytes>,
        rcode: Rcode,
    ) -> AnswerBuilder<BytesMut> {
        let builder = MessageBuilder::new_bytes();
        builder.start_answer(req, rcode).unwrap()
    }

    fn add_answer_record<O: Octets, T: ComposeRecordData>(
        req: &Message<O>,
        answer: &mut AnswerBuilder<BytesMut>,
        item: T,
    ) {
        let question = req.sole_question().unwrap();
        let qname = question.qname();
        let qclass = question.qclass();
        answer
            .push((qname, qclass, Ttl::from_secs(0), item))
            .unwrap();
    }
}

//------------ Error ----------------------------------------------------------

/// Zone update error.
#[derive(Debug)]
pub enum Error {
    /// The record owner is outside the zone.
    OutOfZone,

    /// The record must be a SOA record.
    NotSoaRecord,

    /// An I/O error occurred while updating the zone.
    IoError(std::io::Error),

    /// The updater has finished and cannot be used anymore.
    Finished,
}

//--- Display

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::OutOfZone => f.write_str("OutOfZone"),
            Error::NotSoaRecord => f.write_str("NotSoaRecord"),
            Error::IoError(err) => write!(f, "I/O error: {err}"),

            Error::Finished => f.write_str("Finished"),
        }
    }
}

//--- From

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<OutOfZone> for Error {
    fn from(_: OutOfZone) -> Self {
        Self::OutOfZone
    }
}
