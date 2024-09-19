//! High-level support for applying changes to a [`Zone`].
//!
//! This module provides a high-level interface for making alterations to the
//! content of zones without requiring knowledge of the low-level details of
//! how the [`WritableZone`] trait implemented by [`Zone`] works.
use core::future::Future;
use core::pin::Pin;

use std::borrow::ToOwned;
use std::boxed::Box;
use std::io::Error as IoError;

use bytes::Bytes;
use tracing::trace;

use crate::base::name::FlattenInto;
use crate::base::scan::ScannerError;
use crate::base::{ParsedName, Record, Rtype};
use crate::net::xfr::protocol::ParsedRecord;
use crate::rdata::ZoneRecordData;
use crate::zonetree::{Rrset, SharedRrset};

use super::types::ZoneUpdate;
use super::util::rel_name_rev_iter;
use super::{WritableZone, WritableZoneNode, Zone, ZoneDiff};

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
pub struct ZoneUpdater {
    /// The zone to be updated.
    zone: Zone,

    /// The current write handles in use.
    ///
    /// For each new zone version any old write state has to be committed and
    /// a new write state opened.
    write: WriteState,

    /// Whether or not we entered an IXFR-like batching mode.
    batching: bool,
}

impl ZoneUpdater {
    /// Creates a new [`ZoneUpdater`] that will update the given [`Zone`]
    /// content.
    ///
    /// Returns the new instance on success, or an error if the zone could not
    /// be opened for writing.
    ///
    /// Use [`apply`][Self::apply] to apply changes to the zone.
    pub fn new(
        zone: Zone,
    ) -> Pin<Box<dyn Future<Output = std::io::Result<Self>> + Send>> {
        Box::pin(async move {
            let write = WriteState::new(zone.clone()).await?;

            Ok(Self {
                zone,
                write,
                batching: false,
            })
        })
    }
}

impl ZoneUpdater {
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
        update: ZoneUpdate<ParsedRecord>,
    ) -> std::io::Result<Option<ZoneDiff>> {
        trace!("Event: {update}");
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

            ZoneUpdate::DeleteRecord(rec) => self.delete_record(rec).await?,

            ZoneUpdate::AddRecord(rec) => self.add_record(rec).await?,

            // Batch deletion signals the start of a batch, and the end of any
            // batch addition that was in progress.
            ZoneUpdate::BeginBatchDelete(_old_soa) => {
                let diff = if self.batching {
                    // Commit the previous batch.
                    let diff = self.write.commit().await?;

                    // Open a writer for the new batch.
                    self.write.reopen().await?;

                    diff
                } else {
                    None
                };

                self.batching = true;

                return Ok(diff);
            }

            ZoneUpdate::BeginBatchAdd(new_soa) => {
                // Update the SOA record.
                self.update_soa(new_soa).await?;
                self.batching = true;
            }

            ZoneUpdate::Finished(zone_soa) => {
                // Update the SOA record.
                self.update_soa(zone_soa).await?;

                // Commit the previous batch and return any diff produced.
                return self.write.commit().await;
            }
        }

        Ok(None)
    }
}

impl ZoneUpdater {
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
        rec: &ParsedRecord,
    ) -> std::io::Result<Option<Box<dyn WritableZoneNode>>> {
        let owner = rec.owner().to_owned();

        let mut it = rel_name_rev_iter(self.zone.apex_name(), &owner)
            .map_err(|_| IoError::custom("Record owner name out of zone"))?;

        let Some(label) = it.next() else {
            return Ok(None);
        };

        let writable = self.write.writable.as_ref().unwrap();
        let mut node = writable.update_child(label).await?;

        // Find (create if missing) the tree node for the owner name
        // of the given record.
        for label in it {
            node = node.update_child(label).await?;
        }

        Ok(Some(node))
    }

    async fn update_soa(
        &mut self,
        new_soa: Record<
            ParsedName<Bytes>,
            ZoneRecordData<Bytes, ParsedName<Bytes>>,
        >,
    ) -> std::io::Result<()> {
        if new_soa.rtype() != Rtype::SOA {
            return Err(IoError::custom("Invalid SOA rtype"));
        }

        let mut rrset = Rrset::new(Rtype::SOA, new_soa.ttl());
        rrset.push_data(new_soa.data().to_owned().flatten_into());
        self.write
            .writable
            .as_ref()
            .unwrap()
            .update_rrset(SharedRrset::new(rrset))
            .await
    }

    /// Find and delete a record in the zone by exact match.
    async fn delete_record(
        &mut self,
        rec: Record<
            ParsedName<Bytes>,
            ZoneRecordData<Bytes, ParsedName<Bytes>>,
        >,
    ) -> std::io::Result<()> {
        let end_node = self.get_writable_child_node_for_owner(&rec).await?;
        let mut rrset = Rrset::new(rec.rtype(), rec.ttl());
        let rtype = rec.rtype();
        let data = rec.data();
        let writable = self.write.writable.as_ref().unwrap();

        trace!("Deleting RR for {rtype}");

        let node = end_node.as_ref().unwrap_or(writable);

        if let Some(existing_rrset) = node.get_rrset(rtype).await? {
            for existing_data in existing_rrset.data() {
                if existing_data != data {
                    rrset.push_data(existing_data.clone());
                }
            }
        }

        trace!("Removing single RR of {rtype} so updating RRSET");
        node.update_rrset(SharedRrset::new(rrset)).await
    }

    async fn add_record(
        &mut self,
        rec: Record<
            ParsedName<Bytes>,
            ZoneRecordData<Bytes, ParsedName<Bytes>>,
        >,
    ) -> std::io::Result<()> {
        let end_node = self.get_writable_child_node_for_owner(&rec).await?;
        let mut rrset = Rrset::new(rec.rtype(), rec.ttl());
        let rtype = rec.rtype();
        let data = rec.into_data().flatten_into();
        let writable = self.write.writable.as_ref().unwrap();

        trace!("Adding RR: {:?}", rrset);
        rrset.push_data(data);

        let node = end_node.as_ref().unwrap_or(writable);

        if let Some(existing_rrset) = node.get_rrset(rtype).await? {
            for existing_data in existing_rrset.data() {
                rrset.push_data(existing_data.clone());
            }
        }

        node.update_rrset(SharedRrset::new(rrset)).await
    }
}

//------------ WriteState -----------------------------------------------------

struct WriteState {
    write: Box<dyn WritableZone>,
    writable: Option<Box<dyn WritableZoneNode>>,
}

impl WriteState {
    async fn new(zone: Zone) -> std::io::Result<Self> {
        let write = zone.write().await;
        let writable = Some(write.open(true).await?);
        Ok(Self { write, writable })
    }

    async fn remove_all(&mut self) -> std::io::Result<()> {
        if let Some(writable) = &mut self.writable {
            writable.remove_all().await?;
        }

        Ok(())
    }

    async fn commit(&mut self) -> std::io::Result<Option<ZoneDiff>> {
        // Commit the deletes and adds that just occurred
        if let Some(writable) = self.writable.take() {
            // Ensure that there are no dangling references to the created
            // diff (otherwise commit() will panic).
            drop(writable);
            self.write.commit(false).await
        } else {
            Ok(None)
        }
    }

    async fn reopen(&mut self) -> std::io::Result<()> {
        self.writable = Some(self.write.open(true).await?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

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
    use crate::rdata::{Soa, A};
    use crate::zonetree::ZoneBuilder;

    use super::*;

    #[tokio::test]
    async fn simple_test() {
        init_logging();

        let zone = mk_empty_zone("example.com");

        let mut updater = ZoneUpdater::new(zone.clone()).await.unwrap();

        let s = Serial::now();
        let soa = mk_soa(s);
        let soa = ZoneRecordData::Soa(soa);
        let soa = Record::new(
            ParsedName::from(Name::from_str("example.com").unwrap()),
            Class::IN,
            Ttl::from_secs(0),
            soa,
        );

        updater
            .apply(ZoneUpdate::AddRecord(soa.clone()))
            .await
            .unwrap();

        updater.apply(ZoneUpdate::Finished(soa)).await.unwrap();
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
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::LOCALHOST));
        add_answer_record(&req, &mut answer, A::new(Ipv4Addr::BROADCAST));
        add_answer_record(&req, &mut answer, soa);
        let resp = answer.into_message();

        // Process the response.
        let it = interpreter.interpret_response(resp).unwrap();

        for update in it {
            let update = update.unwrap();
            updater.apply(update).await.unwrap();
        }

        dbg!(zone);
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
