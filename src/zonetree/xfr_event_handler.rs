//! Support for applying XFR changes to a [`Zone`].
use crate::net::client::xfr::{Error, XfrEvent, XfrEventHandler, XfrRecord};

use super::error::OutOfZone;
use super::{WritableZone, WritableZoneNode, Zone};
use crate::base::name::{FlattenInto, Label, ToLabelIter};
use crate::base::{Name, Record, Rtype, ToName};
use crate::rdata::ZoneRecordData;
use crate::zonetree::{Rrset, SharedRrset};
use bytes::Bytes;
use std::borrow::ToOwned;
use std::boxed::Box;
use tracing::{error, trace};

struct ZoneUpdateEventHandler {
    zone: Zone,

    write: WriteState,

    batching: bool,

    first_event_seen: bool,
}

impl ZoneUpdateEventHandler {
    async fn new(zone: Zone) -> std::io::Result<Self> {
        let write = WriteState::new(&zone).await?;

        Ok(Self {
            zone,
            write,
            batching: false,
            first_event_seen: false,
        })
    }

    async fn init_batch(&mut self) -> Result<(), Error> {
        if self.batching {
            self.write = WriteState::new(&self.zone)
                .await
                .map_err(|_| Error::EventHandlerError)?;
        }

        Ok(())
    }

    fn mk_relative_name_iterator<'l>(
        apex_name: &Name<Bytes>,
        qname: &'l impl ToName,
    ) -> Result<impl Iterator<Item = &'l Label> + Clone, OutOfZone> {
        let mut qname = qname.iter_labels().rev();
        for apex_label in apex_name.iter_labels().rev() {
            let qname_label = qname.next();
            if Some(apex_label) != qname_label {
                error!(
                    "Qname '{qname_label:?}' is not in zone '{apex_name}'"
                );
                return Err(OutOfZone);
            }
        }
        Ok(qname)
    }

    async fn prep_add_del(
        &mut self,
        rec: XfrRecord,
    ) -> Result<
        (
            Rtype,
            ZoneRecordData<Bytes, Name<Bytes>>,
            Option<Box<dyn WritableZoneNode>>,
            Rrset,
        ),
        Error,
    > {
        let owner = rec.owner().to_owned();
        let ttl = rec.ttl();
        let rtype = rec.rtype();
        let data: ZoneRecordData<Bytes, Name<Bytes>> =
            rec.into_data().flatten_into();

        let mut end_node: Option<Box<dyn WritableZoneNode>> = None;

        let name =
            Self::mk_relative_name_iterator(self.zone.apex_name(), &owner)
                .map_err(|_| Error::EventHandlerError)?;

        let writable = self.write.writable.as_ref().unwrap();

        for label in name {
            trace!("Relativised label: {label}");
            end_node = Some(
                match end_node {
                    Some(new_node) => new_node.update_child(label),
                    None => writable.update_child(label),
                }
                .await
                .map_err(|_| Error::EventHandlerError)?,
            );
        }

        let rrset = Rrset::new(rtype, ttl);
        Ok((rtype, data, end_node, rrset))
    }
}

impl XfrEventHandler for ZoneUpdateEventHandler {
    async fn handle_event(
        &mut self,
        evt: XfrEvent<XfrRecord>,
    ) -> Result<(), Error> {
        match evt {
            XfrEvent::DeleteRecord(_serial, rec) => {
                let (rtype, data, end_node, mut rrset) =
                    self.prep_add_del(rec).await?;

                let writable = self.write.writable.as_ref().unwrap();

                trace!("Deleting RR for {rtype}");

                match end_node {
                    Some(n) => {
                        trace!("Deleting RR at end_node");

                        if let Some(existing_rrset) = n
                            .get_rrset(rtype)
                            .await
                            .map_err(|_| Error::EventHandlerError)?
                        {
                            for existing_data in existing_rrset.data() {
                                if existing_data != &data {
                                    rrset.push_data(existing_data.clone());
                                }
                            }

                            trace!("Removing single RR of {rtype} so updating RRSET");
                            n.update_rrset(SharedRrset::new(rrset))
                                .await
                                .map_err(|_| Error::EventHandlerError)?;
                        }
                    }
                    None => {
                        trace!("Deleting RR at root");
                        if let Some(existing_rrset) = writable
                            .get_rrset(rtype)
                            .await
                            .map_err(|_| Error::EventHandlerError)?
                        {
                            for existing_data in existing_rrset.data() {
                                if existing_data != &data {
                                    rrset.push_data(existing_data.clone());
                                }
                            }

                            trace!("Removing single RR of {rtype} so updating RRSET");
                            writable
                                .update_rrset(SharedRrset::new(rrset))
                                .await
                                .map_err(|_| Error::EventHandlerError)?;
                        }
                    }
                }
            }

            XfrEvent::AddRecord(_serial, rec) => {
                self.init_batch().await?;

                if !self.first_event_seen && rec.rtype() == Rtype::SOA {
                    // If the first event is the addition of a SOA record to
                    // the zone, this must be a complete replacement of the
                    // zone (as you can't have two SOA records), i.e.
                    // something like an AXFR transfer. We can't add records
                    // from a new version of the zone to an existing zone
                    // because if the old version contained a record which the
                    // new version does not, it would get left behind. So in
                    // this case we have to mark all of the existing records
                    // in the zone as "removed" and then add new records. This
                    // allows the old records to continue being served to
                    // current consumers while the zone is being updated.
                    self.write
                        .remove_all()
                        .await
                        .map_err(|_| Error::EventHandlerError)?;
                }

                let (rtype, data, end_node, mut rrset) =
                    self.prep_add_del(rec).await?;

                let writable = self.write.writable.as_ref().unwrap();

                trace!("Adding RR: {:?}", rrset);
                rrset.push_data(data);

                match end_node {
                    Some(n) => {
                        trace!("Adding RR at end_node");

                        if let Some(existing_rrset) = n
                            .get_rrset(rtype)
                            .await
                            .map_err(|_| Error::EventHandlerError)?
                        {
                            for existing_data in existing_rrset.data() {
                                rrset.push_data(existing_data.clone());
                            }
                        }

                        n.update_rrset(SharedRrset::new(rrset))
                            .await
                            .map_err(|_| Error::EventHandlerError)?;
                    }
                    None => {
                        trace!("Adding RR at root");
                        writable
                            .update_rrset(SharedRrset::new(rrset))
                            .await
                            .map_err(|_| Error::EventHandlerError)?;
                    }
                }
            }

            XfrEvent::BeginBatchDelete(_) => {
                if self.batching {
                    // Commit the previous batch.
                    self.write.commit().await?;
                }

                self.batching = true;
            }

            XfrEvent::BeginBatchAdd(_) => {
                self.batching = true;
            }

            XfrEvent::EndOfTransfer => {
                // Commit the previous batch.
                self.write.commit().await?;
            }

            XfrEvent::ProcessingFailed => {
                // ???
            }
        }

        self.first_event_seen = true;

        Ok(())
    }
}

//------------ WriteState -----------------------------------------------------

struct WriteState {
    write: Box<dyn WritableZone>,
    writable: Option<Box<dyn WritableZoneNode>>,
}

impl WriteState {
    async fn new(zone: &Zone) -> std::io::Result<Self> {
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

    async fn commit(&mut self) -> Result<(), Error> {
        // Commit the deletes and adds that just occurred
        if let Some(writable) = self.writable.take() {
            // Ensure that there are no dangling references to the created
            // diff (otherwise commit() will panic).
            drop(writable);
            self.write
                .commit(false)
                .await
                .map_err(|_| Error::EventHandlerError)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use crate::base::iana::Class;
    use crate::zonetree::ZoneBuilder;

    use super::*;
    use crate::base::{ParsedName, Serial, Ttl};
    use crate::rdata::Soa;

    #[tokio::test]
    async fn simple_test() {
        init_logging();

        let zone = mk_empty_zone("example.com");

        let mut evt_handler =
            ZoneUpdateEventHandler::new(zone.clone()).await.unwrap();

        let s = Serial::now();
        let soa = mk_soa(s);
        let soa = ZoneRecordData::Soa(soa);
        let soa = Record::new(
            ParsedName::from(Name::from_str("example.com").unwrap()),
            Class::IN,
            Ttl::from_secs(0),
            soa,
        );

        evt_handler
            .handle_event(XfrEvent::AddRecord(s, soa))
            .await
            .unwrap();

        evt_handler
            .handle_event(XfrEvent::EndOfTransfer)
            .await
            .unwrap();
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
}
