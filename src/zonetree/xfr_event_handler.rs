//! Support for applying XFR changes to a [`Zone`].
use std::borrow::ToOwned;
use std::boxed::Box;

use bytes::Bytes;
use tracing::{error, trace};

use super::error::OutOfZone;
use super::{WritableZone, WritableZoneNode, Zone};
use crate::base::name::{FlattenInto, Label, ToLabelIter};
use crate::base::{Name, ParsedName, Record, Rtype, ToName};
use crate::net::xfr::processing::{XfrEvent, XfrRecord};
use crate::rdata::ZoneRecordData;
use crate::zonetree::{Rrset, SharedRrset};

/// TODO
pub struct ZoneUpdateEventHandler {
    zone: Zone,

    write: WriteState,

    batching: bool,

    first_event_seen: bool,
}

impl ZoneUpdateEventHandler {
    /// TODO
    pub async fn new(zone: Zone) -> std::io::Result<Self> {
        let write = WriteState::new(&zone).await?;

        Ok(Self {
            zone,
            write,
            batching: false,
            first_event_seen: false,
        })
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
        (),
    > {
        let owner = rec.owner().to_owned();
        let ttl = rec.ttl();
        let rtype = rec.rtype();
        let data: ZoneRecordData<Bytes, Name<Bytes>> =
            rec.into_data().flatten_into();

        let mut end_node: Option<Box<dyn WritableZoneNode>> = None;

        let name =
            Self::mk_relative_name_iterator(self.zone.apex_name(), &owner)
                .map_err(|_| ())?;

        let writable = self.write.writable.as_ref().unwrap();

        for label in name {
            trace!("Relativised label: {label}");
            end_node = Some(
                match end_node {
                    Some(new_node) => new_node.update_child(label),
                    None => writable.update_child(label),
                }
                .await
                .map_err(|_| ())?,
            );
        }

        let rrset = Rrset::new(rtype, ttl);
        Ok((rtype, data, end_node, rrset))
    }

    /// TODO
    pub async fn handle_event(
        &mut self,
        evt: XfrEvent<XfrRecord>,
    ) -> Result<(), ()> {
        trace!("Event: {evt}");
        match evt {
            XfrEvent::DeleteRecord(_serial, rec) => {
                self.delete_record(rec).await?
            }

            XfrEvent::AddRecord(_serial, rec) => self.add_record(rec).await?,

            // Note: Batches first contain deletions then additions, so batch
            // deletion signals the start of a batch, and the end of any
            // previous batch addition.
            XfrEvent::BeginBatchDelete(_old_soa) => {
                if self.batching {
                    // Commit the previous batch.
                    self.write.commit().await?;
                    // Open a writer for the new batch.
                    self.write.reopen().await.map_err(|_| ())?;
                }

                self.batching = true;
            }

            XfrEvent::BeginBatchAdd(new_soa) => {
                // Update the SOA record.
                self.update_soa(new_soa).await?;
                self.batching = true;
            }

            XfrEvent::EndOfTransfer(zone_soa) => {
                if !self.batching {
                    // Update the SOA record.
                    self.update_soa(zone_soa).await?;
                }
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

    async fn update_soa(
        &mut self,
        new_soa: Record<
            ParsedName<Bytes>,
            ZoneRecordData<Bytes, ParsedName<Bytes>>,
        >,
    ) -> Result<(), ()> {
        if new_soa.rtype() != Rtype::SOA {
            return Err(());
        }

        let mut rrset = Rrset::new(Rtype::SOA, new_soa.ttl());
        rrset.push_data(new_soa.data().to_owned().flatten_into());
        self.write
            .writable
            .as_ref()
            .unwrap()
            .update_rrset(SharedRrset::new(rrset))
            .await
            .map_err(|_| ())?;
        Ok(())
    }

    async fn delete_record(
        &mut self,
        rec: Record<
            ParsedName<Bytes>,
            ZoneRecordData<Bytes, ParsedName<Bytes>>,
        >,
    ) -> Result<(), ()> {
        let (rtype, data, end_node, mut rrset) =
            self.prep_add_del(rec).await?;

        let writable = self.write.writable.as_ref().unwrap();

        trace!("Deleting RR for {rtype}");

        let node = end_node.as_ref().unwrap_or(writable);

        if let Some(existing_rrset) =
            node.get_rrset(rtype).await.map_err(|_| ())?
        {
            for existing_data in existing_rrset.data() {
                if existing_data != &data {
                    rrset.push_data(existing_data.clone());
                }
            }
        }

        trace!("Removing single RR of {rtype} so updating RRSET");

        node.update_rrset(SharedRrset::new(rrset))
            .await
            .map_err(|_| ())?;

        Ok(())
    }

    async fn add_record(
        &mut self,
        rec: Record<
            ParsedName<Bytes>,
            ZoneRecordData<Bytes, ParsedName<Bytes>>,
        >,
    ) -> Result<(), ()> {
        if !self.first_event_seen && rec.rtype() == Rtype::SOA {
            // If the first event is the addition of a SOA record to the zone,
            // this must be a complete replacement of the zone (as you can't
            // have two SOA records), i.e. something like an AXFR transfer. We
            // can't add records from a new version of the zone to an existing
            // zone because if the old version contained a record which the
            // new version does not, it would get left behind. So in this case
            // we have to mark all of the existing records in the zone as
            // "removed" and then add new records. This allows the old records
            // to continue being served to current consumers while the zone is
            // being updated.
            self.write.remove_all().await.map_err(|_| ())?;
        }

        let (rtype, data, end_node, mut rrset) =
            self.prep_add_del(rec).await?;

        let writable = self.write.writable.as_ref().unwrap();

        trace!("Adding RR: {:?}", rrset);
        rrset.push_data(data);

        let node = end_node.as_ref().unwrap_or(writable);

        if let Some(existing_rrset) =
            node.get_rrset(rtype).await.map_err(|_| ())?
        {
            for existing_data in existing_rrset.data() {
                rrset.push_data(existing_data.clone());
            }
        }

        node.update_rrset(SharedRrset::new(rrset))
            .await
            .map_err(|_| ())?;

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

    async fn commit(&mut self) -> Result<(), ()> {
        // Commit the deletes and adds that just occurred
        if let Some(writable) = self.writable.take() {
            // Ensure that there are no dangling references to the created
            // diff (otherwise commit() will panic).
            drop(writable);
            self.write.commit(false).await.map_err(|_| ())?;
        }

        Ok(())
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
        Message, MessageBuilder, ParsedName, Record, Serial, Ttl,
    };
    use crate::net::xfr::processing::XfrResponseProcessor;
    use crate::rdata::{Soa, A};
    use crate::zonetree::ZoneBuilder;

    use super::*;

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
            .handle_event(XfrEvent::AddRecord(s, soa.clone()))
            .await
            .unwrap();

        evt_handler
            .handle_event(XfrEvent::EndOfTransfer(soa))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn axfr_response_generates_expected_events() {
        init_logging();

        let zone = mk_empty_zone("example.com");

        let mut evt_handler =
            ZoneUpdateEventHandler::new(zone.clone()).await.unwrap();

        // Create an AXFR request to reply to.
        let req = mk_request("example.com", Rtype::AXFR).into_message();

        // Create an XFR response processor.
        let mut processor = XfrResponseProcessor::new();

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
        let it = processor.process_answer(resp).unwrap();

        for evt in it {
            let evt = evt.unwrap();
            evt_handler.handle_event(evt).await.unwrap();
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