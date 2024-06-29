//! TODO
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use std::borrow::ToOwned;
use std::boxed::Box;
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use tokio::time::Instant;
use tracing::{debug, error, info, trace, warn};

use crate::base::name::{FlattenInto, Label, ToLabelIter};
use crate::base::{Message, Name, Rtype, ToName};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};
use crate::rdata::ZoneRecordData;
use crate::zonetree::error::OutOfZone;
use crate::zonetree::{Rrset, SharedRrset, WritableZoneNode, Zone};

//------------ Connection -----------------------------------------------------

#[derive(Clone)]
/// TODO
pub struct Connection<Upstream> {
    /// Upstream transport to use for requests.
    upstream: Arc<Upstream>,

    /// The zone to update.
    zone: Zone,
}

impl<Upstream> Connection<Upstream> {
    /// TODO
    pub fn new(zone: Zone, upstream: Upstream) -> Self {
        Self {
            upstream: Arc::new(upstream),
            zone,
        }
    }
}

//------------ SendRequest ----------------------------------------------------

impl<CR, Upstream> SendRequest<CR> for Connection<Upstream>
where
    CR: ComposeRequest + 'static,
    Upstream: SendRequest<CR> + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(Request::<CR, Upstream>::new(
            request_msg,
            self.zone.clone(),
            self.upstream.clone(),
        ))
    }
}

//------------ Request --------------------------------------------------------

/// The state of a request that is executed.
pub struct Request<CR, Upstream>
where
    CR: ComposeRequest,
    Upstream: SendRequest<CR>,
{
    /// The request message.
    request_msg: Option<CR>,

    /// The upstream transport of the connection.
    upstream: Arc<Upstream>,

    /// The zone to update.
    zone: Zone,
}

impl<CR, Upstream> Request<CR, Upstream>
where
    CR: ComposeRequest,
    Upstream: SendRequest<CR> + Send + Sync,
{
    /// Create a new Request object.
    fn new(request_msg: CR, zone: Zone, upstream: Arc<Upstream>) -> Self {
        Self {
            request_msg: Some(request_msg),
            zone,
            upstream,
        }
    }

    /// This is the implementation of the get_response method.
    ///
    /// This function is cancel safe.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        let req = self.request_msg.take().unwrap();

        let mut xfr_type = None;
        let mut expected_initial_soa_seen_count = None;

        let mut write = self.zone.write().await;
        let mut initial_soa = None;

        let writable =
            write.open(true).await.map_err(|_| Error::ZoneWrite)?;
        let mut send_request = self.upstream.send_request(req);
        let mut i = 0;
        let mut n = 0;
        let mut initial_soa_serial = None;
        let mut initial_soa_serial_seen_count = 0;
        let start_time = Instant::now();
        let mut last_progress_report = start_time;

        // https://datatracker.ietf.org/doc/html/rfc5936#section-6
        // 6.  Zone Integrity "An AXFR client MUST ensure that only a
        //   successfully transferred copy of the zone data can be used to
        //    serve this zone.  Previous description and implementation
        //    practice has introduced a two-stage model of the whole zone
        //    synchronization procedure: Upon a trigger event (e.g., when
        //    polling of a SOA resource record detects a change in the SOA
        //    serial number, or when a DNS NOTIFY request [RFC1996] is
        //    received), the AXFR session is initiated, whereby the zone data
        //    are saved in a zone file or database (this latter step is
        //    necessary anyway to ensure proper restart of the server); upon
        //    successful completion of the AXFR operation and some sanity
        //    checks, this data set is "loaded" and made available for serving
        //    the zone in an atomic operation, and flagged "valid" for use
        //    during the next restart of the DNS server; if any error is
        //    detected, this data set MUST be deleted, and the AXFR client
        //    MUST continue to serve the previous version of the zone, if it
        //    did before.  The externally visible behavior of an AXFR client
        //    implementation MUST be equivalent to that of this two- stage
        //    model."
        //
        // Regarding "whereby the zone data are saved in a zone file or
        // database (this latter step is necessary anyway to ensure proper
        // restart of the server)" and "- this is NOT done here. We only
        // commit changes to memory. It is left for a client to wrap the zone
        // and detect the call to commit() and at that point save the zone if
        // wanted. See `ArchiveZone` in examples/serve-zone.rs for an example.

        // TODO: Add something like the NSD `size-limit-xfr` option that
        // "specifies XFR temporary file size limit" which "can be used to
        // stop very large zone retrieval, that could otherwise use up a lot
        // of memory and disk space".
        let mut msg;
        'outer: loop {
            msg = send_request.get_response().await?;
            trace!("Received response {i}");
            i += 1;

            if msg.no_error() {
                if expected_initial_soa_seen_count.is_none() {
                    xfr_type = Some(msg.first_question().unwrap().qtype());
                    expected_initial_soa_seen_count = match xfr_type.unwrap()
                    {
                        Rtype::AXFR => Some(2),
                        Rtype::IXFR => Some(3),
                        _ => return Ok(msg),
                    };
                }

                match msg.answer() {
                    Ok(answer) => {
                        let records =
                            answer.limit_to::<ZoneRecordData<_, _>>();
                        for record in records.flatten() {
                            trace!("XFR record {n}: {record:?}");

                            if xfr_type == Some(Rtype::IXFR)
                                && n == 1
                                && initial_soa_serial_seen_count == 1
                                && record.rtype() != Rtype::SOA
                            {
                                // https://datatracker.ietf.org/doc/html/rfc1995#section-4
                                // 4. Response Format
                                //   "If incremental zone transfer is not available, the entire zone is
                                //    returned.  The first and the last RR of the response is the SOA
                                //    record of the zone.  I.e. the behavior is the same as an AXFR
                                //    response except the query type is IXFR."
                                debug!("IXFR response appears to be AXFR, switching...");
                                xfr_type = Some(Rtype::AXFR);
                                expected_initial_soa_seen_count = Some(2);
                            }

                            let owner = record.owner().to_owned();
                            let ttl = record.ttl();
                            let rtype = record.rtype();
                            let data = record.into_data().flatten_into();

                            if let ZoneRecordData::Soa(soa) = &data {
                                if let Some(initial_soa_serial) =
                                    initial_soa_serial
                                {
                                    if initial_soa_serial == soa.serial() {
                                        // AXFR end SOA detected.
                                        // Notify transport that no
                                        // more responses are
                                        // expected.
                                        initial_soa_serial_seen_count += 1;
                                        if Some(initial_soa_serial_seen_count)
                                            == expected_initial_soa_seen_count
                                        {
                                            trace!("Closing response stream at record nr {i} (soa seen count = {initial_soa_serial_seen_count})");
                                            send_request.stream_complete()?;
                                            break 'outer;
                                        }
                                    }
                                } else {
                                    initial_soa_serial = Some(soa.serial());
                                    initial_soa = Some(soa.clone());
                                    initial_soa_serial_seen_count = 1;
                                }
                            }

                            n += 1;

                            let now = Instant::now();
                            if now
                                .duration_since(last_progress_report)
                                .as_secs()
                                > 10
                            {
                                let seconds_so_far =
                                    now.duration_since(start_time).as_secs()
                                        as f64;
                                let records_per_second =
                                    ((n as f64) / seconds_so_far).floor()
                                        as i64;
                                info!("XFR progress report for zone '{}': Received {n} records in {i} responses in {} seconds ({} records/second)", self.zone.apex_name(), seconds_so_far, records_per_second);
                                last_progress_report = now;
                            }

                            let mut end_node: Option<
                                Box<dyn WritableZoneNode>,
                            > = None;

                            let name = Self::mk_relative_name_iterator(
                                self.zone.apex_name(),
                                &owner,
                            )
                            .map_err(|_| Error::MessageParseError)?;

                            for label in name {
                                trace!("Relativised label: {label}");
                                end_node = Some(
                                    match end_node {
                                        Some(new_node) => {
                                            new_node.update_child(label)
                                        }
                                        None => writable.update_child(label),
                                    }
                                    .await
                                    .map_err(|_| Error::ZoneWrite)?,
                                );
                            }

                            let mut rrset = Rrset::new(rtype, ttl);
                            rrset.push_data(data);

                            trace!("Adding RRset: {rrset:?}");
                            let rrset = SharedRrset::new(rrset);
                            match end_node {
                                Some(n) => {
                                    trace!("Adding RRset at end_node");
                                    n.update_rrset(rrset)
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?;
                                }
                                None => {
                                    trace!("Adding RRset at root");
                                    writable
                                        .update_rrset(rrset)
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?;
                                }
                            }
                        }
                    }

                    Err(err) => {
                        error!("Error while parsing XFR ANSWER: {err}");
                        return Err(Error::MessageParseError);
                    }
                }
            } else {
                return Err(Error::MessageParseError);
            }
        }

        info!("XFR progress report for zone '{}': Transfer complete, commiting changes.", self.zone.apex_name());

        // Ensure that there are no dangling references to the created diff
        // (otherwise commit() will panic).
        drop(writable);

        // TODO
        write.commit(false).await.map_err(|_| Error::ZoneWrite)?;

        let new_serial = initial_soa.as_ref().unwrap().serial();

        info!(
            "Zone '{}' has been updated to serial {} by {}",
            self.zone.apex_name(),
            new_serial,
            xfr_type.unwrap(),
        );

        Ok(msg)
    }

    /// TODO
    fn mk_relative_name_iterator<'l>(
        apex_name: &Name<Bytes>,
        qname: &'l impl ToName,
    ) -> Result<impl Iterator<Item = &'l Label> + Clone, OutOfZone> {
        let mut qname = qname.iter_labels().rev();
        for apex_label in apex_name.iter_labels().rev() {
            let qname_label = qname.next();
            if Some(apex_label) != qname_label {
                error!("Qname is not in zone '{apex_name}'");
                return Err(OutOfZone);
            }
        }
        Ok(qname)
    }
}

impl<CR, Upstream> Debug for Request<CR, Upstream>
where
    CR: ComposeRequest,
    Upstream: SendRequest<CR>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Request")
            .field("fut", &format_args!("_"))
            .finish()
    }
}

impl<CR, Upstream> GetResponse for Request<CR, Upstream>
where
    CR: ComposeRequest,
    Upstream: SendRequest<CR> + Send + Sync,
{
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Message<Bytes>, Error>>
                + Send
                + Sync
                + '_,
        >,
    > {
        Box::pin(self.get_response_impl())
    }
}
