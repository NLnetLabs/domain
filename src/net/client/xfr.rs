//! TODO
#![cfg(feature = "unstable-client-transport")]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use std::borrow::ToOwned;
use std::boxed::Box;
use std::fmt::{Debug, Formatter};
use std::future::ready;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bytes::Bytes;
use tokio::time::Instant;
use tracing::{debug, error, info, trace, warn};

use crate::base::name::FlattenInto;
#[cfg(feature = "unstable-zonetree")]
use crate::base::name::{Label, ToLabelIter};
#[cfg(feature = "unstable-zonetree")]
use crate::base::ToName;
use crate::base::{Message, Name, ParsedName, Rtype, Serial};
use crate::net::client::request::{
    ComposeRequest, ComposeRequestMulti, Error, GetResponse,
    GetResponseMulti, SendRequest, SendRequestMulti,
};
use crate::rdata::{Soa, ZoneRecordData};

#[cfg(feature = "unstable-zonetree")]
use crate::zonetree::error::OutOfZone;
#[cfg(feature = "unstable-zonetree")]
use crate::zonetree::{
    Rrset, SharedRrset, WritableZone, WritableZoneNode, Zone,
};

//------------ Connection -----------------------------------------------------

#[derive(Clone)]
/// TODO
pub struct Connection<Upstream> {
    /// Upstream transport to use for requests.
    upstream: Arc<Upstream>,

    /// The zone to update.
    #[cfg(feature = "unstable-zonetree")]
    zone: Option<Zone>,
}

impl<Upstream> Connection<Upstream> {
    /// TODO

    pub fn new(
        #[cfg(feature = "unstable-zonetree")] zone: Option<Zone>,
        upstream: Upstream,
    ) -> Self {
        Self {
            upstream: Arc::new(upstream),
            #[cfg(feature = "unstable-zonetree")]
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
            #[cfg(feature = "unstable-zonetree")]
            self.zone.clone(),
            self.upstream.clone(),
        ))
    }
}

//------------ SendRequestMulti -----------------------------------------------

/*
impl<CR, Upstream> SendRequestMulti<CR> for Connection<Upstream>
where
    CR: ComposeRequestMulti + 'static,
    Upstream: SendRequestMulti<CR> + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn GetResponseMulti + Send + Sync> {
        Box::new(RequestMulti::<CR, Upstream>::new(
            request_msg,
            #[cfg(feature = "unstable-zonetree")]
            self.zone.clone(),
            self.upstream.clone(),
        ))
    }
}
*/

impl<CR, Upstream> SendRequestMulti<CR> for Connection<Upstream>
where
    CR: ComposeRequestMulti + 'static,
    Upstream: SendRequestMulti<CR> + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: CR,
    ) -> Box<dyn GetResponseMulti + Send + Sync> {
        Box::new(RequestMulti::<CR, Upstream>::new(
            request_msg,
            #[cfg(feature = "unstable-zonetree")]
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

    /// TODO
    send_request: Option<Box<dyn GetResponse + Send + Sync>>,

    /// The upstream transport of the connection.
    upstream: Arc<Upstream>,

    /// The zone to update.
    #[cfg(feature = "unstable-zonetree")]
    zone: Option<Zone>,

    /// TODO
    #[cfg(feature = "unstable-zonetree")]
    write: Option<Box<dyn WritableZone>>,

    /// TODO
    #[cfg(feature = "unstable-zonetree")]
    writable: Option<Box<dyn WritableZoneNode>>,

    /// TODO
    xfr_type: Option<Rtype>,

    /// TODO
    i: usize,

    /// TODO:
    n: usize,

    /// TODO
    expected_initial_soa_seen_count: Option<u8>,

    /// TODO
    initial_soa: Option<Soa<Name<Bytes>>>,

    /// TODO
    initial_soa_owner: Option<ParsedName<Bytes>>,

    /// TODO
    initial_soa_serial: Option<Serial>,

    /// TODO
    initial_soa_serial_seen_count: u8,

    /// TODO
    start_time: Instant,

    /// TODO
    last_progress_report: Option<Instant>,
}

impl<CR, Upstream> Request<CR, Upstream>
where
    CR: ComposeRequest,
    Upstream: SendRequest<CR> + Send + Sync,
{
    /// Create a new Request object.
    fn new(
        request_msg: CR,
        #[cfg(feature = "unstable-zonetree")] zone: Option<Zone>,
        upstream: Arc<Upstream>,
    ) -> Self {
        Self {
            request_msg: Some(request_msg),
            send_request: None,
            #[cfg(feature = "unstable-zonetree")]
            zone,
            #[cfg(feature = "unstable-zonetree")]
            write: None,
            #[cfg(feature = "unstable-zonetree")]
            writable: None,
            upstream,
            xfr_type: None,
            i: 0,
            n: 0,
            expected_initial_soa_seen_count: None,
            initial_soa: None,
            initial_soa_owner: None,
            initial_soa_serial: None,
            initial_soa_serial_seen_count: 0,
            start_time: Instant::now(),
            last_progress_report: None,
        }
    }

    /// This is the implementation of the get_response method.
    ///
    /// This function is cancel safe.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        // The first time we are called, send the request and receive back an
        // object which can be used to fetch responses. Then use that in both
        // the first and subsequent invocations to do response fetching.
        let send_request = match &mut self.send_request {
            None => {
                let req = self.request_msg.take().unwrap();
                self.send_request = Some(self.upstream.send_request(req));
                self.send_request.as_mut().unwrap()
            }
            Some(send_request) => send_request,
        };

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
        let msg = send_request.get_response().await?;

        let not_xfr = msg
            .sole_question()
            .map(|q| q.qtype() != Rtype::AXFR && q.qtype() != Rtype::IXFR);
        if matches!(not_xfr, Ok(true)) {
            return Ok(msg);
        }

        if msg.is_error() {
            return Ok(msg);
        }

        trace!("Received response {}", self.i);
        self.i += 1;

        if self.expected_initial_soa_seen_count.is_none() {
            self.xfr_type = Some(msg.first_question().unwrap().qtype());
            self.expected_initial_soa_seen_count =
                match self.xfr_type.unwrap() {
                    Rtype::AXFR => Some(2),
                    Rtype::IXFR => Some(3),
                    _ => unreachable!(),
                };
        }

        #[cfg(feature = "unstable-zonetree")]
        let mut ixfr_update_mode = IxfrUpdateMode::Deleting;

        /// TODO
        #[cfg(feature = "unstable-zonetree")]
        async fn commit(
            writable: Option<Box<dyn WritableZoneNode>>,
            write: Option<Box<dyn WritableZone>>,
        ) -> Result<bool, Error> {
            // Commit the deletes and adds that just occurred
            if let Some(writable) = writable {
                // Ensure that there are no dangling references to the created
                // diff (otherwise commit() will panic).
                drop(writable);

                if let Some(mut write) = write {
                    write
                        .commit(false)
                        .await
                        .map_err(|_| Error::ZoneWrite)?;

                    return Ok(true);
                }
            }

            Ok(false)
        }

        match msg.answer() {
            Ok(answer) => {
                let records = answer.limit_to::<ZoneRecordData<_, _>>();
                for record in records.flatten() {
                    trace!("XFR record {}: {record:?}", self.n);

                    // With IXFR we expect both the first and second records to be SOA records.
                    // With AXFR only a single SOA record is expected.
                    if self.xfr_type == Some(Rtype::IXFR)
                        && self.n == 1
                        && self.initial_soa_serial_seen_count == 1
                        && record.rtype() != Rtype::SOA
                    {
                        // https://datatracker.ietf.org/doc/html/rfc1995#section-4
                        // 4. Response Format
                        //   "If incremental zone transfer is not available, the entire zone is
                        //    returned.  The first and the last RR of the response is the SOA
                        //    record of the zone.  I.e. the behavior is the same as an AXFR
                        //    response except the query type is IXFR."
                        debug!(
                            "IXFR response appears to be AXFR, switching..."
                        );
                        self.xfr_type = Some(Rtype::AXFR);
                        self.expected_initial_soa_seen_count = Some(2);
                    }

                    let owner = record.owner().to_owned();
                    #[cfg(feature = "unstable-zonetree")]
                    let ttl = record.ttl();
                    #[cfg(feature = "unstable-zonetree")]
                    let rtype = record.rtype();
                    let data: ZoneRecordData<Bytes, Name<Bytes>> =
                        record.into_data().flatten_into();

                    if let ZoneRecordData::Soa(soa) = &data {
                        #[cfg(feature = "unstable-zonetree")]
                        if self.xfr_type == Some(Rtype::IXFR) && self.n > 1 {
                            match ixfr_update_mode {
                                IxfrUpdateMode::Deleting => {
                                    trace!("IXFR: Switching to adding mode");
                                    ixfr_update_mode = IxfrUpdateMode::Adding;
                                }
                                IxfrUpdateMode::Adding => {
                                    trace!(
                                        "IXFR: Switching to deleting mode"
                                    );
                                    ixfr_update_mode =
                                        IxfrUpdateMode::Deleting;

                                    if let Some(zone) = &self.zone {
                                        if commit(
                                            self.writable.take(),
                                            self.write.take(),
                                        )
                                        .await?
                                        {
                                            let new_serial = self
                                                .initial_soa
                                                .as_ref()
                                                .unwrap()
                                                .serial();

                                            info!(
                                                    "Zone '{}' has been updated to serial {} by {}",
                                                    zone.apex_name(),
                                                    new_serial,
                                                    self.xfr_type.unwrap(),
                                                );
                                        }
                                    }
                                }
                            }
                        }

                        if let Some(initial_soa_serial) =
                            self.initial_soa_serial
                        {
                            if initial_soa_serial == soa.serial() {
                                // AXFR end SOA detected.
                                // Notify transport that no
                                // more responses are
                                // expected.
                                self.initial_soa_serial_seen_count += 1;
                                if Some(self.initial_soa_serial_seen_count)
                                    == self.expected_initial_soa_seen_count
                                {
                                    trace!("Closing response stream at record nr {} (soa seen count = {})",
                                        self.i, self.initial_soa_serial_seen_count);
                                    #[cfg(feature = "unstable-zonetree")]
                                    if let Some(zone) = &self.zone {
                                        info!("{} progress report for zone '{}': Transfer complete, commiting changes.", self.xfr_type.unwrap(), zone.apex_name());
                                        if commit(
                                            self.writable.take(),
                                            self.write.take(),
                                        )
                                        .await?
                                        {
                                            let new_serial = self
                                                .initial_soa
                                                .as_ref()
                                                .unwrap()
                                                .serial();

                                            info!(
                                                    "Zone '{}' has been updated to serial {} by {}",
                                                    zone.apex_name(),
                                                    new_serial,
                                                    self.xfr_type.unwrap(),
                                                );
                                        }
                                    } else {
                                        info!(
                                            "{} progress report for zone '{}': Transfer complete.",
                                            self.xfr_type.unwrap(), self.initial_soa_owner.as_ref().unwrap()
                                        );
                                    }
                                    break;
                                }
                            }
                        } else {
                            self.initial_soa_serial = Some(soa.serial());
                            self.initial_soa = Some(soa.clone());
                            self.initial_soa_serial_seen_count = 1;
                            self.initial_soa_owner = Some(owner.clone());
                        }
                    }

                    self.n += 1;

                    let now = Instant::now();
                    if now
                        .duration_since(
                            self.last_progress_report
                                .unwrap_or(self.start_time),
                        )
                        .as_secs()
                        > 10
                    {
                        let seconds_so_far =
                            now.duration_since(self.start_time).as_secs()
                                as f64;
                        let records_per_second =
                            ((self.n as f64) / seconds_so_far).floor() as i64;

                        info!("XFR progress report for zone '{}': Received {} records in {} responses in {} seconds ({} records/second)",
                            self.initial_soa_owner.as_ref().unwrap(),
                            self.n,
                            self.i,
                            seconds_so_far,
                            records_per_second);
                        self.last_progress_report = Some(now);
                    }

                    #[cfg(feature = "unstable-zonetree")]
                    let Some(zone) = &self.zone
                    else {
                        continue;
                    };

                    #[cfg(feature = "unstable-zonetree")]
                    {
                        let writable = match &self.writable {
                            Some(writable) => writable,
                            None => {
                                let new_write = zone.write().await;
                                self.writable = Some(
                                    new_write
                                        .open(true)
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?,
                                );
                                self.write = Some(new_write);
                                self.writable.as_ref().unwrap()
                            }
                        };

                        let mut end_node: Option<Box<dyn WritableZoneNode>> =
                            None;

                        let name = Self::mk_relative_name_iterator(
                            zone.apex_name(),
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

                        if self.xfr_type == Some(Rtype::AXFR)
                            || (self.xfr_type == Some(Rtype::IXFR)
                                && ixfr_update_mode == IxfrUpdateMode::Adding)
                        {
                            let mut rrset = Rrset::new(rtype, ttl);
                            rrset.push_data(data);

                            trace!("Adding RR: {:?}", rrset);

                            match end_node {
                                Some(n) => {
                                    trace!("Adding RR at end_node");

                                    if let Some(existing_rrset) = n
                                        .get_rrset(rtype)
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?
                                    {
                                        for existing_data in
                                            existing_rrset.data()
                                        {
                                            rrset.push_data(
                                                existing_data.clone(),
                                            );
                                        }
                                    }

                                    n.update_rrset(SharedRrset::new(rrset))
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?;
                                }
                                None => {
                                    trace!("Adding RR at root");
                                    writable
                                        .update_rrset(SharedRrset::new(rrset))
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?;
                                }
                            }
                        } else {
                            trace!("Deleting RR for {rtype}");
                            let mut rrset = Rrset::new(rtype, ttl);
                            match end_node {
                                Some(n) => {
                                    trace!("Deleting RR at end_node");

                                    if let Some(existing_rrset) = n
                                        .get_rrset(rtype)
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?
                                    {
                                        for existing_data in
                                            existing_rrset.data()
                                        {
                                            if existing_data != &data {
                                                rrset.push_data(
                                                    existing_data.clone(),
                                                );
                                            }
                                        }

                                        trace!("Removing single RR of {rtype} so updating RRSET");
                                        n.update_rrset(SharedRrset::new(
                                            rrset,
                                        ))
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?;
                                    }
                                }
                                None => {
                                    trace!("Deleting RR at root");
                                    if let Some(existing_rrset) = writable
                                        .get_rrset(rtype)
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?
                                    {
                                        for existing_data in
                                            existing_rrset.data()
                                        {
                                            if existing_data != &data {
                                                rrset.push_data(
                                                    existing_data.clone(),
                                                );
                                            }
                                        }

                                        trace!("Removing single RR of {rtype} so updating RRSET");
                                        writable
                                            .update_rrset(SharedRrset::new(
                                                rrset,
                                            ))
                                            .await
                                            .map_err(|_| Error::ZoneWrite)?;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Err(err) => {
                error!("Error while parsing XFR ANSWER: {err}");
                return Err(Error::MessageParseError);
            }
        }

        Ok(msg)
    }

    /// TODO
    #[cfg(feature = "unstable-zonetree")]
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

//------------ RequestMulti ---------------------------------------------------

/// The state of a request that is executed.
pub struct RequestMulti<CR, Upstream>
where
    CR: ComposeRequestMulti,
    Upstream: SendRequestMulti<CR>,
{
    /// The request message.
    request_msg: Option<CR>,

    /// TODO
    send_request: Option<Box<dyn GetResponseMulti + Send + Sync>>,

    /// The upstream transport of the connection.
    upstream: Arc<Upstream>,

    /// The zone to update.
    #[cfg(feature = "unstable-zonetree")]
    zone: Option<Zone>,

    /// TODO
    #[cfg(feature = "unstable-zonetree")]
    write: Option<Box<dyn WritableZone>>,

    /// TODO
    #[cfg(feature = "unstable-zonetree")]
    writable: Option<Box<dyn WritableZoneNode>>,

    /// TODO
    xfr_type: Option<Rtype>,

    /// TODO
    i: usize,

    /// TODO:
    n: usize,

    /// TODO
    expected_initial_soa_seen_count: Option<u8>,

    /// TODO
    initial_soa: Option<Soa<Name<Bytes>>>,

    /// TODO
    initial_soa_owner: Option<ParsedName<Bytes>>,

    /// TODO
    initial_soa_serial: Option<Serial>,

    /// TODO
    initial_soa_serial_seen_count: u8,

    /// TODO
    start_time: Instant,

    /// TODO
    last_progress_report: Option<Instant>,

    /// TODO
    complete: bool,
}

impl<CR, Upstream> RequestMulti<CR, Upstream>
where
    CR: ComposeRequestMulti,
    Upstream: SendRequestMulti<CR> + Send + Sync,
{
    /// Create a new Request object.
    fn new(
        request_msg: CR,
        #[cfg(feature = "unstable-zonetree")] zone: Option<Zone>,
        upstream: Arc<Upstream>,
    ) -> Self {
        Self {
            request_msg: Some(request_msg),
            send_request: None,
            #[cfg(feature = "unstable-zonetree")]
            zone,
            #[cfg(feature = "unstable-zonetree")]
            write: None,
            #[cfg(feature = "unstable-zonetree")]
            writable: None,
            upstream,
            xfr_type: None,
            i: 0,
            n: 0,
            expected_initial_soa_seen_count: None,
            initial_soa: None,
            initial_soa_owner: None,
            initial_soa_serial: None,
            initial_soa_serial_seen_count: 0,
            start_time: Instant::now(),
            last_progress_report: None,
            complete: false,
        }
    }

    /// This is the implementation of the get_response method.
    ///
    /// This function is cancel safe.
    async fn get_response_impl(
        &mut self,
    ) -> Result<Option<Message<Bytes>>, Error> {
        // The first time we are called, send the request and receive back an
        // object which can be used to fetch responses. Then use that in both
        // the first and subsequent invocations to do response fetching.
        let send_request = match &mut self.send_request {
            None => {
                let req = self.request_msg.take().unwrap();
                self.send_request = Some(self.upstream.send_request(req));
                self.send_request.as_mut().unwrap()
            }
            Some(send_request) => send_request,
        };

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
        let msg = send_request.get_response().await?;
        let msg = match msg {
            Some(msg) => msg,
            None => return Ok(None),
        };

        let not_xfr = msg
            .sole_question()
            .map(|q| q.qtype() != Rtype::AXFR && q.qtype() != Rtype::IXFR);
        if matches!(not_xfr, Ok(true)) {
            return Ok(Some(msg));
        }

        if msg.is_error() {
            return Ok(Some(msg));
        }

        trace!("Received response {}", self.i);
        self.i += 1;

        if self.expected_initial_soa_seen_count.is_none() {
            self.xfr_type = Some(msg.first_question().unwrap().qtype());
            self.expected_initial_soa_seen_count =
                match self.xfr_type.unwrap() {
                    Rtype::AXFR => Some(2),
                    Rtype::IXFR => Some(3),
                    _ => unreachable!(),
                };
        }

        #[cfg(feature = "unstable-zonetree")]
        let mut ixfr_update_mode = IxfrUpdateMode::Deleting;

        /// TODO
        #[cfg(feature = "unstable-zonetree")]
        async fn commit(
            writable: Option<Box<dyn WritableZoneNode>>,
            write: Option<Box<dyn WritableZone>>,
        ) -> Result<bool, Error> {
            // Commit the deletes and adds that just occurred
            if let Some(writable) = writable {
                // Ensure that there are no dangling references to the created
                // diff (otherwise commit() will panic).
                drop(writable);

                if let Some(mut write) = write {
                    write
                        .commit(false)
                        .await
                        .map_err(|_| Error::ZoneWrite)?;

                    return Ok(true);
                }
            }

            Ok(false)
        }

        match msg.answer() {
            Ok(answer) => {
                let records = answer.limit_to::<ZoneRecordData<_, _>>();
                for record in records.flatten() {
                    trace!("XFR record {}: {record:?}", self.n);

                    // With IXFR we expect both the first and second records to be SOA records.
                    // With AXFR only a single SOA record is expected.
                    if self.xfr_type == Some(Rtype::IXFR)
                        && self.n == 1
                        && self.initial_soa_serial_seen_count == 1
                        && record.rtype() != Rtype::SOA
                    {
                        // https://datatracker.ietf.org/doc/html/rfc1995#section-4
                        // 4. Response Format
                        //   "If incremental zone transfer is not available, the entire zone is
                        //    returned.  The first and the last RR of the response is the SOA
                        //    record of the zone.  I.e. the behavior is the same as an AXFR
                        //    response except the query type is IXFR."
                        debug!(
                            "IXFR response appears to be AXFR, switching..."
                        );
                        self.xfr_type = Some(Rtype::AXFR);
                        self.expected_initial_soa_seen_count = Some(2);
                    }

                    let owner = record.owner().to_owned();
                    #[cfg(feature = "unstable-zonetree")]
                    let ttl = record.ttl();
                    #[cfg(feature = "unstable-zonetree")]
                    let rtype = record.rtype();
                    let data: ZoneRecordData<Bytes, Name<Bytes>> =
                        record.into_data().flatten_into();

                    if let ZoneRecordData::Soa(soa) = &data {
                        #[cfg(feature = "unstable-zonetree")]
                        if self.xfr_type == Some(Rtype::IXFR) && self.n > 1 {
                            match ixfr_update_mode {
                                IxfrUpdateMode::Deleting => {
                                    trace!("IXFR: Switching to adding mode");
                                    ixfr_update_mode = IxfrUpdateMode::Adding;
                                }
                                IxfrUpdateMode::Adding => {
                                    trace!(
                                        "IXFR: Switching to deleting mode"
                                    );
                                    ixfr_update_mode =
                                        IxfrUpdateMode::Deleting;

                                    if let Some(zone) = &self.zone {
                                        if commit(
                                            self.writable.take(),
                                            self.write.take(),
                                        )
                                        .await?
                                        {
                                            let new_serial = self
                                                .initial_soa
                                                .as_ref()
                                                .unwrap()
                                                .serial();

                                            info!(
                                                    "Zone '{}' has been updated to serial {} by {}",
                                                    zone.apex_name(),
                                                    new_serial,
                                                    self.xfr_type.unwrap(),
                                                );
                                        }
                                    }
                                }
                            }
                        }

                        if let Some(initial_soa_serial) =
                            self.initial_soa_serial
                        {
                            if initial_soa_serial == soa.serial() {
                                // AXFR end SOA detected.
                                // Notify transport that no
                                // more responses are
                                // expected.
                                self.initial_soa_serial_seen_count += 1;
                                if Some(self.initial_soa_serial_seen_count)
                                    == self.expected_initial_soa_seen_count
                                {
                                    trace!("Closing response stream at record nr {} (soa seen count = {})",
                                        self.i, self.initial_soa_serial_seen_count);
                                    // We need to check that this is the last
                                    // record in the message. We also need to
                                    // check for the end-of-stream indication.
                                    // This gives the TSIG transport a chance
                                    // to verify that the last message was
                                    // properly signed.
                                    println!("TODO check for end-of-stream");
                                    self.complete = true;

                                    #[cfg(feature = "unstable-zonetree")]
                                    if let Some(zone) = &self.zone {
                                        info!("{} progress report for zone '{}': Transfer complete, commiting changes.", self.xfr_type.unwrap(), zone.apex_name());
                                        if commit(
                                            self.writable.take(),
                                            self.write.take(),
                                        )
                                        .await?
                                        {
                                            let new_serial = self
                                                .initial_soa
                                                .as_ref()
                                                .unwrap()
                                                .serial();

                                            info!(
                                                    "Zone '{}' has been updated to serial {} by {}",
                                                    zone.apex_name(),
                                                    new_serial,
                                                    self.xfr_type.unwrap(),
                                                );
                                        }
                                    } else {
                                        info!(
                                            "{} progress report for zone '{}': Transfer complete.",
                                            self.xfr_type.unwrap(), self.initial_soa_owner.as_ref().unwrap()
                                        );
                                    }
                                    break;
                                }
                            }
                        } else {
                            self.initial_soa_serial = Some(soa.serial());
                            self.initial_soa = Some(soa.clone());
                            self.initial_soa_serial_seen_count = 1;
                            self.initial_soa_owner = Some(owner.clone());
                        }
                    }

                    self.n += 1;

                    let now = Instant::now();
                    if now
                        .duration_since(
                            self.last_progress_report
                                .unwrap_or(self.start_time),
                        )
                        .as_secs()
                        > 10
                    {
                        let seconds_so_far =
                            now.duration_since(self.start_time).as_secs()
                                as f64;
                        let records_per_second =
                            ((self.n as f64) / seconds_so_far).floor() as i64;

                        info!("XFR progress report for zone '{}': Received {} records in {} responses in {} seconds ({} records/second)",
                            self.initial_soa_owner.as_ref().unwrap(),
                            self.n,
                            self.i,
                            seconds_so_far,
                            records_per_second);
                        self.last_progress_report = Some(now);
                    }

                    #[cfg(feature = "unstable-zonetree")]
                    let Some(zone) = &self.zone
                    else {
                        continue;
                    };

                    #[cfg(feature = "unstable-zonetree")]
                    {
                        let writable = match &self.writable {
                            Some(writable) => writable,
                            None => {
                                let new_write = zone.write().await;
                                self.writable = Some(
                                    new_write
                                        .open(true)
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?,
                                );
                                self.write = Some(new_write);
                                self.writable.as_ref().unwrap()
                            }
                        };

                        let mut end_node: Option<Box<dyn WritableZoneNode>> =
                            None;

                        let name = Self::mk_relative_name_iterator(
                            zone.apex_name(),
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

                        if self.xfr_type == Some(Rtype::AXFR)
                            || (self.xfr_type == Some(Rtype::IXFR)
                                && ixfr_update_mode == IxfrUpdateMode::Adding)
                        {
                            let mut rrset = Rrset::new(rtype, ttl);
                            rrset.push_data(data);

                            trace!("Adding RR: {:?}", rrset);

                            match end_node {
                                Some(n) => {
                                    trace!("Adding RR at end_node");

                                    if let Some(existing_rrset) = n
                                        .get_rrset(rtype)
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?
                                    {
                                        for existing_data in
                                            existing_rrset.data()
                                        {
                                            rrset.push_data(
                                                existing_data.clone(),
                                            );
                                        }
                                    }

                                    n.update_rrset(SharedRrset::new(rrset))
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?;
                                }
                                None => {
                                    trace!("Adding RR at root");
                                    writable
                                        .update_rrset(SharedRrset::new(rrset))
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?;
                                }
                            }
                        } else {
                            trace!("Deleting RR for {rtype}");
                            let mut rrset = Rrset::new(rtype, ttl);
                            match end_node {
                                Some(n) => {
                                    trace!("Deleting RR at end_node");

                                    if let Some(existing_rrset) = n
                                        .get_rrset(rtype)
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?
                                    {
                                        for existing_data in
                                            existing_rrset.data()
                                        {
                                            if existing_data != &data {
                                                rrset.push_data(
                                                    existing_data.clone(),
                                                );
                                            }
                                        }

                                        trace!("Removing single RR of {rtype} so updating RRSET");
                                        n.update_rrset(SharedRrset::new(
                                            rrset,
                                        ))
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?;
                                    }
                                }
                                None => {
                                    trace!("Deleting RR at root");
                                    if let Some(existing_rrset) = writable
                                        .get_rrset(rtype)
                                        .await
                                        .map_err(|_| Error::ZoneWrite)?
                                    {
                                        for existing_data in
                                            existing_rrset.data()
                                        {
                                            if existing_data != &data {
                                                rrset.push_data(
                                                    existing_data.clone(),
                                                );
                                            }
                                        }

                                        trace!("Removing single RR of {rtype} so updating RRSET");
                                        writable
                                            .update_rrset(SharedRrset::new(
                                                rrset,
                                            ))
                                            .await
                                            .map_err(|_| Error::ZoneWrite)?;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            Err(err) => {
                error!("Error while parsing XFR ANSWER: {err}");
                return Err(Error::MessageParseError);
            }
        }

        Ok(Some(msg))
    }

    /// TODO
    #[cfg(feature = "unstable-zonetree")]
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
}

impl<CR, Upstream> Debug for RequestMulti<CR, Upstream>
where
    CR: ComposeRequestMulti,
    Upstream: SendRequestMulti<CR>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
        f.debug_struct("Request")
            .field("fut", &format_args!("_"))
            .finish()
    }
}

impl<CR, Upstream> GetResponseMulti for RequestMulti<CR, Upstream>
where
    CR: ComposeRequestMulti,
    Upstream: SendRequestMulti<CR> + Send + Sync,
{
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<Message<Bytes>>, Error>>
                + Send
                + Sync
                + '_,
        >,
    > {
        if self.complete {
            Box::pin(ready(Ok(None)))
        } else {
            Box::pin(self.get_response_impl())
        }
    }
}

//------------ IxfrUpdateMode -------------------------------------------------

/// TODO
#[cfg(feature = "unstable-zonetree")]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum IxfrUpdateMode {
    /// TODO
    Deleting,
    /// TODO
    Adding,
}
