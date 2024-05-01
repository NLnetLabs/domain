//! XFR request handling middleware.

// TODO: Add IXFR diff purging.
// TODO: Add IXFR diff condensation.
// TODO: Add RRset combining in single responses.
use core::future::{ready, Ready};
use core::marker::PhantomData;
use core::ops::ControlFlow;
use core::pin::Pin;

use std::boxed::Box;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::string::ToString;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use bytes::Bytes;
use futures::stream::{once, Once};
use octseq::Octets;
use threadpool::ThreadPool;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::base::iana::{Class, Opcode, OptRcode, Rcode};
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{
    CanonicalOrd, Message, Name, ParsedName, Rtype, Serial, StreamTarget,
    ToName,
};
use crate::net::server::message::Request;
use crate::net::server::service::{
    CallResult, Service, ServiceFeedback, ServiceResult,
};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::ZoneRecordData;
use crate::zonetree::{
    Answer, AnswerContent, ReadableZone, SharedRrset, StoredName, Zone,
    ZoneDiff, ZoneSetIter,
};

use super::stream::MiddlewareStream;

//------------ XfrMapStream --------------------------------------------------

type XfrResultStream<StreamItem> = UnboundedReceiverStream<StreamItem>;

//------------ XfrMiddlewareStream -------------------------------------------

type XfrMiddlewareStream<Future, Stream, StreamItem> = MiddlewareStream<
    Future,
    Stream,
    Once<Ready<StreamItem>>,
    XfrResultStream<StreamItem>,
    StreamItem,
>;

//------------ ZoneDiffKey ---------------------------------------------------

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct ZoneDiffKey {
    start_serial: Serial,
    end_serial: Serial,
}

impl Ord for ZoneDiffKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.start_serial.canonical_cmp(&other.start_serial)
    }
}

impl PartialOrd for ZoneDiffKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ZoneDiffKey {
    fn new(start_serial: Serial, end_serial: Serial) -> Self {
        Self {
            start_serial,
            end_serial,
        }
    }

    fn start_serial(&self) -> Serial {
        self.start_serial
    }

    fn to_serial(&self) -> Serial {
        self.end_serial
    }
}

//------------ ZoneDiffs -----------------------------------------------------

type ZoneDiffs = BTreeMap<ZoneDiffKey, ZoneDiff>;

//------------ ZoneInfo ------------------------------------------------------

#[derive(Clone, Debug)]
struct ZoneInfo {
    zone: Zone,
    diffs: ZoneDiffs,
}

impl ZoneInfo {
    pub fn new(zone: Zone) -> Self {
        Self {
            zone,
            diffs: Default::default(),
        }
    }

    pub fn zone(&self) -> &Zone {
        &self.zone
    }

    pub fn add_diff(&mut self, diff: ZoneDiff) {
        let k = ZoneDiffKey::new(
            diff.start_serial.unwrap(), // SAFETY: TODO
            diff.end_serial.unwrap(),   // SAFETY: TODO
        );
        self.diffs.insert(k, diff);
    }

    pub fn get_diffs(
        &self,
        start_serial: Serial,
        end_serial: Serial,
    ) -> Option<Vec<&ZoneDiff>> {
        let mut diffs = Vec::new();
        let mut serial = start_serial;

        // Note: Assumes diffs are ordered by rising start serial.
        for (key, diff) in self.diffs.iter() {
            if key.start_serial() < serial {
                // Diff is for a serial that is too old, skip it.
                continue;
            } else if key.start_serial() > serial
                || key.start_serial() > end_serial
            {
                // Diff is for a serial that too new, abort as we don't have
                // the diff that the client needs.
                return None;
            } else if key.start_serial() == end_serial {
                // We found the last diff that the client needs.
                break;
            }

            diffs.push(diff);
            serial = key.to_serial();
        }

        Some(diffs)
    }
}

//------------ XfrMiddlewareSvc ----------------------------------------------

/// A [`MiddlewareProcessor`] for responding to XFR requests.
///
/// Standards covered by ths implementation:
///
/// | RFC    | Status  |
/// |--------|---------|
/// | [1034] | TBD     |
/// | [1035] | TBD     |
/// | [1995] | TBD     |
/// | [5936] | TBD     |
///
/// [`MiddlewareProcessor`]:
///     crate::net::server::middleware::processor::MiddlewareProcessor
/// [1034]: https://datatracker.ietf.org/doc/html/rfc1034
/// [1035]: https://datatracker.ietf.org/doc/html/rfc1035
/// [1995]: https://datatracker.ietf.org/doc/html/rfc1995
/// [5936]: https://datatracker.ietf.org/doc/html/rfc5936
#[derive(Clone, Debug)]
pub struct XfrMiddlewareSvc<RequestOctets, Svc> {
    svc: Svc,

    /// The set of zones to answer XFR requests for.
    zones: Arc<Mutex<HashMap<(Class, StoredName), ZoneInfo>>>,

    pool: ThreadPool,

    _phantom: PhantomData<RequestOctets>,
}

impl<RequestOctets, Svc> XfrMiddlewareSvc<RequestOctets, Svc> {
    /// Creates an empty processor instance.
    ///
    /// The processor will not respond to XFR requests until you add at least
    /// one zone to it.
    #[must_use]
    pub fn new(svc: Svc, num_threads: usize) -> Self {
        let pool = threadpool::Builder::new()
            .num_threads(num_threads)
            .thread_name("xfr".to_string())
            .build();

        Self {
            svc,
            zones: Arc::new(Mutex::new(HashMap::new())),
            pool,
            _phantom: PhantomData,
        }
    }

    pub fn add_zoneset(&mut self, iter: &mut ZoneSetIter<'_>) {
        for zone in iter.cloned() {
            self.add_zone(zone);
        }
    }

    pub fn add_zones<'a>(
        &mut self,
        zones: &mut impl Iterator<Item = &'a Zone>,
    ) {
        for zone in zones.cloned() {
            self.add_zone(zone);
        }
    }

    pub fn add_zone(&mut self, zone: Zone) {
        let dname = zone.apex_name().to_name();
        let key = (zone.class(), dname);
        let info = ZoneInfo::new(zone);
        self.zones.lock().unwrap().insert(key, info);
    }

    pub fn add_diff(&mut self, zone: &Zone, diff: ZoneDiff) {
        let dname = zone.apex_name().to_name();
        let key = (zone.class(), dname);
        if let Some(zone_info) = self.zones.lock().unwrap().get_mut(&key) {
            zone_info.add_diff(diff);
        }
    }
}

impl<RequestOctets, Svc> XfrMiddlewareSvc<RequestOctets, Svc>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    Svc: Service<RequestOctets>,
    Svc::Target: Composer + Default + Send + Sync + 'static,
{
    async fn preprocess(
        msg: Arc<Message<RequestOctets>>,
        zones: Arc<Mutex<HashMap<(Class, StoredName), ZoneInfo>>>,
        pool: ThreadPool,
    ) -> ControlFlow<
        XfrMiddlewareStream<
            Svc::Future,
            Svc::Stream,
            <Svc::Stream as futures::stream::Stream>::Item,
        >,
    > {
        if let Some(q) = msg.first_question() {
            if matches!(q.qtype(), Rtype::SOA | Rtype::AXFR | Rtype::IXFR) {
                let qname: Name<Bytes> = q.qname().to_name();
                let key = (q.qclass(), qname.clone());

                // Make sure we don't hold the lock across an .await point below.
                let zone = {
                    let guard = zones.lock().unwrap();
                    let info = guard.get(&key);
                    info.map(|info| info.zone().clone())
                };

                let Some(zone) = zone else {
                    // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2.1
                    // 2.2.1 Header Values
                    //   "If a server is not authoritative for the queried zone,
                    //    the server SHOULD set the value to NotAuth(9)"

                    // Note: This may not be strictly true, we may be
                    // authoritative for the zone but not willing to transfer
                    // it, but we can't know here which is the case.
                    let response = mk_error_response(&msg, OptRcode::NOTAUTH);
                    let res = Ok(CallResult::new(response));
                    let stream = MiddlewareStream::Map(once(ready(res)));
                    return ControlFlow::Break(stream);
                };

                let read = zone.read();
                let zone_soa_answer = match read.is_async() {
                    true => read.query_async(qname.clone(), Rtype::SOA).await,
                    false => read.query(qname.clone(), Rtype::SOA),
                };

                let Ok(zone_soa_answer) = zone_soa_answer else {
                    let response =
                        mk_error_response(&msg, OptRcode::SERVFAIL);
                    let res = Ok(CallResult::new(response));
                    let stream = MiddlewareStream::Map(once(ready(res)));
                    return ControlFlow::Break(stream);
                };

                // TODO: Move this whole SOA/AXFR/IXFR block into a new
                // Catalog type?
                match q.qtype() {
                    Rtype::SOA => {
                        let builder = mk_builder_for_target();
                        let response =
                            zone_soa_answer.to_message(&msg, builder);
                        let res = Ok(CallResult::new(response));
                        let stream = MiddlewareStream::Map(once(ready(res)));
                        return ControlFlow::Break(stream);
                    }

                    Rtype::AXFR => {
                        return Self::do_axfr(
                            &msg,
                            &zone_soa_answer,
                            read,
                            pool,
                        )
                        .await;
                    }

                    Rtype::IXFR => {
                        // Make sure we don't hold the lock across an .await point below.
                        let zone_info = {
                            let guard = zones.lock().unwrap();
                            let info = guard.get(&key);
                            let info = info.unwrap(); // TODO: SAFETY.
                            (*info).clone() // TODO: get rid of this clone.
                        };

                        match Self::do_ixfr(
                            &msg,
                            qname,
                            &zone_soa_answer,
                            &zone_info,
                        )
                        .await
                        {
                            Some(res) => return res,
                            None => {
                                return Self::do_axfr(
                                    &msg,
                                    &zone_soa_answer,
                                    read,
                                    pool,
                                )
                                .await;
                            }
                        }
                    }

                    _ => unreachable!(),
                }
            }
        }

        ControlFlow::Continue(())
    }

    async fn do_axfr(
        msg: &Arc<Message<RequestOctets>>,
        zone_soa_answer: &Answer,
        read: Box<dyn ReadableZone>,
        pool: ThreadPool,
    ) -> ControlFlow<
        XfrMiddlewareStream<
            Svc::Future,
            Svc::Stream,
            <Svc::Stream as futures::stream::Stream>::Item,
        >,
    > {
        // Return a stream of response messages containing:
        //   - SOA
        //   - RRSETs, one or more per response message
        //   - SOA

        let (sender, receiver) = unbounded_channel();
        let stream = UnboundedReceiverStream::new(receiver);

        Self::add_to_stream(
            CallResult::feedback_only(ServiceFeedback::BeginTransaction),
            &sender,
        );

        Self::add_msg_to_stream(zone_soa_answer, msg, &sender);

        let cloned_msg = msg.clone();
        let zone_soa_answer = zone_soa_answer.clone();
        tokio::spawn(async move {
            let cloned_sender = sender.clone();
            let cloned_msg2 = cloned_msg.clone();

            // TODO: Add batching of RRsets into single DNS responses instead
            // of one response per RRset. Perhaps via a response combining
            // middleware service?

            let op =
                Box::new(move |owner: StoredName, rrset: &SharedRrset| {
                    if rrset.rtype() != Rtype::SOA {
                        let cloned_owner = owner.clone();
                        let cloned_rrset = rrset.clone();
                        let cloned_msg2 = cloned_msg2.clone();
                        let cloned_sender = cloned_sender.clone();

                        // In manual testing the same kind of performance can
                        // be achieved by using:
                        //
                        //     tokio::task::spawn_blocking()
                        //
                        // here instead of pool.execute(), but we get much
                        // less control over how many threads are going to be
                        // used. It would use threads from the Tokio blocking
                        // thread pool which by default allows up to 512
                        // threads, but those threads are also used for any
                        // other calls to spawn_blocking() within the
                        // application.
                        //
                        // Note: While it's also possible to just run the zone
                        // walk in a single spawned thread, that prevents
                        // scaling across more threads if it becomes useful,
                        // and allows an unbounded number of simultaneous XFR
                        // transfers to occur in parallel, while using a
                        // thread pool puts an upper limit on the number of
                        // threads concurrently performing XFR.
                        pool.execute(move || {
                            if !cloned_sender.is_closed() {
                                let builder = mk_builder_for_target();
                                let mut answer = builder
                                    .start_answer(
                                        &cloned_msg2,
                                        Rcode::NOERROR,
                                    )
                                    .unwrap();
                                for item in cloned_rrset.data() {
                                    answer
                                        .push((
                                            cloned_owner.clone(),
                                            cloned_rrset.ttl(),
                                            item,
                                        ))
                                        .unwrap();
                                }

                                let mut additional = answer.additional();
                                Self::set_axfr_header(
                                    &cloned_msg2,
                                    &mut additional,
                                );
                                let call_result =
                                    Ok(CallResult::new(additional));

                                let _ = cloned_sender.send(call_result);
                            }
                        });
                    }
                });

            match read.is_async() {
                true => {
                    read.walk_async(op).await;
                }
                false => {
                    let _ = tokio::task::spawn_blocking(move || {
                        read.walk(op);
                    })
                    .await;
                }
            }

            Self::add_msg_to_stream(&zone_soa_answer, &cloned_msg, &sender);

            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::EndTransaction),
                &sender,
            );
        });

        ControlFlow::Break(MiddlewareStream::Result(stream))
    }

    // Returns None if fallback to AXFR should be done.
    async fn do_ixfr(
        msg: &Arc<Message<RequestOctets>>,
        qname: Name<Bytes>,
        zone_soa_answer: &Answer,
        zone_info: &ZoneInfo,
    ) -> Option<
        ControlFlow<
            XfrMiddlewareStream<
                Svc::Future,
                Svc::Stream,
                <Svc::Stream as futures::stream::Stream>::Item,
            >,
        >,
    > {
        // https://datatracker.ietf.org/doc/html/rfc1995#section-2
        // 2. Brief Description of the Protocol
        //   "Transport of a query may be by either UDP or TCP.  If an IXFR
        //    query is via UDP, the IXFR server may attempt to reply using UDP
        //    if the entire response can be contained in a single DNS packet.
        //    If the UDP reply does not fit, the query is responded to with a
        //    single SOA record of the server's current version to inform the
        //    client that a TCP query should be initiated."
        //
        // https://datatracker.ietf.org/doc/html/rfc1995#section-3
        // 3. Query Format
        //   "The IXFR query packet format is the same as that of a normal DNS
        //    query, but with the query type being IXFR and the authority
        //    section containing the SOA record of client's version of the
        //    zone."
        //
        // https://datatracker.ietf.org/doc/html/rfc1995#section-4
        // 4. Response Format
        //   "If incremental zone transfer is not available, the entire zone
        //    is returned.  The first and the last RR of the response is the
        //    SOA record of the zone.  I.e. the behavior is the same as an
        //    AXFR response except the query type is IXFR."
        //
        // https://datatracker.ietf.org/doc/html/rfc1995#section-2
        // 2. Brief Description of the Protocol
        //   "To ensure integrity, servers should use UDP checksums for all
        //    UDP responses.  A cautious client which receives a UDP packet
        //    with a checksum value of zero should ignore the result and try a
        //    TCP IXFR instead."
        if let Ok(mut query_soas) = msg.authority().map(|section| {
            section.limit_to::<crate::rdata::Soa<ParsedName<_>>>()
        }) {
            if let Some(Ok(query_soa)) = query_soas.next() {
                if query_soas.next().is_none() {
                    let query_serial = query_soa.data().serial();

                    if let AnswerContent::Data(rrset) =
                        zone_soa_answer.content()
                    {
                        if rrset.data().len() == 1 {
                            if let ZoneRecordData::Soa(soa) =
                                rrset.first().unwrap().data()
                            {
                                let zone_serial = soa.serial();

                                // TODO: if cached then return cached IXFR response
                                return Self::compute_ixfr(
                                    msg,
                                    qname,
                                    query_serial,
                                    zone_serial,
                                    zone_info,
                                    zone_soa_answer,
                                )
                                .await;
                            }
                        }
                    }

                    let response = mk_error_response(msg, OptRcode::SERVFAIL);
                    let res = Ok(CallResult::new(response));
                    let stream = MiddlewareStream::Map(once(ready(res)));
                    return Some(ControlFlow::Break(stream));
                }
            }
        }

        let response = mk_error_response(msg, OptRcode::FORMERR);
        let res = Ok(CallResult::new(response));
        let stream = MiddlewareStream::Map(once(ready(res)));

        Some(ControlFlow::Break(stream))
    }

    // Returns None if fallback to AXFR should be done.
    async fn compute_ixfr(
        msg: &Arc<Message<RequestOctets>>,
        qname: Name<Bytes>,
        query_serial: Serial,
        zone_serial: Serial,
        zone_info: &ZoneInfo,
        zone_soa_answer: &Answer,
    ) -> Option<
        ControlFlow<
            XfrMiddlewareStream<
                Svc::Future,
                Svc::Stream,
                <Svc::Stream as futures::stream::Stream>::Item,
            >,
        >,
    > {
        // https://datatracker.ietf.org/doc/html/rfc1995#section-2
        // 2. Brief Description of the Protocol
        //   "If an IXFR query with the same or newer version number than that
        //    of the server is received, it is replied to with a single SOA
        //    record of the server's current version, just as in AXFR."
        //                                            ^^^^^^^^^^^^^^^
        // Errata https://www.rfc-editor.org/errata/eid3196 points out that
        // this is NOT "just as in AXFR" as AXFR does not do that.
        if query_serial >= zone_serial {
            let (sender, receiver) = unbounded_channel();
            let stream = UnboundedReceiverStream::new(receiver);

            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::BeginTransaction),
                &sender,
            );

            // https://datatracker.ietf.org/doc/html/rfc1995#section-4
            // 4. Response Format
            //   "If incremental zone transfer is available, one or more
            //    difference sequences is returned.  The list of difference
            //    sequences is preceded and followed by a copy of the server's
            //    current version of the SOA."
            Self::add_msg_to_stream(zone_soa_answer, msg, &sender);

            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::EndTransaction),
                &sender,
            );

            return Some(ControlFlow::Break(MiddlewareStream::Result(
                stream,
            )));
        }

        let start_serial = query_serial;
        let end_serial = zone_serial;
        let Some(diffs) = zone_info.get_diffs(start_serial, end_serial)
        else {
            // Fallback to AXFR
            return None;
        };

        // let mut stream = FuturesOrdered::new();
        let (sender, receiver) = unbounded_channel();
        let stream = UnboundedReceiverStream::new(receiver);

        Self::add_to_stream(
            CallResult::feedback_only(ServiceFeedback::BeginTransaction),
            &sender,
        );

        // https://datatracker.ietf.org/doc/html/rfc1995#section-4
        // 4. Response Format
        //   "If incremental zone transfer is available, one or more
        //    difference sequences is returned.  The list of difference
        //    sequences is preceded and followed by a copy of the server's
        //    current version of the SOA."
        Self::add_msg_to_stream(zone_soa_answer, msg, &sender);

        // https://datatracker.ietf.org/doc/html/rfc1995#section-4
        // 4. Response Format
        //   "Modification of an RR is performed first by removing the
        //    original RR and then adding the modified one.
        //
        //    The sequences of differential information are ordered oldest
        //    first newest last.  Thus, the differential sequences are the
        //    history of changes made since the version known by the IXFR
        //    client up to the server's current version.
        //
        //    RRs in the incremental transfer messages may be partial. That
        //    is, if a single RR of multiple RRs of the same RR type changes,
        //    only the changed RR is transferred."

        // For each zone version:
        for diff in diffs {
            // Emit deleted RRs.

            // https://datatracker.ietf.org/doc/html/rfc1995#section-4
            // 4. Response Format
            //    "Each difference sequence represents one update to the zone
            //    (one SOA serial change) consisting of deleted RRs and added
            //    RRs.  The first RR of the deleted RRs is the older SOA RR
            //    and the first RR of the added RRs is the newer SOA RR.

            // Emit the removed SOA.
            let removed_top_node_rrsets = diff.removed.get(&qname).unwrap();
            let non_soa = removed_top_node_rrsets
                .iter()
                .find(|rrset| rrset.rtype() == Rtype::SOA)
                .unwrap();
            let mut old_soa_version_answer = Answer::new(Rcode::NOERROR);
            old_soa_version_answer.add_answer(non_soa.clone());

            Self::add_msg_to_stream(&old_soa_version_answer, msg, &sender);

            for non_soa_rr in removed_top_node_rrsets
                .iter()
                .filter(|rrset| rrset.rtype() != Rtype::SOA)
            {
                let mut answer = Answer::new(Rcode::NOERROR);
                answer.add_answer(non_soa_rr.clone());
                Self::add_msg_to_stream(&answer, msg, &sender);
            }

            // Emit added RRs.

            // https://datatracker.ietf.org/doc/html/rfc1995#section-4
            // 4. Response Format
            //    "Each difference sequence represents one update to the zone
            //    (one SOA serial change) consisting of deleted RRs and added
            //    RRs.  The first RR of the deleted RRs is the older SOA RR
            //    and the first RR of the added RRs is the newer SOA RR.
            let added_top_node_rrsets = diff.added.get(&qname).unwrap();
            let non_soa = added_top_node_rrsets
                .iter()
                .find(|rrset| rrset.rtype() == Rtype::SOA)
                .unwrap();
            let mut old_soa_version_answer = Answer::new(Rcode::NOERROR);
            old_soa_version_answer.add_answer(non_soa.clone());

            Self::add_msg_to_stream(&old_soa_version_answer, msg, &sender);

            for non_soa_rr in added_top_node_rrsets
                .iter()
                .filter(|rrset| rrset.rtype() != Rtype::SOA)
            {
                let mut answer = Answer::new(Rcode::NOERROR);
                answer.add_answer(non_soa_rr.clone());
                Self::add_msg_to_stream(&answer, msg, &sender);
            }
        }

        // https://datatracker.ietf.org/doc/html/rfc1995#section-4
        // 4. Response Format
        //   "If incremental zone transfer is available, one or more
        //    difference sequences is returned.  The list of difference
        //    sequences is preceded and followed by a copy of the server's
        //    current version of the SOA."
        Self::add_msg_to_stream(zone_soa_answer, msg, &sender);

        Self::add_to_stream(
            CallResult::feedback_only(ServiceFeedback::EndTransaction),
            &sender,
        );

        Some(ControlFlow::Break(MiddlewareStream::Result(stream)))
    }

    fn add_msg_to_stream(
        answer: &Answer,
        msg: &Message<RequestOctets>,
        sender: &UnboundedSender<ServiceResult<Svc::Target>>,
    ) {
        let builder = mk_builder_for_target();
        let mut additional = answer.to_message(msg, builder);
        Self::set_axfr_header(msg, &mut additional);
        let call_result = CallResult::new(additional);
        Self::add_to_stream(call_result, sender);
    }

    #[allow(clippy::type_complexity)]
    fn add_to_stream(
        call_result: CallResult<Svc::Target>,
        sender: &UnboundedSender<ServiceResult<Svc::Target>>,
    ) {
        sender.send(Ok(call_result)).unwrap();
    }

    fn set_axfr_header(
        msg: &Message<RequestOctets>,
        additional: &mut AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) {
        // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2.1
        // 2.2.1: Header Values
        //
        // "These are the DNS message header values for AXFR responses.
        //
        //     ID          MUST be copied from request -- see Note a)
        //
        //     QR          MUST be 1 (Response)
        //
        //     OPCODE      MUST be 0 (Standard Query)
        //
        //     Flags:
        //        AA       normally 1 -- see Note b)
        //        TC       MUST be 0 (Not truncated)
        //        RD       RECOMMENDED: copy request's value; MAY be set to 0
        //        RA       SHOULD be 0 -- see Note c)
        //        Z        "mbz" -- see Note d)
        //        AD       "mbz" -- see Note d)
        //        CD       "mbz" -- see Note d)"
        let header = additional.header_mut();
        header.set_id(msg.header().id());
        header.set_qr(true);
        header.set_opcode(Opcode::QUERY);
        header.set_aa(true);
        header.set_tc(false);
        header.set_rd(msg.header().rd());
        header.set_ra(false);
        header.set_z(false);
        header.set_ad(false);
        header.set_cd(false);
    }
}

//--- Service

impl<RequestOctets, Svc> Service<RequestOctets>
    for XfrMiddlewareSvc<RequestOctets, Svc>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    Svc: Service<RequestOctets> + Clone + 'static + Send + Sync + Unpin,
    Svc::Future: Send + Sync + Unpin,
    Svc::Target: Composer + Default + Send + Sync,
    Svc::Stream: Send + Sync,
{
    type Target = Svc::Target;
    type Stream = XfrMiddlewareStream<
        Svc::Future,
        Svc::Stream,
        <Svc::Stream as futures::stream::Stream>::Item,
    >;
    type Future = Pin<
        Box<dyn core::future::Future<Output = Self::Stream> + Send + Sync>,
    >;

    fn call(&self, request: Request<RequestOctets>) -> Self::Future {
        if let Some(q) = request.message().first_question() {
            if matches!(q.qtype(), Rtype::SOA | Rtype::AXFR | Rtype::IXFR) {
                let request = request.clone();
                let msg = request.message().clone();
                let svc = self.svc.clone();
                let zones = self.zones.clone();
                let pool = self.pool.clone();
                let fut = async move {
                    match Self::preprocess(msg, zones, pool).await {
                        ControlFlow::Continue(()) => {
                            let stream = svc.call(request).await;
                            MiddlewareStream::IdentityStream(stream)
                        }
                        ControlFlow::Break(stream) => stream,
                    }
                };
                return Box::pin(fut);
            }
        }

        let svc = self.svc.clone();
        Box::pin(async move {
            MiddlewareStream::IdentityStream(svc.call(request).await)
        })
    }
}
