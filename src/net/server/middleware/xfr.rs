//! XFR request handling middleware.

// TODO: Add RRset combining in single responses.
use core::future::{ready, Future, Ready};
use core::marker::PhantomData;
use core::ops::ControlFlow;
use core::pin::Pin;

use std::boxed::Box;
use std::sync::Arc;

use bytes::Bytes;
use futures::stream::{once, Once, Stream};
use octseq::Octets;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{error, info, trace, warn};

use crate::base::iana::{Opcode, OptRcode, Rcode};
use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{
    Message, Name, ParsedName, Question, Rtype, Serial, StreamTarget, ToName,
};
use crate::net::server::message::Request;
use crate::net::server::service::{
    CallResult, Service, ServiceError, ServiceFeedback, ServiceResult,
};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::ZoneRecordData;
use crate::zonetree::{
    Answer, AnswerContent, ReadableZone, SharedRrset, StoredName,
};

use super::stream::MiddlewareStream;

//------------ ThreadPool ----------------------------------------------------

use crate::zonecatalog::catalog::{self, Acl, Catalog, CatalogZone};
use crate::zonetree::error::OutOfZone;
#[rustversion::since(1.72)]
use threadpool::ThreadPool;

#[rustversion::before(1.72)]
#[derive(Clone, Debug)]
struct ThreadPool;

#[rustversion::before(1.72)]
impl ThreadPool {
    pub fn execute<F>(&self, job: F)
    where
        F: FnOnce() + Send + 'static,
    {
        // Less constrained (by default spawns up to 512 threads) and more
        // impacting (the thread pool is shared by the rest of the application
        // so filling it with XFR threads can starve uses of the pool by other
        // parts of the application) than threadpool::ThreadPool, but pre 1.72
        // std::sync::mpsc::Sender is not Sync, which is required for code
        // using threadpool::ThreadPool to compile, so we fall back to this
        // instead.
        tokio::task::spawn_blocking(job);
    }
}

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

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum XfrMode {
    AxfrAndIxfr,
    AxfrOnly,
}

//------------ CompatibilityMode ---------------------------------------------

/// https://datatracker.ietf.org/doc/html/rfc5936#section-7.1
/// 7.1.  Server
///   "An implementation of an AXFR server MAY permit configuring, on a per
///    AXFR client basis, the necessity to revert to a single resource record
///    per message; in that case, the default SHOULD be to use multiple
///    records per message."
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum CompatibilityMode {
    #[default]
    Default,

    BackwardCompatible,
}

//------------ PerClientSettings ---------------------------------------------

pub type PerClientSettings = Acl<CompatibilityMode>;

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

    catalog: Arc<Catalog>,

    pool: ThreadPool,

    xfr_mode: XfrMode,

    per_client_settings: Arc<PerClientSettings>,

    _phantom: PhantomData<RequestOctets>,
}

impl<RequestOctets, Svc> XfrMiddlewareSvc<RequestOctets, Svc> {
    /// Creates an empty processor instance.
    ///
    /// The processor will not respond to XFR requests until you add at least
    /// one zone to it.
    // TODO: Move extra arguments into a Config object.
    #[must_use]
    pub fn new(
        svc: Svc,
        catalog: Arc<Catalog>,
        num_threads: usize,
        xfr_mode: XfrMode,
        per_client_settings: PerClientSettings,
    ) -> Self {
        let pool = Self::mk_thread_pool(num_threads);
        let per_client_settings = Arc::new(per_client_settings);

        Self {
            svc,
            catalog,
            pool,
            xfr_mode,
            per_client_settings,
            _phantom: PhantomData,
        }
    }

    #[rustversion::since(1.72)]
    fn mk_thread_pool(num_threads: usize) -> ThreadPool {
        use std::string::ToString;
        threadpool::Builder::new()
            .num_threads(num_threads)
            .thread_name("xfr".to_string())
            .build()
    }

    #[rustversion::before(1.72)]
    fn mk_thread_pool(_num_threads: usize) -> ThreadPool {
        ThreadPool
    }
}

impl<RequestOctets, Svc> XfrMiddlewareSvc<RequestOctets, Svc>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    Svc: Service<RequestOctets>,
    Svc::Target: Composer + Default + Send + Sync + 'static,
{
    async fn preprocess(
        req: &Request<RequestOctets>,
        catalog: Arc<Catalog>,
        pool: ThreadPool,
        xfr_mode: XfrMode,
        per_client_settings: Arc<PerClientSettings>,
    ) -> ControlFlow<
        XfrMiddlewareStream<
            Svc::Future,
            Svc::Stream,
            <Svc::Stream as Stream>::Item,
        >,
    > {
        let msg = req.message();

        let Some(q) = Self::get_relevant_question(msg) else {
            return ControlFlow::Continue(());
        };

        // Find the zone
        let zones = catalog.zones();
        let Some(zone) = zones.get_zone(q.qname(), q.qclass()) else {
            // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2.1
            // 2.2.1 Header Values
            //   "If a server is not authoritative for the queried zone, the
            //    server SHOULD set the value to NotAuth(9)"
            warn!(
                "{} for {} from {} refused: unknown zone",
                q.qtype(),
                q.qname(),
                req.client_addr()
            );

            // Note: This may not be strictly true, we may be authoritative
            // for the zone but not willing to transfer it, but we can't know
            // here which is the case.
            return ControlFlow::Break(Self::to_stream(mk_error_response(
                msg,
                OptRcode::NOTAUTH,
            )));
        };

        // Read the zone SOA RR
        let read = zone.read();
        let qname: Name<Bytes> = q.qname().to_name();
        let Ok(zone_soa_answer) = Self::read_soa(&read, qname.clone()).await
        else {
            warn!(
                "{} for {} from {} refused: zone lacks SOA RR",
                q.qtype(),
                q.qname(),
                req.client_addr()
            );
            return ControlFlow::Break(Self::to_stream(mk_error_response(
                msg,
                OptRcode::SERVFAIL,
            )));
        };

        match q.qtype() {
            Rtype::SOA => {
                let builder = mk_builder_for_target();
                let response = zone_soa_answer.to_message(msg, builder);
                ControlFlow::Break(Self::to_stream(response))
            }

            Rtype::AXFR => {
                // https://datatracker.ietf.org/doc/html/rfc5936#section-4.2
                // 4.2.  UDP
                //   "With the addition of EDNS0 and applications that require many
                //    small zones, such as in web hosting and some ENUM scenarios,
                //    AXFR sessions on UDP would now seem desirable.  However, there
                //    are still some aspects of AXFR sessions that are not easily
                //    translated to UDP.
                //
                //    Therefore, this document does not update RFC 1035 in this
                //    respect: AXFR sessions over UDP transport are not defined."
                if req.transport_ctx().is_udp() {
                    info!(
                        "AXFR for {} from {} refused: not supported over UDP",
                        q.qname(),
                        req.client_addr()
                    );
                    ControlFlow::Break(Self::to_stream(mk_error_response(
                        msg,
                        OptRcode::NOTIMP,
                    )))
                } else {
                    info!(
                        "AXFR for {} from {}",
                        q.qname(),
                        req.client_addr()
                    );
                    Self::do_axfr(
                        req,
                        &zone_soa_answer,
                        read,
                        pool,
                        per_client_settings,
                    )
                    .await
                }
            }

            Rtype::IXFR => {
                let cat_zone = zone
                    .as_ref()
                    .as_any()
                    .downcast_ref::<CatalogZone>()
                    .unwrap();

                info!("IXFR for {} from {}", q.qname(), req.client_addr());

                // https://datatracker.ietf.org/doc/html/rfc1995#section-2
                // 2. Brief Description of the Protocol
                //   "Transport of a query may be by either UDP or TCP.  If an
                //    IXFR query is via UDP, the IXFR server may attempt to reply
                //    using UDP if the entire response can be contained in a
                //    single DNS packet.  If the UDP reply does not fit, the query
                //    is responded to with a single SOA record of the server's
                //    current version to inform the client that a TCP query should
                //    be initiated."

                match Self::do_ixfr(
                    req,
                    qname,
                    &zone_soa_answer,
                    cat_zone.info(),
                    xfr_mode,
                    per_client_settings.clone(),
                )
                .await
                {
                    Some(res) => res,
                    None => {
                        info!(
                            "IXFR for {} from {}: falling back to AXFR",
                            q.qname(),
                            req.client_addr()
                        );

                        // https://datatracker.ietf.org/doc/html/rfc1995#section-4
                        // 4. Response Format
                        //    "If incremental zone transfer is not available, the
                        //     entire zone is returned.  The first and the last RR
                        //     of the response is the SOA record of the zone.
                        //     I.e. the behavior is the same as an AXFR response
                        //     except the query type is IXFR."
                        Self::do_axfr(
                            req,
                            &zone_soa_answer,
                            read,
                            pool,
                            per_client_settings,
                        )
                        .await
                    }
                }
            }

            _ => ControlFlow::Continue(()),
        }
    }

    async fn do_axfr(
        req: &Request<RequestOctets>,
        zone_soa_answer: &Answer,
        read: Box<dyn ReadableZone>,
        pool: ThreadPool,
        per_client_settings: Arc<PerClientSettings>,
    ) -> ControlFlow<
        XfrMiddlewareStream<
            Svc::Future,
            Svc::Stream,
            <Svc::Stream as Stream>::Item,
        >,
    > {
        let msg = req.message();

        // Return a stream of response messages containing:
        //   - SOA
        //   - RRSETs, one or more per response message
        //   - SOA
        //
        // Neither RFC 5936 nor RFC 1035 defined AXFR for UDP, only for TCP.
        // However, RFC 1995 says that for IXFR if no diffs are available the
        // full zone should be served just as with AXFR, and that UDP is
        // supported as long as the entire XFR response fits in a single
        // datagram. Thus we don't check for UDP or TCP here, except to abort
        // if the response is too large to fit in a single UDP datagram,
        // instead we let the caller that has the context decide whether AXFR
        // is supported or not.
        //
        // References:
        //   - https://datatracker.ietf.org/doc/html/rfc1995#section-2
        //   - https://datatracker.ietf.org/doc/html/rfc1995#section-4
        //   - https://datatracker.ietf.org/doc/html/rfc5936#section-4.2

        let (sender, receiver) = unbounded_channel();
        let stream = UnboundedReceiverStream::new(receiver);

        Self::add_to_stream(
            CallResult::feedback_only(ServiceFeedback::BeginTransaction),
            &sender,
        );

        let (batcher_tx, mut batcher_rx) =
            tokio::sync::mpsc::channel::<(StoredName, SharedRrset)>(100);

        let qname: StoredName =
            msg.sole_question().unwrap().qname().to_name();
        let AnswerContent::Data(soa_rrset) =
            zone_soa_answer.content().clone()
        else {
            unreachable!()
        };
        batcher_tx
            .send((qname.clone(), soa_rrset.clone()))
            .await
            .unwrap();

        // Do we need to operate in backward compatibility mode for this client?
        let compatibility_mode = per_client_settings
            .get_ip(req.client_addr().ip())
            .copied()
            .unwrap_or_default();

        if compatibility_mode == CompatibilityMode::BackwardCompatible {
            trace!(
                "Compatibility mode enabled for client with IP address {}",
                req.client_addr().ip()
            );
        }

        // Stream the RRsets in the background to the batcher.
        tokio::spawn(async move {
            // Define a zone tree walking operation like a filter map that
            // selects non-SOA RRsets and emits them to the batching stream.
            let cloned_batcher_tx = batcher_tx.clone();
            let op =
                Box::new(move |owner: StoredName, rrset: &SharedRrset| {
                    if rrset.rtype() != Rtype::SOA {
                        cloned_batcher_tx
                            .blocking_send((owner.clone(), rrset.clone()))
                            .unwrap();
                    }
                });

            // Walk the zone tree, invoking our operation for each leaf.
            match read.is_async() {
                true => {
                    read.walk_async(op).await;
                    batcher_tx.send((qname, soa_rrset)).await.unwrap();
                }
                false => {
                    pool.execute(move || {
                        read.walk(op);
                        if let Err(err) = batcher_tx.blocking_send((qname, soa_rrset)) {
                            error!("Internal error: Failed to send final AXFR SOA to batcher: {err}");
                        }
                    });
                }
            }
        });

        // TODO: Extract this batcher and use it for IXFR too.

        // Combine RRsets enumerated by zone walking as many as possible per
        // DNS response message and pass the created messages downstream to
        // the caller.
        let msg = msg.clone();

        // TODO: Shouldn't this be run on a pool thread? If so how do we do async there?
        // Maybe don't use a thread pool but instead use a semaphore instead to limit
        // concurrent XFR activity?
        tokio::spawn(async move {
            let qclass = msg.sole_question().unwrap().qclass();

            let (mut owner, mut rrset) = batcher_rx.recv().await.unwrap();
            assert_eq!(rrset.rtype(), Rtype::SOA);
            let saved_soa_rrset = rrset.clone();
            let mut soa_seen_count = 0;

            let mut rrset_data = rrset.data();

            // Loop until all of the RRsets sent by the zone walker have been
            // pushed into DNS response messages and sent into the result
            // stream.
            'outer: loop {
                // Build a DNS response that contains as many answers as
                // possible.
                let builder = mk_builder_for_target();
                let mut answer =
                    builder.start_answer(&msg, Rcode::NOERROR).unwrap();

                // Loop over the RRset items being sent by the zone walker and
                // add as many of them as possible to the response being
                // built.

                let mut num_rrs_added = 0;
                'inner: loop {
                    if rrset == saved_soa_rrset {
                        soa_seen_count += 1;
                    }

                    for rr in rrset_data {
                        let res = answer.push((
                            owner.clone(),
                            qclass,
                            rrset.ttl(),
                            rr,
                        ));
                        match res {
                            Err(_) if num_rrs_added > 0 => {
                                // Message is full, send what we have so far.
                                break 'inner;
                            }

                            Err(err) => {
                                error!("Internal error: Unable to add RR to AXFR response message: {err}");
                                break 'outer;
                            }

                            Ok(()) => {
                                num_rrs_added += 1;
                                if compatibility_mode
                                    == CompatibilityMode::BackwardCompatible
                                {
                                    break 'inner;
                                }
                            }
                        }
                    }

                    if soa_seen_count == 2 {
                        // No more RRsets to fetch.
                        break;
                    } else {
                        // Fetch more RRsets to add to the message.
                        (owner, rrset) = batcher_rx.recv().await.unwrap();
                        rrset_data = rrset.data();
                        num_rrs_added = 0;
                    }
                }

                // Send the message.
                let mut additional = answer.additional();
                Self::set_axfr_header(&msg, &mut additional);
                let call_result = Ok(CallResult::new(additional));
                let _ = sender.send(call_result); // TODO: Handle this Result.

                if num_rrs_added < rrset_data.len() {
                    rrset_data = &rrset.data()[num_rrs_added..];
                } else if soa_seen_count == 2 {
                    break;
                } else {
                    // Fetch more RRsets to add to the message.
                    (owner, rrset) = batcher_rx.recv().await.unwrap();
                    rrset_data = rrset.data();
                }
            }

            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::EndTransaction),
                &sender,
            );

            batcher_rx.close();
        });

        ControlFlow::Break(MiddlewareStream::Result(stream))
    }

    // Returns None if fallback to AXFR should be done.
    async fn do_ixfr(
        req: &Request<RequestOctets>,
        qname: Name<Bytes>,
        zone_soa_answer: &Answer,
        zone_info: &catalog::ZoneInfo,
        xfr_mode: XfrMode,
        per_client_settings: Arc<PerClientSettings>,
    ) -> Option<
        ControlFlow<
            XfrMiddlewareStream<
                Svc::Future,
                Svc::Stream,
                <Svc::Stream as Stream>::Item,
            >,
        >,
    > {
        if xfr_mode == XfrMode::AxfrOnly {
            trace!("Not responding with IXFR as mode is set to AXFR only");
            return None;
        }

        let msg = req.message();

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
                                    req,
                                    qname,
                                    query_serial,
                                    zone_serial,
                                    zone_info,
                                    zone_soa_answer,
                                    per_client_settings,
                                )
                                .await;
                            }
                        }
                    }

                    return Some(ControlFlow::Break(Self::to_stream(
                        mk_error_response(msg, OptRcode::SERVFAIL),
                    )));
                }
            }
        }

        Some(ControlFlow::Break(Self::to_stream(mk_error_response(
            msg,
            OptRcode::FORMERR,
        ))))
    }

    // Returns None if fallback to AXFR should be done.
    async fn compute_ixfr(
        req: &Request<RequestOctets>,
        qname: Name<Bytes>,
        query_serial: Serial,
        zone_serial: Serial,
        zone_info: &catalog::ZoneInfo,
        zone_soa_answer: &Answer,
        _per_client_settings: Arc<PerClientSettings>,
    ) -> Option<
        ControlFlow<
            XfrMiddlewareStream<
                Svc::Future,
                Svc::Stream,
                <Svc::Stream as Stream>::Item,
            >,
        >,
    > {
        let msg = req.message();

        // https://datatracker.ietf.org/doc/html/rfc1995#section-2
        // 2. Brief Description of the Protocol
        //   "If an IXFR query with the same or newer version number than that
        //    of the server is received, it is replied to with a single SOA
        //    record of the server's current version, just as in AXFR."
        //                                            ^^^^^^^^^^^^^^^
        // Errata https://www.rfc-editor.org/errata/eid3196 points out that
        // this is NOT "just as in AXFR" as AXFR does not do that.
        if query_serial >= zone_serial {
            let builder = mk_builder_for_target();
            let response = zone_soa_answer.to_message(msg, builder);
            trace!("IXFR finished because query_serial >= zone_serial");
            return Some(ControlFlow::Break(Self::to_stream(response)));
        }

        // Get the necessary diffs, if available
        let start_serial = query_serial;
        let end_serial = zone_serial;
        let diffs = zone_info.diffs_for_range(start_serial, end_serial).await;
        if diffs.is_empty() {
            // Fallback to AXFR
            trace!("Fallback to AXFR because no IXFR diff is available");
            return None;
        };

        // https://datatracker.ietf.org/doc/html/rfc1995#section-4
        // 4. Response Format
        //   "If incremental zone transfer is available, one or more
        //    difference sequences is returned.  The list of difference
        //    sequences is preceded and followed by a copy of the server's
        //    current version of the SOA."
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
        Self::add_answer_to_stream(zone_soa_answer, msg, &sender);

        let msg = msg.clone();
        let zone_soa_answer = zone_soa_answer.clone();

        // Stream the IXFR diffs in the background
        tokio::spawn(async move {
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
                let removed_top_node_rrsets =
                    diff.removed.get(&qname).unwrap();
                let non_soa = removed_top_node_rrsets
                    .iter()
                    .find(|rrset| rrset.rtype() == Rtype::SOA)
                    .unwrap();
                let mut old_soa_version_answer = Answer::new(Rcode::NOERROR);
                old_soa_version_answer.add_answer(non_soa.clone());

                // TODO: Accumulate RRsets in each message until it would
                // overflow, and only then start a new message.

                Self::add_answer_to_stream(
                    &old_soa_version_answer,
                    &msg,
                    &sender,
                );

                for non_soa_rr in removed_top_node_rrsets
                    .iter()
                    .filter(|rrset| rrset.rtype() != Rtype::SOA)
                {
                    let mut answer = Answer::new(Rcode::NOERROR);
                    answer.add_answer(non_soa_rr.clone());
                    Self::add_answer_to_stream(&answer, &msg, &sender);
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

                Self::add_answer_to_stream(
                    &old_soa_version_answer,
                    &msg,
                    &sender,
                );

                for non_soa_rr in added_top_node_rrsets
                    .iter()
                    .filter(|rrset| rrset.rtype() != Rtype::SOA)
                {
                    let mut answer = Answer::new(Rcode::NOERROR);
                    answer.add_answer(non_soa_rr.clone());
                    Self::add_answer_to_stream(&answer, &msg, &sender);
                }
            }

            // https://datatracker.ietf.org/doc/html/rfc1995#section-4
            // 4. Response Format
            //   "If incremental zone transfer is available, one or more
            //    difference sequences is returned.  The list of difference
            //    sequences is preceded and followed by a copy of the server's
            //    current version of the SOA."
            Self::add_answer_to_stream(&zone_soa_answer, &msg, &sender);

            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::EndTransaction),
                &sender,
            );
        });

        Some(ControlFlow::Break(MiddlewareStream::Result(stream)))
    }

    fn add_answer_to_stream(
        answer: &Answer,
        msg: &Message<RequestOctets>,
        sender: &UnboundedSender<
            Result<CallResult<Svc::Target>, ServiceError>,
        >,
    ) {
        let builder = mk_builder_for_target();
        let mut additional = answer.to_message(msg, builder);
        Self::set_axfr_header(msg, &mut additional);
        let call_result = CallResult::new(additional);
        Self::add_to_stream(call_result, sender);
    }

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

        // Note: MandatoryMiddlewareSvc will also "fix" the response ID like
        // is done here, so strictly speaking this isn't necessary.
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

    fn to_stream(
        response: AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) -> XfrMiddlewareStream<
        Svc::Future,
        Svc::Stream,
        <Svc::Stream as Stream>::Item,
    > {
        let res = Ok(CallResult::new(response));
        MiddlewareStream::Map(once(ready(res)))
    }

    #[allow(clippy::borrowed_box)]
    async fn read_soa(
        read: &Box<dyn ReadableZone>,
        qname: Name<Bytes>,
    ) -> Result<Answer, OutOfZone> {
        match read.is_async() {
            true => read.query_async(qname, Rtype::SOA).await,
            false => read.query(qname, Rtype::SOA),
        }
    }

    fn get_relevant_question(
        msg: &Message<RequestOctets>,
    ) -> Option<Question<ParsedName<RequestOctets::Range<'_>>>> {
        if Opcode::QUERY == msg.header().opcode() && !msg.header().qr() {
            if let Some(q) = msg.first_question() {
                if matches!(q.qtype(), Rtype::SOA | Rtype::AXFR | Rtype::IXFR)
                {
                    return Some(q);
                }
            }
        }

        None
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
        <Svc::Stream as Stream>::Item,
    >;
    type Future = Pin<Box<dyn Future<Output = Self::Stream> + Send + Sync>>;

    fn call(&self, request: Request<RequestOctets>) -> Self::Future {
        let request = request.clone();
        let svc = self.svc.clone();
        let catalog = self.catalog.clone();
        let pool = self.pool.clone();
        let xfr_mode = self.xfr_mode;
        let per_client_settings = self.per_client_settings.clone();
        Box::pin(async move {
            match Self::preprocess(
                &request,
                catalog,
                pool,
                xfr_mode,
                per_client_settings,
            )
            .await
            {
                ControlFlow::Continue(()) => {
                    let stream = svc.call(request).await;
                    MiddlewareStream::IdentityStream(stream)
                }
                ControlFlow::Break(stream) => stream,
            }
        })
    }
}
