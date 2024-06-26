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
use tokio::sync::Semaphore;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{error, info, trace, warn};

use crate::base::iana::{Opcode, OptRcode, Rcode};
use crate::base::message_builder::{
    AdditionalBuilder, AnswerBuilder, PushError,
};
use crate::base::record::ComposeRecord;
use crate::base::wire::Composer;
use crate::base::{
    Message, Name, ParsedName, Question, Rtype, Serial, StreamTarget, ToName,
};
use crate::net::server::message::Request;
use crate::net::server::service::{
    CallResult, Service, ServiceFeedback, ServiceResult,
};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::ZoneRecordData;
use crate::zonecatalog::catalog::{
    Catalog, CatalogZone, CompatibilityMode, XfrStrategy, ZoneInfo, ZoneType,
};
use crate::zonetree::error::OutOfZone;
use crate::zonetree::{
    Answer, AnswerContent, ReadableZone, SharedRrset, StoredName,
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

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum XfrMode {
    AxfrAndIxfr,
    AxfrOnly,
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

    catalog: Arc<Catalog>,

    zone_walking_semaphore: Arc<Semaphore>,

    batcher_semaphore: Arc<Semaphore>,

    xfr_mode: XfrMode,

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
        max_concurrency: usize,
        xfr_mode: XfrMode,
    ) -> Self {
        let zone_walking_semaphore =
            Arc::new(Semaphore::new(max_concurrency));
        let batcher_semaphore = Arc::new(Semaphore::new(max_concurrency));

        Self {
            svc,
            catalog,
            zone_walking_semaphore,
            batcher_semaphore,
            xfr_mode,
            _phantom: PhantomData,
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
        zone_walking_semaphore: Arc<Semaphore>,
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets>,
        catalog: Arc<Catalog>,
        xfr_mode: XfrMode,
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

        let qname: Name<Bytes> = q.qname().to_name();

        // Find the zone
        let zones = catalog.zones();
        let Some(zone) = zones.get_zone(&qname, q.qclass()) else {
            // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2.1
            // 2.2.1 Header Values
            //   "If a server is not authoritative for the queried zone, the
            //    server SHOULD set the value to NotAuth(9)"
            warn!(
                "{} for {qname} from {} refused: unknown zone",
                q.qtype(),
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
        let Ok(zone_soa_answer) = Self::read_soa(&read, qname.clone()).await
        else {
            warn!(
                "{} for {qname} from {} refused: zone lacks SOA RR",
                q.qtype(),
                req.client_addr()
            );
            return ControlFlow::Break(Self::to_stream(mk_error_response(
                msg,
                OptRcode::SERVFAIL,
            )));
        };

        // Only provide XFR if allowed.
        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<CatalogZone>()
            .unwrap();

        if !Self::is_allowed(req, &qname, q.qtype(), cat_zone.info()) {
            return ControlFlow::Break(Self::to_stream(mk_error_response(
                msg,
                OptRcode::REFUSED,
            )));
        }

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
                        "AXFR for {qname} from {} refused: not supported over UDP",
                        req.client_addr()
                    );
                    ControlFlow::Break(Self::to_stream(mk_error_response(
                        msg,
                        OptRcode::NOTIMP,
                    )))
                } else {
                    info!("AXFR for {qname} from {}", req.client_addr());
                    Self::do_axfr(
                        zone_walking_semaphore,
                        batcher_semaphore,
                        req,
                        qname,
                        &zone_soa_answer,
                        cat_zone.info(),
                        read,
                    )
                    .await
                }
            }

            Rtype::IXFR => {
                info!("IXFR for {qname} from {}", req.client_addr());

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
                    batcher_semaphore.clone(),
                    req,
                    qname.clone(),
                    &zone_soa_answer,
                    cat_zone.info(),
                    xfr_mode,
                )
                .await
                {
                    Some(res) => res,
                    None => {
                        info!(
                            "IXFR for {qname} from {}: falling back to AXFR",
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
                            zone_walking_semaphore,
                            batcher_semaphore,
                            req,
                            qname,
                            &zone_soa_answer,
                            cat_zone.info(),
                            read,
                        )
                        .await
                    }
                }
            }

            _ => ControlFlow::Continue(()),
        }
    }

    fn is_allowed(
        req: &Request<RequestOctets>,
        qname: &Name<Bytes>,
        qtype: Rtype,
        zone_info: &ZoneInfo,
    ) -> bool {
        let client_ip = req.client_addr().ip();

        if qtype == Rtype::SOA {
            return true;
        }

        let ZoneType::Primary { allow_xfr, .. } = zone_info.zone_type()
        else {
            warn!(
                "{qtype} for {qname} from {client_ip} refused: zone does not allow XFR",
            );
            return false;
        };

        let Some((xfr_settings, _tsig_key)) =
            allow_xfr.get_ip(req.client_addr().ip())
        else {
            warn!(
                "{qtype} for {qname} from {client_ip} refused: client is not permitted to transfer this zone",
            );
            return false;
        };

        if matches!(
            (qtype, xfr_settings.strategy),
            (Rtype::AXFR, XfrStrategy::IxfrOnly)
                | (Rtype::IXFR, XfrStrategy::AxfrOnly)
        ) {
            warn!(
                "{qtype} for {qname} from {client_ip} refused: zone does not allow {qtype}",
            );
            return false;
        }

        true
    }

    async fn do_axfr(
        zone_walk_semaphore: Arc<Semaphore>,
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets>,
        qname: Name<Bytes>,
        zone_soa_answer: &Answer,
        zone_info: &ZoneInfo,
        read: Box<dyn ReadableZone>,
    ) -> ControlFlow<
        XfrMiddlewareStream<
            Svc::Future,
            Svc::Stream,
            <Svc::Stream as Stream>::Item,
        >,
    > {
        let msg = req.message();

        let AnswerContent::Data(zone_soa_rrset) =
            zone_soa_answer.content().clone()
        else {
            unreachable!()
        };

        let ZoneType::Primary { allow_xfr, .. } = zone_info.zone_type()
        else {
            unreachable!();
        };

        let Some((xfr_settings, _tsig_key)) =
            allow_xfr.get_ip(req.client_addr().ip())
        else {
            unreachable!();
        };

        let compatibility_mode = xfr_settings.compatibility_mode
            == CompatibilityMode::BackwardCompatible;

        if compatibility_mode {
            trace!(
                "Compatibility mode enabled for client with IP address {}",
                req.client_addr().ip()
            );
        }

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

        // Create a stream that will be immediately returned to the caller.
        // Async tasks will then push DNS response messages into the stream as
        // they become available.
        let (sender, receiver) = unbounded_channel();
        let stream = UnboundedReceiverStream::new(receiver);

        // Create a bounded queue for passing RRsets found during zone walking
        // to a task which will batch the RRs together before pushing them
        // into the result stream.
        let (batcher_tx, mut batcher_rx) =
            tokio::sync::mpsc::channel::<(StoredName, SharedRrset)>(100);

        // Notify the underlying transport to expect a stream of related
        // responses. The transport should modify its behaviour to account for
        // the potentially slow and long running nature of a transaction.
        Self::add_to_stream(
            CallResult::feedback_only(ServiceFeedback::BeginTransaction),
            &sender,
        );

        // Enqueue the zone SOA RRset for the batcher to process.
        batcher_tx
            .send((qname.clone(), zone_soa_rrset.clone()))
            .await
            .unwrap();

        // Stream the remaining non-SOA zone RRsets in the background to the
        // batcher.
        tokio::spawn(async move {
            // Limit the number of concurrently running XFR related zone
            // walking operations.
            let _ = zone_walk_semaphore.acquire().await.unwrap();

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
                    batcher_tx.send((qname, zone_soa_rrset)).await.unwrap();
                }
                false => {
                    tokio::task::spawn_blocking(move || {
                        read.walk(op);
                        if let Err(err) =
                            batcher_tx.blocking_send((qname, zone_soa_rrset))
                        {
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

        tokio::spawn(async move {
            // Limit the number of concurrently running XFR batching
            // operations.
            let _ = batcher_semaphore.acquire().await.unwrap();

            let qclass = msg.sole_question().unwrap().qclass();

            let (mut owner, mut zone_soa_rrset) =
                batcher_rx.recv().await.unwrap();
            assert_eq!(zone_soa_rrset.rtype(), Rtype::SOA);
            let saved_soa_rrset = zone_soa_rrset.clone();
            let mut soa_seen_count = 0;

            let mut current_rrset = zone_soa_rrset;
            let mut records_to_process = current_rrset.data();

            let mut batcher = RrBatcher::new(msg.clone());
            if compatibility_mode {
                batcher.set_limit(1);
            }

            // Loop until all of the RRsets sent by the zone walker have been
            // pushed into DNS response messages and sent into the result
            // stream.
            'outer: loop {
                // Loop over the RRset items being sent by the zone walker and
                // add as many of them as possible to the response being
                // built.

                let mut num_rrs_added = 0;
                let builder = 'inner: loop {
                    if records_to_process == saved_soa_rrset.data() {
                        soa_seen_count += 1;
                    }

                    for rr in records_to_process {
                        let res = batcher.push((
                            owner.clone(),
                            qclass,
                            current_rrset.ttl(),
                            rr,
                        ));

                        match res {
                            Ok(ControlFlow::Continue(())) => {
                                // Message still has space, keep going.
                                num_rrs_added += 1;
                            }

                            Ok(ControlFlow::Break(builder)) => {
                                // Message is full, send what we have so far.
                                break 'inner Some(builder);
                            }

                            Err(err) => {
                                error!("Internal error: Unable to add RR to AXFR response message: {err}");
                                break 'outer;
                            }
                        }
                    }

                    if soa_seen_count == 2 {
                        // This is our signal to stop, as the AXFR message
                        // starts and ends with the zone SOA.
                        break 'inner batcher.take();
                    } else {
                        // Fetch more RRsets to add to the message.
                        (owner, current_rrset) =
                            batcher_rx.recv().await.unwrap();
                        records_to_process = current_rrset.data();
                    }
                };

                // Send the message.
                if let Some(builder) = builder {
                    let mut additional = builder.additional();
                    Self::set_axfr_header(&msg, &mut additional);
                    let call_result = Ok(CallResult::new(additional));
                    let _ = sender.send(call_result); // TODO: Handle this Result.
                }

                if num_rrs_added < records_to_process.len() {
                    // Some RRs from the current RRset didn't fit in the last
                    // message, process these before fetching another RRset
                    // from the incoming queue.
                    records_to_process =
                        &current_rrset.data()[num_rrs_added..];
                } else if soa_seen_count == 2 {
                    break;
                } else {
                    // Fetch more RRsets to add to the message from the incoming queue.
                    let res = batcher_rx.recv().await;
                    if res.is_none() {
                        let mut additional =
                            mk_error_response(&msg, OptRcode::SERVFAIL);
                        Self::set_axfr_header(&msg, &mut additional);
                        let call_result = Ok(CallResult::new(additional));
                        let _ = sender.send(call_result); // TODO: Handle this Result.
                        break 'outer;
                    };
                    (owner, zone_soa_rrset) = res.unwrap();
                    records_to_process = zone_soa_rrset.data();
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
    #[allow(clippy::too_many_arguments)]
    async fn do_ixfr(
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets>,
        qname: Name<Bytes>,
        zone_soa_answer: &Answer,
        zone_info: &ZoneInfo,
        xfr_mode: XfrMode,
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
                                    batcher_semaphore,
                                    req,
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
    #[allow(clippy::too_many_arguments)]
    async fn compute_ixfr(
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets>,
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
                <Svc::Stream as Stream>::Item,
            >,
        >,
    > {
        let msg = req.message();

        let AnswerContent::Data(zone_soa_rrset) =
            zone_soa_answer.content().clone()
        else {
            unreachable!()
        };

        // Note: Unlike RFC 5936 for AXFR, neither RFC 1995 nor RFC 9103 say
        // anything about whether an IXFR response can consist of more than
        // one response message, but given the 2^16 byte maximum response size
        // of a TCP DNS message and the 2^16 maximum number of ANSWER RRs
        // allowed per DNS response, large zones may not fit in a single
        // response message and will have to be split into multiple response
        // messages.

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
            // The caller should fallback to an AXFR style response at this
            // point.
            return None;
        };

        // Create a stream that will be immediately returned to the caller.
        // Async tasks will then push DNS response messages into the stream as
        // they become available.
        let (sender, receiver) = unbounded_channel();
        let stream = UnboundedReceiverStream::new(receiver);

        // Notify the underlying transport to expect a stream of related
        // responses. The transport should modify its behaviour to account for
        // the potentially slow and long running nature of a transaction.
        Self::add_to_stream(
            CallResult::feedback_only(ServiceFeedback::BeginTransaction),
            &sender,
        );

        // Stream the IXFR diffs in the background
        let msg = msg.clone();
        tokio::spawn(async move {
            // Limit the number of concurrently running XFR batching
            // operations.
            let _ = batcher_semaphore.acquire().await.unwrap();

            // https://datatracker.ietf.org/doc/html/rfc1995#section-4
            // 4. Response Format
            //    ...
            //   "If incremental zone transfer is available, one or more
            //    difference sequences is returned.  The list of difference
            //    sequences is preceded and followed by a copy of the server's
            //    current version of the SOA.
            //
            //    Each difference sequence represents one update to the zone
            //    (one SOA serial change) consisting of deleted RRs and added
            //    RRs.  The first RR of the deleted RRs is the older SOA RR
            //    and the first RR of the added RRs is the newer SOA RR.
            //
            //    Modification of an RR is performed first by removing the
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

            let (owner, qclass) = {
                let q = msg.first_question().unwrap();
                (q.qname().to_name::<Bytes>(), q.qclass())
            };

            let diff_sequences = diffs
                .iter()
                .flat_map(|diff| {
                    // https://datatracker.ietf.org/doc/html/rfc1995#section-4
                    // 4. Response Format
                    //    "Each difference sequence represents one update to the zone
                    //    (one SOA serial change) consisting of deleted RRs and added
                    //    RRs.  The first RR of the deleted RRs is the older SOA RR
                    //    and the first RR of the added RRs is the newer SOA RR.
                    let deleted = diff.removed.get(&qname).unwrap();
                    let added = diff.added.get(&qname).unwrap();

                    let mut rrset_iters: std::vec::Vec<
                        Box<dyn Iterator<Item = SharedRrset>>,
                    > = vec![];

                    for rrsets in [deleted, added] {
                        rrset_iters.push(Box::new(std::iter::once(
                            rrsets
                                .iter()
                                .find(|rrset| rrset.rtype() == Rtype::SOA)
                                .unwrap()
                                .clone(),
                        )));

                        rrset_iters.push(Box::new(
                            rrsets
                                .iter()
                                .filter(|rrset| rrset.rtype() != Rtype::SOA)
                                .cloned(),
                        ));
                    }

                    rrset_iters
                })
                .flatten();

            let rrsets = std::iter::once(zone_soa_rrset.clone())
                .chain(diff_sequences)
                .chain(std::iter::once(zone_soa_rrset.clone()));

            let mut batcher = RrBatcher::new(msg.clone());

            // Loop until all of the RRsets in the diffs have been pushed into
            // DNS response messages and sent into the result stream.
            let mut records_to_process;
            let mut num_rrs_added;

            for rrset in rrsets {
                records_to_process = rrset.data();
                num_rrs_added = 0;

                'outer: while !records_to_process.is_empty() {
                    let builder = 'inner: loop {
                        for rr in records_to_process {
                            match batcher.push((
                                owner.clone(),
                                qclass,
                                rrset.ttl(),
                                rr,
                            )) {
                                Ok(ControlFlow::Continue(())) => {
                                    // Message still has space, keep going.
                                    num_rrs_added += 1;
                                }

                                Ok(ControlFlow::Break(builder)) => {
                                    // Message is full, send what we have so far.
                                    break 'inner builder;
                                }

                                Err(err) => {
                                    error!("Internal error: Unable to add RR to AXFR response message: {err}");
                                    let mut additional = mk_error_response(
                                        &msg,
                                        OptRcode::SERVFAIL,
                                    );
                                    Self::set_axfr_header(
                                        &msg,
                                        &mut additional,
                                    );
                                    let call_result =
                                        Ok(CallResult::new(additional));
                                    let _ = sender.send(call_result); // TODO: Handle this Result.
                                    break 'outer;
                                }
                            }
                        }
                    };

                    let mut additional = builder.additional();
                    Self::set_axfr_header(&msg, &mut additional);
                    let call_result = Ok(CallResult::new(additional));
                    let _ = sender.send(call_result); // TODO: Handle this Result.

                    records_to_process = &rrset.data()[num_rrs_added..];
                }
            }

            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::EndTransaction),
                &sender,
            );
        });

        Some(ControlFlow::Break(MiddlewareStream::Result(stream)))
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

        // Note: MandatoryMiddlewareSvc will also "fix" ID and QR, so strictly
        // speaking this isn't necessary, but as a caller might not use
        // MandatoryMiddlewareSvc we do it anyway to try harder to conform to
        // the RFC.
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
        let zone_walking_semaphore = self.zone_walking_semaphore.clone();
        let batcher_semaphore = self.batcher_semaphore.clone();
        let xfr_mode = self.xfr_mode;
        Box::pin(async move {
            match Self::preprocess(
                zone_walking_semaphore,
                batcher_semaphore,
                &request,
                catalog,
                xfr_mode,
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

//----------- RrBatcher -------------------------------------------------------

// IDEA: Maybe this should act like an iterator and whenever it runs out of
// items to process one should feed it more? And pass it RRsets instead of
// Records.

struct RrBatcher<RequestOctets, Target> {
    req_msg: Arc<Message<RequestOctets>>,
    limit: Option<u16>,
    answer: Option<Result<AnswerBuilder<StreamTarget<Target>>, PushError>>,
}

impl<RequestOctets, Target> RrBatcher<RequestOctets, Target>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    pub fn new(req_msg: Arc<Message<RequestOctets>>) -> Self {
        Self {
            req_msg,
            limit: None,
            answer: None,
        }
    }

    pub fn set_limit(&mut self, limit: u16) {
        self.limit = Some(limit);
    }

    pub fn push(
        &mut self,
        record: impl ComposeRecord,
    ) -> Result<ControlFlow<AnswerBuilder<StreamTarget<Target>>>, PushError>
    {
        self.answer.get_or_insert_with(|| {
            let builder = mk_builder_for_target();
            builder.start_answer(&self.req_msg, Rcode::NOERROR)
        });

        let mut answer = self.answer.take().unwrap()?;

        let res = answer.push(record);
        let arcount = answer.counts().arcount();

        match res {
            Ok(()) if Some(arcount) == self.limit => {
                // Message is as full as the caller allows, pass it back to
                // the caller to process.
                Ok(ControlFlow::Break(answer))
            }

            Err(_) if arcount > 0 => {
                // Message is full, pass it back to the caller to process.
                Ok(ControlFlow::Break(answer))
            }

            Err(err) => {
                // We expect to be able to add at least one answer to the message.
                Err(err)
            }

            Ok(()) => {
                // Record has been added, keep the answer builder for the next push.
                self.answer = Some(Ok(answer));
                Ok(ControlFlow::Continue(()))
            }
        }
    }

    pub fn take(&mut self) -> Option<AnswerBuilder<StreamTarget<Target>>> {
        self.answer.take().and_then(|res| res.ok())
    }
}
