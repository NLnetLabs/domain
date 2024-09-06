//! XFR request handling middleware.

use core::future::{ready, Future, Ready};
use core::marker::PhantomData;
use core::ops::{ControlFlow, Deref};

use std::boxed::Box;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;

use bytes::Bytes;
use futures::stream::{once, Once, Stream};
use octseq::Octets;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::Semaphore;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{error, info, trace, warn};

use crate::base::iana::{Class, Opcode, OptRcode, Rcode};
use crate::base::message_builder::{
    AdditionalBuilder, AnswerBuilder, PushError,
};
use crate::base::wire::Composer;
use crate::base::{
    Message, Name, ParsedName, Question, Rtype, Serial, StreamTarget, ToName,
};
use crate::net::server::batcher::{
    CallbackBatcher, Callbacks, ResourceRecordBatcher,
};
use crate::net::server::message::{Request, TransportSpecificContext};
use crate::net::server::middleware::stream::MiddlewareStream;
use crate::net::server::service::{
    CallResult, Service, ServiceFeedback, ServiceResult,
};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::{Soa, ZoneRecordData};
use crate::zonetree::error::OutOfZone;
use crate::zonetree::{
    Answer, AnswerContent, ReadableZone, SharedRrset, StoredName, Zone,
    ZoneDiff, ZoneTree,
};

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
pub struct XfrMiddlewareSvc<RequestOctets, NextSvc, XDP> {
    next_svc: NextSvc,

    xfr_data_provider: XDP,

    zone_walking_semaphore: Arc<Semaphore>,

    batcher_semaphore: Arc<Semaphore>,

    _phantom: PhantomData<RequestOctets>,
}

impl<RequestOctets, NextSvc, XDP>
    XfrMiddlewareSvc<RequestOctets, NextSvc, XDP>
where
    XDP: XfrDataProvider,
{
    /// Creates a new processor instance.
    #[must_use]
    pub fn new(
        next_svc: NextSvc,
        xfr_data_provider: XDP,
        max_concurrency: usize,
    ) -> Self {
        let zone_walking_semaphore =
            Arc::new(Semaphore::new(max_concurrency));
        let batcher_semaphore = Arc::new(Semaphore::new(max_concurrency));

        Self {
            next_svc,
            xfr_data_provider,
            zone_walking_semaphore,
            batcher_semaphore,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOctets, NextSvc, XDP>
    XfrMiddlewareSvc<RequestOctets, NextSvc, XDP>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc: Service<RequestOctets, ()> + Clone + Send + Sync + 'static,
    NextSvc::Future: Send + Sync + Unpin,
    NextSvc::Target: Composer + Default + Send + Sync,
    NextSvc::Stream: Send + Sync,
    XDP: XfrDataProvider,
{
    pub async fn preprocess<T>(
        zone_walking_semaphore: Arc<Semaphore>,
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, T>,
        xfr_data_provider: XDP,
    ) -> ControlFlow<
        XfrMiddlewareStream<
            NextSvc::Future,
            NextSvc::Stream,
            <NextSvc::Stream as Stream>::Item,
        >,
    > {
        let msg = req.message();

        // Do we support this type of request?
        let Some(q) = Self::get_relevant_question(msg) else {
            return ControlFlow::Continue(());
        };

        // https://datatracker.ietf.org/doc/html/rfc1995#section-3
        // 3. Query Format
        //   "The IXFR query packet format is the same as that of a normal DNS
        //    query, but with the query type being IXFR and the authority
        //    section containing the SOA record of client's version of the
        //    zone."
        let ixfr_query_serial = if let Ok(Some(Ok(query_soa))) = msg
            .authority()
            .map(|section| section.limit_to::<Soa<ParsedName<_>>>().next())
        {
            Some(query_soa.data().serial())
        } else {
            None
        };

        if q.qtype() == Rtype::IXFR && ixfr_query_serial.is_none() {
            return Self::log_and_break(
                &q,
                req,
                msg,
                OptRcode::FORMERR,
                "IXFR request lacks authority section SOA",
            );
        }

        // Is transfer allowed for the requested zone for this requestor?
        let res = xfr_data_provider
            .request(req, q.qname(), q.qclass(), ixfr_query_serial)
            .await
            .map_err(|err| match err {
                XfrDataProviderError::UnknownZone => {
                    // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2.1
                    // 2.2.1 Header Values
                    //   "If a server is not authoritative for the queried
                    //    zone, the server SHOULD set the value to NotAuth(9)"
                    ("unknown zone", OptRcode::NOTAUTH)
                }

                XfrDataProviderError::TemporarilyUnavailable => {
                    // The zone is not yet loaded or has expired, both of
                    // which are presumably transient conditions and thus
                    // SERVFAIL is the appropriate response, not NOTAUTH, as
                    // we know we are supposed to be authoritative for the
                    // zone but we just don't have the data right now.
                    ("zone not currently available", OptRcode::SERVFAIL)
                }

                XfrDataProviderError::Refused => {
                    ("access denied", OptRcode::REFUSED)
                }
            })
            .map_err(|(reason, rcode)| {
                Self::log_and_break(&q, req, msg, rcode, reason)
            });

        let Ok((zone, diffs)) = res else {
            return res.unwrap_err();
        };

        // Read the zone SOA RR
        let read = zone.read();
        let Ok(zone_soa_answer) =
            Self::read_soa(&read, q.qname().to_name()).await
        else {
            return Self::log_and_break(
                &q,
                req,
                msg,
                OptRcode::SERVFAIL,
                "name is outside the zone",
            );
        };

        match q.qtype() {
            Rtype::AXFR if req.transport_ctx().is_udp() => {
                // https://datatracker.ietf.org/doc/html/rfc5936#section-4.2
                // 4.2.  UDP
                //   "With the addition of EDNS0 and applications that require
                //    many small zones, such as in web hosting and some ENUM
                //    scenarios, AXFR sessions on UDP would now seem
                //    desirable.  However, there are still some aspects of
                //    AXFR sessions that are not easily translated to UDP.
                //
                //    Therefore, this document does not update RFC 1035 in
                //    this respect: AXFR sessions over UDP transport are not
                //    defined."
                Self::log_and_break(
                    &q,
                    req,
                    msg,
                    OptRcode::NOTIMP,
                    "AXFR not suppored over UDP",
                )
            }

            Rtype::AXFR | Rtype::IXFR if diffs.is_empty() => {
                if q.qtype() == Rtype::IXFR && diffs.is_empty() {
                    // https://datatracker.ietf.org/doc/html/rfc1995#section-4
                    // 4. Response Format
                    //    "If incremental zone transfer is not available, the
                    //     entire zone is returned.  The first and the last RR of
                    //     the response is the SOA record of the zone. I.e. the
                    //     behavior is the same as an AXFR response except the
                    //     query type is IXFR."
                    info!(
                        "IXFR for {} from {}: diffs not available, falling back to AXFR",
                        q.qname(),
                        req.client_addr()
                    );
                } else {
                    info!(
                        "AXFR for {} from {}",
                        q.qname(),
                        req.client_addr()
                    );
                }
                let stream = Self::do_axfr(
                    zone_walking_semaphore,
                    batcher_semaphore,
                    req,
                    q.qname().to_name(),
                    &zone_soa_answer,
                    read,
                )
                .await
                .unwrap_or_else(|rcode| {
                    Self::to_stream(mk_error_response(msg, rcode))
                });

                ControlFlow::Break(stream)
            }

            Rtype::IXFR => {
                let ixfr_query_serial = ixfr_query_serial.unwrap();
                info!(
                    "IXFR for {} (serial {ixfr_query_serial}) from {}",
                    q.qname(),
                    req.client_addr()
                );

                // https://datatracker.ietf.org/doc/html/rfc1995#section-2
                // 2. Brief Description of the Protocol
                //   "Transport of a query may be by either UDP or TCP.  If an
                //    IXFR query is via UDP, the IXFR server may attempt to
                //    reply using UDP if the entire response can be contained
                //    in a single DNS packet.  If the UDP reply does not fit,
                //    the query is responded to with a single SOA record of
                //    the server's current version to inform the client that a
                //    TCP query should be initiated."
                let stream = Self::do_ixfr(
                    batcher_semaphore.clone(),
                    req,
                    ixfr_query_serial,
                    &zone_soa_answer,
                    diffs,
                )
                .await
                .unwrap_or_else(|rcode| {
                    Self::to_stream(mk_error_response(msg, rcode))
                });

                ControlFlow::Break(stream)
            }

            _ => ControlFlow::Continue(()),
        }
    }

    #[allow(clippy::type_complexity)]
    fn log_and_break<T>(
        q: &Question<ParsedName<<RequestOctets as Octets>::Range<'_>>>,
        req: &Request<RequestOctets, T>,
        msg: &Message<RequestOctets>,
        rcode: OptRcode,
        reason: &'static str,
    ) -> ControlFlow<
        XfrMiddlewareStream<
            NextSvc::Future,
            NextSvc::Stream,
            <NextSvc::Stream as Stream>::Item,
        >,
    > {
        warn!(
            "{} for {} from {} refused: {reason}",
            q.qtype(),
            q.qname(),
            req.client_addr()
        );
        ControlFlow::Break(Self::to_stream(mk_error_response(msg, rcode)))
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_axfr<T>(
        zone_walk_semaphore: Arc<Semaphore>,
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, T>,
        qname: StoredName,
        zone_soa_answer: &Answer,
        read: Box<dyn ReadableZone>,
    ) -> Result<
        XfrMiddlewareStream<
            NextSvc::Future,
            NextSvc::Stream,
            <NextSvc::Stream as Stream>::Item,
        >,
        OptRcode,
    > {
        let msg = req.message();

        let AnswerContent::Data(zone_soa_rrset) =
            zone_soa_answer.content().clone()
        else {
            error!(
                "AXFR for {qname} from {} refused: zone lacks SOA RR",
                req.client_addr()
            );
            return Err(OptRcode::SERVFAIL);
        };

        // TODO
        // let compatibility_mode = xfr_config.compatibility_mode
        //     == CompatibilityMode::BackwardCompatible;
        let compatibility_mode = false;

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
        if batcher_tx
            .send((qname.clone(), zone_soa_rrset.clone()))
            .await
            .is_err()
        {
            return Err(OptRcode::SERVFAIL);
        }

        // Stream the remaining non-SOA zone RRsets in the background to the
        // batcher.
        tokio::spawn(async move {
            // Limit the number of concurrently running XFR related zone
            // walking operations.
            if zone_walk_semaphore.acquire().await.is_err() {
                error!("Internal error: Failed to acquire XFR zone walking semaphore");
                return;
            }

            let cloned_batcher_tx = batcher_tx.clone();
            let op =
                Box::new(move |owner: StoredName, rrset: &SharedRrset| {
                    if rrset.rtype() != Rtype::SOA {
                        let _ = cloned_batcher_tx
                            .blocking_send((owner.clone(), rrset.clone()));
                        // If the blocking send fails it means that he batcher
                        // is no longer available. This can happen if it was
                        // no longer able to pass messages back to the
                        // underlying transport, which can happen if the
                        // client closed the connection. We don't log this
                        // because we can't stop the tree walk and so will
                        // keep hitting this error until the tree walk is
                        // complete, causing a lot of noise if we were to log
                        // this.
                    }
                });

            // Walk the zone tree, invoking our operation for each leaf.
            match read.is_async() {
                true => {
                    read.walk_async(op).await;
                    if let Err(err) =
                        batcher_tx.send((qname, zone_soa_rrset)).await
                    {
                        error!("Internal error: Failed to send final AXFR SOA to batcher: {err}");
                    }
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

        // Combine RRsets enumerated by zone walking as many as possible per
        // DNS response message and pass the created messages downstream to
        // the caller.
        let msg = msg.clone();
        let soft_byte_limit = Self::calc_msg_bytes_available(req);

        tokio::spawn(async move {
            // Limit the number of concurrently running XFR batching
            // operations.
            if batcher_semaphore.acquire().await.is_err() {
                error!(
                    "Internal error: Failed to acquire XFR batcher semaphore"
                );
                return;
            }

            let Ok(qclass) = msg.sole_question().map(|q| q.qclass()) else {
                unreachable!();
            };

            // Note: NSD apparently uses name compresson on AXFR responses
            // because AXFR responses they typically contain lots of
            // alphabetically ordered duplicate names which compress well. NSD
            // limits AXFR responses to 16,383 RRs because DNS name
            // compression uses a 14-bit offset (2^14-1=16383) from the start
            // of the message to the first occurence of a name instead of
            // repeating the name, and name compression is less effective
            // over 16383 bytes. (Credit: Wouter Wijngaards)
            //
            // TODO: Once we start supporting name compression in responses decide
            // if we want to behave the same way.

            let hard_rr_limit = match compatibility_mode {
                true => Some(1),
                false => None,
            };

            let mut batcher = XfrRrBatcher::build(
                msg.clone(),
                sender.clone(),
                Some(soft_byte_limit),
                hard_rr_limit,
            );

            while let Some((owner, rrset)) = batcher_rx.recv().await {
                for rr in rrset.data() {
                    if batcher
                        .push((owner.clone(), qclass, rrset.ttl(), rr))
                        .is_err()
                    {
                        error!("Internal error: Failed to send RR to batcher");
                        let resp =
                            mk_error_response(&msg, OptRcode::SERVFAIL);
                        Self::add_to_stream(CallResult::new(resp), &sender);
                        batcher_rx.close();
                        return;
                    }
                }
            }

            batcher.finish().unwrap(); // TODO

            trace!("Finishing transaction");
            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::EndTransaction),
                &sender,
            );

            batcher_rx.close();
        });

        Ok(MiddlewareStream::Result(stream))
    }

    // Returns None if fallback to AXFR should be done.
    #[allow(clippy::too_many_arguments)]
    async fn do_ixfr<T>(
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, T>,
        query_serial: Serial,
        zone_soa_answer: &Answer,
        diffs: Vec<Arc<ZoneDiff>>,
    ) -> Result<
        XfrMiddlewareStream<
            NextSvc::Future,
            NextSvc::Stream,
            <NextSvc::Stream as Stream>::Item,
        >,
        OptRcode,
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
        if let AnswerContent::Data(rrset) = zone_soa_answer.content() {
            if rrset.data().len() == 1 {
                if let ZoneRecordData::Soa(soa) =
                    rrset.first().unwrap().data()
                {
                    let zone_serial = soa.serial();

                    // TODO: if cached then return cached IXFR response
                    return Self::compute_ixfr(
                        batcher_semaphore,
                        req,
                        query_serial,
                        zone_serial,
                        zone_soa_answer,
                        diffs,
                    )
                    .await;
                }
            }
        }

        Err(OptRcode::SERVFAIL)
    }

    #[allow(clippy::too_many_arguments)]
    async fn compute_ixfr<T>(
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, T>,
        query_serial: Serial,
        zone_serial: Serial,
        zone_soa_answer: &Answer,
        diffs: Vec<Arc<ZoneDiff>>,
    ) -> Result<
        XfrMiddlewareStream<
            NextSvc::Future,
            NextSvc::Stream,
            <NextSvc::Stream as Stream>::Item,
        >,
        OptRcode,
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
            return Ok(Self::to_stream(response));
        }

        // Get the necessary diffs, if available
        // let start_serial = query_serial;
        // let end_serial = zone_serial;
        // let diffs = zone_info.diffs_for_range(start_serial, end_serial).await;
        // if diffs.is_empty() {
        //     trace!("No diff available for IXFR");
        //     return IxfrResult::FallbackToAxfr;
        // };

        // TODO: Add something like the Bind `max-ixfr-ratio` option that
        // "sets the size threshold (expressed as a percentage of the size of
        // the full zone) beyond which named chooses to use an AXFR response
        // rather than IXFR when answering zone transfer requests"?

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
        let soft_byte_limit = Self::calc_msg_bytes_available(req);

        tokio::spawn(async move {
            // Limit the number of concurrently running XFR batching
            // operations.
            if batcher_semaphore.acquire().await.is_err() {
                error!(
                    "Internal error: Failed to acquire XFR batcher semaphore"
                );
                return;
            }

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
                let Ok(q) = msg.sole_question() else {
                    unreachable!();
                };
                (q.qname().to_name::<Bytes>(), q.qclass())
            };

            let mut batcher = XfrRrBatcher::build(
                msg.clone(),
                sender.clone(),
                Some(soft_byte_limit),
                None,
            );

            batcher
                .push((
                    owner.clone(),
                    qclass,
                    zone_soa_rrset.ttl(),
                    &zone_soa_rrset.data()[0],
                ))
                .unwrap(); // TODO

            for diff in diffs {
                // 4. Response Format
                //    "Each difference sequence represents one update to the
                //    zone (one SOA serial change) consisting of deleted RRs
                //    and added RRs.  The first RR of the deleted RRs is the
                //    older SOA RR and the first RR of the added RRs is the
                //    newer SOA RR.
                let soa_k = &(owner.clone(), Rtype::SOA);
                let removed_soa = diff.removed.get(soa_k).unwrap(); // The zone MUST have a SOA record
                batcher
                    .push((
                        owner.clone(),
                        qclass,
                        removed_soa.ttl(),
                        &removed_soa.data()[0],
                    ))
                    .unwrap(); // TODO

                diff.removed.iter().for_each(|((owner, rtype), rrset)| {
                    if *rtype != Rtype::SOA {
                        for rr in rrset.data() {
                            batcher
                                .push((
                                    owner.clone(),
                                    qclass,
                                    rrset.ttl(),
                                    rr,
                                ))
                                .unwrap(); // TODO
                        }
                    }
                });

                let added_soa = diff.added.get(soa_k).unwrap(); // The zone MUST have a SOA record
                batcher
                    .push((
                        owner.clone(),
                        qclass,
                        added_soa.ttl(),
                        &added_soa.data()[0],
                    ))
                    .unwrap(); // TODO

                diff.added.iter().for_each(|((owner, rtype), rrset)| {
                    if *rtype != Rtype::SOA {
                        for rr in rrset.data() {
                            batcher
                                .push((
                                    owner.clone(),
                                    qclass,
                                    rrset.ttl(),
                                    rr,
                                ))
                                .unwrap(); // TODO
                        }
                    }
                });
            }

            batcher
                .push((
                    owner,
                    qclass,
                    zone_soa_rrset.ttl(),
                    &zone_soa_rrset.data()[0],
                ))
                .unwrap(); // TODO

            batcher.finish().unwrap(); // TODO

            trace!("Ending transaction");
            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::EndTransaction),
                &sender,
            );
        });

        Ok(MiddlewareStream::Result(stream))
    }

    fn add_to_stream(
        call_result: CallResult<NextSvc::Target>,
        sender: &UnboundedSender<ServiceResult<NextSvc::Target>>,
    ) {
        sender.send(Ok(call_result)).unwrap(); // TODO: Handle this Result
    }

    fn to_stream(
        response: AdditionalBuilder<StreamTarget<NextSvc::Target>>,
    ) -> XfrMiddlewareStream<
        NextSvc::Future,
        NextSvc::Stream,
        <NextSvc::Stream as Stream>::Item,
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
            if let Ok(q) = msg.sole_question() {
                if matches!(q.qtype(), Rtype::AXFR | Rtype::IXFR) {
                    return Some(q);
                }
            }
        }

        None
    }

    fn calc_msg_bytes_available<T>(req: &Request<RequestOctets, T>) -> usize {
        let bytes_available = match req.transport_ctx() {
            TransportSpecificContext::Udp(ctx) => {
                let max_msg_size =
                    ctx.max_response_size_hint().unwrap_or(512);
                max_msg_size - req.num_reserved_bytes()
            }
            TransportSpecificContext::NonUdp(_) => {
                65535 - req.num_reserved_bytes()
            }
        };

        bytes_available as usize
    }
}

//--- impl Service

impl<RequestOctets, NextSvc, XDP, Metadata> Service<RequestOctets, Metadata>
    for XfrMiddlewareSvc<RequestOctets, NextSvc, XDP>
where
    RequestOctets: Octets + Send + Sync + Unpin + 'static,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc: Service<RequestOctets, ()> + Clone + Send + Sync + 'static,
    NextSvc::Future: Send + Sync + Unpin,
    NextSvc::Target: Composer + Default + Send + Sync,
    NextSvc::Stream: Send + Sync,
    XDP: XfrDataProvider + Clone + Sync + Send + 'static,
    Metadata: Clone + Default + Sync + Send + 'static,
{
    type Target = NextSvc::Target;
    type Stream = XfrMiddlewareStream<
        NextSvc::Future,
        NextSvc::Stream,
        <NextSvc::Stream as Stream>::Item,
    >;
    type Future = Pin<Box<dyn Future<Output = Self::Stream> + Send + Sync>>;

    fn call(
        &self,
        request: Request<RequestOctets, Metadata>,
    ) -> Self::Future {
        let request = request.clone();
        let next_svc = self.next_svc.clone();
        let xfr_data_provider = self.xfr_data_provider.clone();
        let zone_walking_semaphore = self.zone_walking_semaphore.clone();
        let batcher_semaphore = self.batcher_semaphore.clone();
        Box::pin(async move {
            match Self::preprocess(
                zone_walking_semaphore,
                batcher_semaphore,
                &request,
                xfr_data_provider,
            )
            .await
            {
                ControlFlow::Continue(()) => {
                    let request = request.with_new_metadata(());
                    let stream = next_svc.call(request).await;
                    MiddlewareStream::IdentityStream(stream)
                }
                ControlFlow::Break(stream) => stream,
            }
        })
    }
}

//------------ XfrMapStream ---------------------------------------------------

pub type XfrResultStream<StreamItem> = UnboundedReceiverStream<StreamItem>;

//------------ XfrMiddlewareStream --------------------------------------------

pub type XfrMiddlewareStream<Future, Stream, StreamItem> = MiddlewareStream<
    Future,
    Stream,
    Once<Ready<StreamItem>>,
    XfrResultStream<StreamItem>,
    StreamItem,
>;

//------------ XfrMode --------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum XfrMode {
    AxfrAndIxfr,
    AxfrOnly,
}

//------------ XfrDataProviderError -------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum XfrDataProviderError {
    UnknownZone,

    Refused,

    TemporarilyUnavailable,
}

//------------ Transferable ---------------------------------------------------

/// A provider of data needed for responding to XFR requests.
pub trait XfrDataProvider {
    /// Request data needed to respond to an XFR request.
    ///
    /// Returns Ok if the request is allowed and the requested data is
    /// available.
    ///
    /// Returns Err otherwise.
    #[allow(clippy::type_complexity)]
    fn request<Octs, Metadata>(
        &self,
        req: &Request<Octs, Metadata>,
        apex_name: &impl ToName,
        class: Class,
        diff_to: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (Zone, Vec<Arc<ZoneDiff>>),
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send,
        >,
    >
    where
        Octs: AsRef<[u8]> + Send + Sync;
}

//--- impl for AsRef

impl<T, U> XfrDataProvider for U
where
    T: XfrDataProvider,
    U: Deref<Target = T>,
{
    fn request<Octs, Metadata>(
        &self,
        req: &Request<Octs, Metadata>,
        apex_name: &impl ToName,
        class: Class,
        diff_to: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (Zone, Vec<Arc<ZoneDiff>>),
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send,
        >,
    >
    where
        Octs: AsRef<[u8]> + Send + Sync,
    {
        (**self).request(req, apex_name, class, diff_to)
    }
}

//--- impl for Zone

impl XfrDataProvider for Zone {
    /// Request data needed to respond to an XFR request.
    ///
    /// Returns Ok(Self, vec![]) if the given apex name and class match this
    /// zone, irrespective of the given request or diff range.
    ///
    /// Returns Err if the requested zone is not this zone.
    fn request<Octs, Metadata>(
        &self,
        _req: &Request<Octs, Metadata>,
        apex_name: &impl ToName,
        class: Class,
        _diff_to: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (Zone, Vec<Arc<ZoneDiff>>),
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send,
        >,
    >
    where
        Octs: AsRef<[u8]> + Send + Sync,
    {
        let res = if apex_name.to_name::<Bytes>() == self.apex_name()
            && class == self.class()
        {
            Ok((self.clone(), vec![]))
        } else {
            Err(XfrDataProviderError::UnknownZone)
        };

        Box::pin(ready(res))
    }
}

//--- impl for ZoneTree

impl XfrDataProvider for ZoneTree {
    /// Request data needed to respond to an XFR request.
    ///
    /// Returns Ok(zone, vec![]) if the given apex name and class match a zone
    /// in this zone tree, irrespective of the given request or diff range.
    ///
    /// Returns Err if the requested zone is not this zone tree.
    fn request<Octs, Metadata>(
        &self,
        _req: &Request<Octs, Metadata>,
        apex_name: &impl ToName,
        class: Class,
        _diff_to: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (Zone, Vec<Arc<ZoneDiff>>),
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send,
        >,
    >
    where
        Octs: AsRef<[u8]> + Send + Sync,
    {
        let res = if let Some(zone) = self.get_zone(apex_name, class) {
            Ok((zone.clone(), vec![]))
        } else {
            Err(XfrDataProviderError::UnknownZone)
        };

        Box::pin(ready(res))
    }
}

//------------ XfrRrBatcher ---------------------------------------------------

pub struct XfrRrBatcher<RequestOctets, Target> {
    _phantom: PhantomData<(RequestOctets, Target)>,
}

impl<RequestOctets, Target> XfrRrBatcher<RequestOctets, Target>
where
    RequestOctets: Octets + Sync + Send + 'static,
    Target: Composer + Default + Send + 'static,
{
    pub fn build(
        req_msg: Arc<Message<RequestOctets>>,
        sender: UnboundedSender<ServiceResult<Target>>,
        soft_byte_limit: Option<usize>,
        hard_rr_limit: Option<u16>,
    ) -> impl ResourceRecordBatcher<RequestOctets, Target> {
        let cb_state = CallbackState::new(
            req_msg.clone(),
            sender,
            soft_byte_limit,
            hard_rr_limit,
        );

        CallbackBatcher::<
            RequestOctets,
            Target,
            Self,
            CallbackState<RequestOctets, Target>,
        >::new(req_msg, cb_state)
    }
}

impl<RequestOctets, Target> XfrRrBatcher<RequestOctets, Target>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    fn set_axfr_header(
        msg: &Message<RequestOctets>,
        additional: &mut AdditionalBuilder<StreamTarget<Target>>,
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
}

//--- Callbacks

impl<RequestOctets, Target>
    Callbacks<RequestOctets, Target, CallbackState<RequestOctets, Target>>
    for XfrRrBatcher<RequestOctets, Target>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    fn batch_started(
        cb_state: &CallbackState<RequestOctets, Target>,
        msg: &Message<RequestOctets>,
    ) -> Result<AnswerBuilder<StreamTarget<Target>>, PushError> {
        let mut builder = mk_builder_for_target();
        if let Some(limit) = cb_state.soft_byte_limit {
            builder.set_push_limit(limit);
        }
        let answer = builder.start_answer(msg, Rcode::NOERROR)?;
        Ok(answer)
    }

    fn batch_ready(
        cb_state: &CallbackState<RequestOctets, Target>,
        builder: AnswerBuilder<StreamTarget<Target>>,
    ) -> Result<(), ()> {
        trace!("Sending RR batch");
        let mut additional = builder.additional();
        Self::set_axfr_header(&cb_state.req_msg, &mut additional);
        let call_result = Ok(CallResult::new(additional));
        cb_state.sender.send(call_result).map_err(|err| {
            warn!("Internal error: Send from RR batcher failed: {err}");
        })
    }

    fn record_pushed(
        cb_state: &CallbackState<RequestOctets, Target>,
        answer: &AnswerBuilder<StreamTarget<Target>>,
    ) -> bool {
        if let Some(hard_rr_limit) = cb_state.hard_rr_limit {
            let ancount = answer.counts().ancount();
            let limit_reached = ancount == hard_rr_limit;
            trace!(
                "ancount={ancount}, hard_rr_limit={hard_rr_limit}, limit_reached={limit_reached}");
            limit_reached
        } else {
            false
        }
    }
}

//------------ CallbackState --------------------------------------------------

struct CallbackState<RequestOctets, Target> {
    req_msg: Arc<Message<RequestOctets>>,
    sender: UnboundedSender<ServiceResult<Target>>,
    soft_byte_limit: Option<usize>,
    hard_rr_limit: Option<u16>,
}

impl<RequestOctets, Target> CallbackState<RequestOctets, Target> {
    fn new(
        req_msg: Arc<Message<RequestOctets>>,
        sender: UnboundedSender<ServiceResult<Target>>,
        soft_byte_limit: Option<usize>,
        hard_rr_limit: Option<u16>,
    ) -> Self {
        Self {
            req_msg,
            sender,
            soft_byte_limit,
            hard_rr_limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;

    use std::borrow::ToOwned;

    use futures::StreamExt;
    use tokio::time::Instant;

    use crate::base::{MessageBuilder, RecordData, Ttl};
    use crate::net::server::message::NonUdpTransportContext;
    use crate::net::server::service::ServiceError;
    use crate::rdata::{Aaaa, AllRecordData, Cname, Mx, Ns, A};
    use crate::zonefile::inplace::Zonefile;

    use super::*;

    type ExpectedRecords =
        Vec<(Name<Bytes>, AllRecordData<Bytes, Name<Bytes>>)>;

    #[tokio::test]
    async fn axfr_with_example_zone() {
        let mut expected_records: ExpectedRecords = vec![
            (n("example.com"), Ns::new(n("example.com")).into()),
            (n("example.com"), A::new(p("192.0.2.1")).into()),
            (n("example.com"), A::new(p("192.0.2.1")).into()),
            (n("example.com"), A::new(p("192.0.2.1")).into()),
            (n("example.com"), Aaaa::new(p("2001:db8::3")).into()),
            (n("www.example.com"), Cname::new(n("example.com")).into()),
            (n("mail.example.com"), Mx::new(10, n("example.com")).into()),
        ];

        let zone = load_zone(include_bytes!(
            "../../../../test-data/zonefiles/nsd-example.txt"
        ));

        let req = mk_axfr_request(zone.apex_name(), ());

        let mut stream = do_axfr_for_zone(&zone, &req).await.unwrap();

        assert_xfr_stream_eq(
            req.message(),
            &zone,
            &mut stream,
            &mut expected_records,
        )
        .await;
    }

    // #[tokio::test]
    // async fn axfr_with_tsig() {
    //     let metadata = Authentication(Some(
    //         KeyName::from_str("blah").unwrap(),
    //     ))

    //     let req = mk_axfr_request("example.com", metadata);
    // }

    //------------ Helper functions -------------------------------------------

    fn n(name: &str) -> Name<Bytes> {
        Name::from_str(name).unwrap()
    }

    fn p<T: FromStr>(txt: &str) -> T
    where
        <T as FromStr>::Err: std::fmt::Debug,
    {
        txt.parse().unwrap()
    }

    fn load_zone(bytes: &[u8]) -> Zone {
        let mut zone_bytes = std::io::BufReader::new(bytes);
        let reader = Zonefile::load(&mut zone_bytes).unwrap();
        Zone::try_from(reader).unwrap()
    }

    fn mk_axfr_request<T>(
        qname: impl ToName,
        metadata: T,
    ) -> Request<Vec<u8>, T> {
        let client_addr = "127.0.0.1:12345".parse().unwrap();
        let received_at = Instant::now();
        let msg = MessageBuilder::new_vec();
        let mut msg = msg.question();
        msg.push((qname, Rtype::AXFR)).unwrap();
        let msg = msg.into_message();

        let transport_specific = TransportSpecificContext::NonUdp(
            NonUdpTransportContext::new(None),
        );

        Request::new(
            client_addr,
            received_at,
            msg,
            transport_specific,
            metadata,
        )
    }

    async fn do_axfr_for_zone<T>(
        zone: &Zone,
        req: &Request<Vec<u8>, T>,
    ) -> Result<
        XfrMiddlewareStream<
            <TestNextSvc as Service>::Future,
            <TestNextSvc as Service>::Stream,
            <<TestNextSvc as Service>::Stream as Stream>::Item,
        >,
        OptRcode,
    > {
        let qname = zone.apex_name();
        let read = zone.read();
        let zone_soa_answer =
            XfrMiddlewareSvc::<_, TestNextSvc, Zone>::read_soa(
                &read,
                qname.to_owned(),
            )
            .await
            .unwrap();
        XfrMiddlewareSvc::<_, TestNextSvc, Zone>::do_axfr(
            Arc::new(Semaphore::new(1)),
            Arc::new(Semaphore::new(1)),
            req,
            qname.to_owned(),
            &zone_soa_answer,
            read,
        )
        .await
    }

    async fn assert_xfr_stream_eq<O: octseq::Octets>(
        req: &Message<O>,
        zone: &Zone,
        mut stream: impl Stream<Item = Result<CallResult<Vec<u8>>, ServiceError>>
            + Unpin,
        expected_records: &mut ExpectedRecords,
    ) {
        let read = zone.read();
        let q = req.first_question().unwrap();
        let zone_soa_answer =
            XfrMiddlewareSvc::<_, TestNextSvc, Zone>::read_soa(
                &read,
                q.qname().to_name(),
            )
            .await
            .unwrap();
        let AnswerContent::Data(zone_soa_rrset) =
            zone_soa_answer.content().clone()
        else {
            unreachable!()
        };
        let first_rr = zone_soa_rrset.first().unwrap();
        let ZoneRecordData::Soa(expected_soa) = first_rr.data() else {
            unreachable!()
        };

        let msg = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            msg.feedback(),
            Some(ServiceFeedback::BeginTransaction)
        ));

        let msg = stream.next().await.unwrap().unwrap();
        let resp_builder = msg.into_inner().0.unwrap();
        let resp = resp_builder.as_message();
        assert!(resp.is_answer(req));
        let mut records = resp.answer().unwrap();

        let rec = records.next().unwrap().unwrap();
        assert_eq!(rec.owner(), zone.apex_name());
        assert_eq!(rec.rtype(), Rtype::SOA);
        assert_eq!(rec.ttl(), Ttl::from_secs(86400));
        let soa = rec
            .into_record::<Soa<ParsedName<&[u8]>>>()
            .unwrap()
            .unwrap()
            .into_data();
        assert_eq!(&soa, expected_soa);

        for rec in records.by_ref() {
            let rec = rec.unwrap();
            if rec.rtype() == Rtype::SOA {
                let soa = rec
                    .into_record::<Soa<ParsedName<&[u8]>>>()
                    .unwrap()
                    .unwrap()
                    .into_data();
                assert_eq!(&soa, expected_soa);
                break;
            } else {
                let pos = expected_records
                    .iter()
                    .position(|(name, data)| {
                        name == &rec.owner() && data.rtype() == rec.rtype()
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "XFR record {} {} {} was not expected",
                            rec.owner(),
                            rec.class(),
                            rec.rtype()
                        )
                    });
                let (_, data) = expected_records.remove(pos);
                let rec = rec
                    .into_record::<AllRecordData<_, ParsedName<_>>>()
                    .unwrap()
                    .unwrap();
                assert_eq!(&data, rec.data());
            }
        }

        assert!(records.next().is_none());
        assert!(expected_records.is_empty());

        let msg = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            msg.feedback(),
            Some(ServiceFeedback::EndTransaction)
        ));

        assert!(stream.next().await.is_none());
    }

    #[derive(Clone)]
    struct TestNextSvc;

    impl Service<Vec<u8>, ()> for TestNextSvc {
        type Target = Vec<u8>;
        type Stream = Once<Ready<ServiceResult<Self::Target>>>;
        type Future = Ready<Self::Stream>;

        fn call(&self, _request: Request<Vec<u8>, ()>) -> Self::Future {
            todo!()
        }
    }
}
