//! RFC 5936 AXFR and RFC 1995 IXFR request handling middleware.
//!
//! This module provides the [`XfrMiddlewareSvc`] service which responds to
//! [RFC 5936] AXFR and [RFC 1995] IXFR requests to perform entire or
//! incremental difference based zone transfers.
//!
//! Determining which requests to honour and with what data is delegated to a
//! caller supplied implementation of the [`XfrDataProvider`] trait.
//!
//! [`XfrRrBatcher`], primarily intended for internal use by
//! [`XfrMiddlewareSvc`], handles splitting of large zone transfer replies
//! into batches with as many resource records per response as will fit.
//!
//! # Limitations
//!
//! * RFC 1995 2 Brief Description of the Protocol states: _"To ensure
//!   integrity, servers should use UDP checksums for all UDP responses."_.
//!   This is not implemented.
//!
//! [RFC 5936]: https://www.rfc-editor.org/info/rfc5936
//! [RFC 1995]: https://www.rfc-editor.org/info/rfc1995

use core::future::{ready, Future, Ready};
use core::marker::PhantomData;
use core::ops::{ControlFlow, Deref};

use std::boxed::Box;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;

use bytes::Bytes;
use futures_util::stream::{once, Once, Stream};
use octseq::Octets;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::Semaphore;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, error, info, trace, warn};

use crate::base::iana::{Opcode, OptRcode, Rcode};
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

//------------ Constants -----------------------------------------------------

/// https://datatracker.ietf.org/doc/html/rfc1035#section-2.3.4
/// 2.3.4. Size limits
///   "UDP messages    512 octets or less"
const MAX_UDP_MSG_BYTE_LEN: u16 = 512;

/// https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
/// 4.2.2. TCP usage
///   "The message is prefixed with a two byte length field which gives the
///    message length, excluding the two byte length field"
const MAX_TCP_MSG_BYTE_LEN: u16 = u16::MAX;

//------------ XfrMiddlewareSvc ----------------------------------------------

/// RFC 5936 AXFR and RFC 1995 IXFR request handling middleware.
///
/// See the [module documentation] for a high level introduction.
///
/// [module documentation]: crate::net::server::middleware::xfr
#[derive(Clone, Debug)]
pub struct XfrMiddlewareSvc<RequestOctets, NextSvc, XDP, Metadata = ()> {
    /// The upstream [`Service`] to pass requests to and receive responses
    /// from.
    next_svc: NextSvc,

    /// A caller supplied implementation of [`XfrDataProvider`] for
    /// determining which requests to answer and with which data.
    xfr_data_provider: XDP,

    /// A limit on the number of XFR related zone walking operations
    /// that may run concurrently.
    zone_walking_semaphore: Arc<Semaphore>,

    /// A limit on the number of XFR related response batching operations that
    /// may run concurrently.
    batcher_semaphore: Arc<Semaphore>,

    _phantom: PhantomData<(RequestOctets, Metadata)>,
}

impl<RequestOctets, NextSvc, XDP, Metadata>
    XfrMiddlewareSvc<RequestOctets, NextSvc, XDP, Metadata>
where
    XDP: XfrDataProvider<Metadata>,
{
    /// Creates a new instance of this middleware.
    ///
    /// Takes an implementation of [`XfrDataProvider`] as a parameter to
    /// determine which requests to honour and with which data.
    ///
    /// The `max_concurrency` parameter limits the number of simultaneous zone
    /// transfer operations that may occur concurrently without blocking.
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

impl<RequestOctets, NextSvc, XDP, Metadata>
    XfrMiddlewareSvc<RequestOctets, NextSvc, XDP, Metadata>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc: Service<RequestOctets, ()> + Clone + Send + Sync + 'static,
    NextSvc::Future: Send + Sync + Unpin,
    NextSvc::Target: Composer + Default + Send + Sync,
    NextSvc::Stream: Send + Sync,
    XDP: XfrDataProvider<Metadata>,
{
    /// Pre-process received DNS XFR queries.
    ///
    /// Other types of query will be propagated unmodified to the next
    /// middleware or application service in the layered stack of services.
    pub async fn preprocess(
        zone_walking_semaphore: Arc<Semaphore>,
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, Metadata>,
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
            .request(req, ixfr_query_serial)
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
                let stream = Self::send_axfr_response(
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
                let stream = Self::send_ixfr_response(
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

    /// Log a message and break with an DNS error response stream.
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

    /// Generate and send an AXFR response for a given request and zone.
    #[allow(clippy::too_many_arguments)]
    async fn send_axfr_response<T>(
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

        let must_fit_in_single_message =
            matches!(req.transport_ctx(), TransportSpecificContext::Udp(_));

        if !must_fit_in_single_message {
            // Notify the underlying transport to expect a stream of related
            // responses. The transport should modify its behaviour to account
            // for the potentially slow and long running nature of a
            // transaction.
            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::BeginTransaction),
                &sender,
            );
        }

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
                        // If the blocking send fails it means that the
                        // batcher is no longer available. This can happen if
                        // it was no longer able to pass messages back to the
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
        let zone_soa_answer = zone_soa_answer.clone();

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
                must_fit_in_single_message,
            );

            while let Some((owner, rrset)) = batcher_rx.recv().await {
                for rr in rrset.data() {
                    if let Err(err) =
                        batcher.push((owner.clone(), qclass, rrset.ttl(), rr))
                    {
                        match err {
                            BatchReadyError::MustFitInSingleMessage => {
                                // https://datatracker.ietf.org/doc/html/rfc1995#section-2
                                // 2. Brief Description of the Protocol
                                //    ..
                                //    "If the UDP reply does not fit, the
                                //     query is responded to with a single SOA
                                //     record of the server's current version
                                //     to inform the client that a TCP query
                                //     should be initiated."
                                debug_assert!(must_fit_in_single_message);
                                let builder = mk_builder_for_target();
                                let resp =
                                    zone_soa_answer.to_message(&msg, builder);
                                debug!("IXFR aborted because response does not fit in a single UDP reply");
                                Self::add_to_stream(
                                    CallResult::new(resp),
                                    &sender,
                                );
                                batcher_rx.close();
                                return;
                            }

                            BatchReadyError::PushError(err) => {
                                error!(
                                "Internal error: Failed to send RR to batcher: {err}"
                            );
                                let resp = mk_error_response(
                                    &msg,
                                    OptRcode::SERVFAIL,
                                );
                                Self::add_to_stream(
                                    CallResult::new(resp),
                                    &sender,
                                );
                                batcher_rx.close();
                                return;
                            }

                            BatchReadyError::SendError => {
                                debug!("Batcher was unable to send completed batch, presumably because the receiver was dropped");
                                batcher_rx.close();
                                return;
                            }
                        }
                    }
                }
            }

            batcher.finish().unwrap(); // TODO

            if !must_fit_in_single_message {
                trace!("Finishing transaction");
                Self::add_to_stream(
                    CallResult::feedback_only(
                        ServiceFeedback::EndTransaction,
                    ),
                    &sender,
                );
            }

            batcher_rx.close();
        });

        Ok(MiddlewareStream::Result(stream))
    }

    // Generate and send an IXFR response for the given request and zone
    // diffs.
    #[allow(clippy::too_many_arguments)]
    async fn send_ixfr_response<T>(
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
        let msg = req.message();

        let AnswerContent::Data(zone_soa_rrset) =
            zone_soa_answer.content().clone()
        else {
            return Err(OptRcode::SERVFAIL);
        };

        if zone_soa_rrset.data().len() != 1 {
            return Err(OptRcode::SERVFAIL);
        }

        let first_rr = zone_soa_rrset.first().unwrap();
        let ZoneRecordData::Soa(soa) = first_rr.data() else {
            return Err(OptRcode::SERVFAIL);
        };

        let zone_serial = soa.serial();

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

        let must_fit_in_single_message =
            matches!(req.transport_ctx(), TransportSpecificContext::Udp(_));

        if !must_fit_in_single_message {
            // Notify the underlying transport to expect a stream of related
            // responses. The transport should modify its behaviour to account
            // for the potentially slow and long running nature of a
            // transaction.
            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::BeginTransaction),
                &sender,
            );
        }

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
                must_fit_in_single_message,
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

            if !must_fit_in_single_message {
                trace!("Ending transaction");
                Self::add_to_stream(
                    CallResult::feedback_only(
                        ServiceFeedback::EndTransaction,
                    ),
                    &sender,
                );
            }
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

    /// Is this message for us?
    ///
    /// Returns `Some(Question)` if the given query uses OPCODE QUERYY and has
    /// a first question with a QTYPE of `AXFR` or `IXFR`, `None` otherwise.
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
                let max_msg_size = ctx
                    .max_response_size_hint()
                    .unwrap_or(MAX_UDP_MSG_BYTE_LEN);
                max_msg_size - req.num_reserved_bytes()
            }
            TransportSpecificContext::NonUdp(_) => {
                MAX_TCP_MSG_BYTE_LEN - req.num_reserved_bytes()
            }
        };

        bytes_available as usize
    }
}

//--- impl Service

impl<RequestOctets, NextSvc, XDP, Metadata> Service<RequestOctets, Metadata>
    for XfrMiddlewareSvc<RequestOctets, NextSvc, XDP, Metadata>
where
    RequestOctets: Octets + Send + Sync + Unpin + 'static,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc: Service<RequestOctets, ()> + Clone + Send + Sync + 'static,
    NextSvc::Future: Send + Sync + Unpin,
    NextSvc::Target: Composer + Default + Send + Sync,
    NextSvc::Stream: Send + Sync,
    XDP: XfrDataProvider<Metadata> + Clone + Sync + Send + 'static,
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
pub trait XfrDataProvider<Metadata = ()> {
    /// Request data needed to respond to an XFR request.
    ///
    /// Returns Ok if the request is allowed and the requested data is
    /// available.
    ///
    /// Returns Err otherwise.
    #[allow(clippy::type_complexity)]
    fn request<Octs>(
        &self,
        req: &Request<Octs, Metadata>,
        diff_from: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (Zone, Vec<Arc<ZoneDiff>>),
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send
                + '_,
        >,
    >
    where
        Octs: Octets + Send + Sync;
}

//--- impl for AsRef

impl<Metadata, T, U> XfrDataProvider<Metadata> for U
where
    T: XfrDataProvider<Metadata> + 'static,
    U: Deref<Target = T>,
{
    fn request<Octs>(
        &self,
        req: &Request<Octs, Metadata>,
        diff_from: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        (Zone, Vec<Arc<ZoneDiff>>),
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send
                + '_,
        >,
    >
    where
        Octs: Octets + Send + Sync,
    {
        (**self).request(req, diff_from)
    }
}

//--- impl for Zone

impl<Metadata> XfrDataProvider<Metadata> for Zone {
    /// Request data needed to respond to an XFR request.
    ///
    /// Returns Ok(Self, vec![]) if the given apex name and class match this
    /// zone, irrespective of the given request or diff range.
    ///
    /// Returns Err if the requested zone is not this zone.
    fn request<Octs>(
        &self,
        req: &Request<Octs, Metadata>,
        _diff_from: Option<Serial>,
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
        Octs: Octets + Send + Sync,
    {
        let res = if let Ok(q) = req.message().sole_question() {
            if q.qname() == self.apex_name() && q.qclass() == self.class() {
                Ok((self.clone(), vec![]))
            } else {
                Err(XfrDataProviderError::UnknownZone)
            }
        } else {
            Err(XfrDataProviderError::UnknownZone)
        };

        Box::pin(ready(res))
    }
}

//--- impl for ZoneTree

impl<Metadata> XfrDataProvider<Metadata> for ZoneTree {
    /// Request data needed to respond to an XFR request.
    ///
    /// Returns Ok(zone, vec![]) if the given apex name and class match a zone
    /// in this zone tree, irrespective of the given request or diff range.
    ///
    /// Returns Err if the requested zone is not this zone tree.
    fn request<Octs>(
        &self,
        req: &Request<Octs, Metadata>,
        _diff_from: Option<Serial>,
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
        Octs: Octets + Send + Sync,
    {
        let res = if let Ok(q) = req.message().sole_question() {
            if let Some(zone) = self.find_zone(q.qname(), q.qclass()) {
                Ok((zone.clone(), vec![]))
            } else {
                Err(XfrDataProviderError::UnknownZone)
            }
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
        must_fit_in_single_message: bool,
    ) -> impl ResourceRecordBatcher<RequestOctets, Target, Error = BatchReadyError>
    {
        let cb_state = CallbackState::new(
            req_msg.clone(),
            sender,
            soft_byte_limit,
            hard_rr_limit,
            must_fit_in_single_message,
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

#[derive(Clone, Copy, Debug)]
pub enum BatchReadyError {
    PushError(PushError),

    SendError,

    MustFitInSingleMessage,
}

impl From<PushError> for BatchReadyError {
    fn from(err: PushError) -> Self {
        Self::PushError(err)
    }
}

impl<RequestOctets, Target>
    Callbacks<RequestOctets, Target, CallbackState<RequestOctets, Target>>
    for XfrRrBatcher<RequestOctets, Target>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    type Error = BatchReadyError;

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
        finished: bool,
    ) -> Result<(), Self::Error> {
        if !finished && cb_state.must_fit_in_single_message {
            return Err(BatchReadyError::MustFitInSingleMessage);
        }

        trace!("Sending RR batch");
        let mut additional = builder.additional();
        Self::set_axfr_header(&cb_state.req_msg, &mut additional);
        let call_result = Ok(CallResult::new(additional));
        cb_state
            .sender
            .send(call_result)
            .map_err(|_unsent_msg| BatchReadyError::SendError)
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
    must_fit_in_single_message: bool,
}

impl<RequestOctets, Target> CallbackState<RequestOctets, Target> {
    fn new(
        req_msg: Arc<Message<RequestOctets>>,
        sender: UnboundedSender<ServiceResult<Target>>,
        soft_byte_limit: Option<usize>,
        hard_rr_limit: Option<u16>,
        must_fit_in_single_message: bool,
    ) -> Self {
        Self {
            req_msg,
            sender,
            soft_byte_limit,
            hard_rr_limit,
            must_fit_in_single_message,
        }
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use core::sync::atomic::{AtomicBool, Ordering};

    use std::borrow::ToOwned;

    use futures_util::StreamExt;
    use tokio::time::Instant;

    use crate::base::iana::Class;
    use crate::base::{MessageBuilder, Ttl};
    use crate::net::server::message::{
        NonUdpTransportContext, UdpTransportContext,
    };
    use crate::net::server::service::ServiceError;
    use crate::rdata::{Aaaa, AllRecordData, Cname, Mx, Ns, Txt, A};
    use crate::tsig::{Algorithm, Key, KeyName};
    use crate::zonefile::inplace::Zonefile;
    use crate::zonetree::types::Rrset;
    use crate::zonetree::ZoneDiffBuilder;

    use super::*;

    type ExpectedRecords =
        Vec<(Name<Bytes>, AllRecordData<Bytes, Name<Bytes>>)>;

    #[tokio::test]
    async fn axfr_with_example_zone() {
        let zone = load_zone(include_bytes!(
            "../../../../test-data/zonefiles/nsd-example.txt"
        ));

        let req = mk_axfr_request(zone.apex_name(), ());

        let res = do_preprocess(zone.clone(), &req).await;

        let ControlFlow::Break(mut stream) = res else {
            panic!("AXFR failed");
        };

        let zone_soa = get_zone_soa(&zone).await;

        let mut expected_records: ExpectedRecords = vec![
            (n("example.com"), zone_soa.clone().into()),
            (n("example.com"), Ns::new(n("example.com")).into()),
            (n("example.com"), A::new(p("192.0.2.1")).into()),
            (n("example.com"), Aaaa::new(p("2001:db8::3")).into()),
            (n("www.example.com"), Cname::new(n("example.com")).into()),
            (n("mail.example.com"), Mx::new(10, n("example.com")).into()),
            (n("example.com"), zone_soa.into()),
        ];

        let msg = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            msg.feedback(),
            Some(ServiceFeedback::BeginTransaction)
        ));

        let stream = assert_stream_eq(
            req.message(),
            &mut stream,
            &mut expected_records,
        )
        .await;

        let msg = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            msg.feedback(),
            Some(ServiceFeedback::EndTransaction)
        ));
    }

    #[tokio::test]
    async fn axfr_multi_response() {
        let zone = load_zone(include_bytes!(
            "../../../../test-data/zonefiles/big.example.com.txt"
        ));

        let req = mk_axfr_request(zone.apex_name(), ());

        let res = do_preprocess(zone.clone(), &req).await;

        let ControlFlow::Break(mut stream) = res else {
            panic!("AXFR failed");
        };

        let zone_soa = get_zone_soa(&zone).await;

        let mut expected_records: ExpectedRecords = vec![
            (n("example.com"), zone_soa.clone().into()),
            (n("example.com"), Ns::new(n("ns1.example.com")).into()),
            (n("example.com"), Ns::new(n("ns2.example.com")).into()),
            (n("example.com"), Mx::new(10, n("mail.example.com")).into()),
            (n("example.com"), A::new(p("192.0.2.1")).into()),
            (n("example.com"), Aaaa::new(p("2001:db8:10::1")).into()),
            (n("ns1.example.com"), A::new(p("192.0.2.2")).into()),
            (n("ns1.example.com"), Aaaa::new(p("2001:db8:10::2")).into()),
            (n("ns2.example.com"), A::new(p("192.0.2.3")).into()),
            (n("ns2.example.com"), Aaaa::new(p("2001:db8:10::3")).into()),
            (n("mail.example.com"), A::new(p("192.0.2.4")).into()),
            (n("mail.example.com"), Aaaa::new(p("2001:db8:10::4")).into()),
        ];

        for i in 1..=10000 {
            expected_records.push((
                n(&format!("host-{i}.example.com")),
                Txt::build_from_slice(b"text").unwrap().into(),
            ));
        }

        expected_records.push((n("example.com"), zone_soa.into()));

        let msg = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            msg.feedback(),
            Some(ServiceFeedback::BeginTransaction)
        ));

        let stream = assert_stream_eq(
            req.message(),
            &mut stream,
            &mut expected_records,
        )
        .await;

        let msg = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            msg.feedback(),
            Some(ServiceFeedback::EndTransaction)
        ));
    }

    #[tokio::test]
    async fn axfr_delegation_records() {
        // https://datatracker.ietf.org/doc/html/rfc5936#section-3.2
    }

    #[tokio::test]
    async fn axfr_glue_records() {
        // https://datatracker.ietf.org/doc/html/rfc5936#section-3.3
    }

    #[tokio::test]
    async fn axfr_name_compression_not_yet_supported() {
        // https://datatracker.ietf.org/doc/html/rfc5936#section-3.4
    }

    #[tokio::test]
    async fn axfr_occluded_names() {
        // https://datatracker.ietf.org/doc/html/rfc5936#section-3.5
    }

    #[tokio::test]
    async fn axfr_not_allowed_over_udp() {
        // https://datatracker.ietf.org/doc/html/rfc5936#section-4.2
        let zone = load_zone(include_bytes!(
            "../../../../test-data/zonefiles/nsd-example.txt"
        ));

        let req = mk_udp_axfr_request(zone.apex_name(), ());

        let res = do_preprocess(zone, &req).await;

        let ControlFlow::Break(mut stream) = res else {
            panic!("AXFR failed");
        };

        let msg = stream.next().await.unwrap().unwrap();
        let resp_builder = msg.into_inner().0.unwrap();
        let resp = resp_builder.as_message();

        assert_eq!(resp.header().rcode(), Rcode::NOTIMP);
    }

    #[tokio::test]
    async fn ixfr_rfc1995_section7_full_zone_reply() {
        // Based on https://datatracker.ietf.org/doc/html/rfc1995#section-7

        // initial zone content:
        // JAIN.AD.JP.         IN SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. (
        //                                   1 600 600 3600000 604800)
        // IN NS  NS.JAIN.AD.JP.
        // NS.JAIN.AD.JP.      IN A   133.69.136.1
        // NEZU.JAIN.AD.JP.    IN A   133.69.136.5

        // Final zone content:
        let rfc_1995_zone = r#"
JAIN.AD.JP.         IN SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. (
                                  3 600 600 3600000 604800)
                    IN NS  NS.JAIN.AD.JP.
NS.JAIN.AD.JP.      IN A   133.69.136.1
JAIN-BB.JAIN.AD.JP. IN A   133.69.136.3
JAIN-BB.JAIN.AD.JP. IN A   192.41.197.2
        "#;
        let zone = load_zone(rfc_1995_zone.as_bytes());

        // Create an object that knows how to provide zone and diff data for
        // our zone and no diffs.
        let zone_with_diffs = ZoneWithDiffs::new(zone.clone(), vec![]);

        // The following IXFR query
        let req = mk_udp_ixfr_request(zone.apex_name(), Serial(1), ());

        let res = do_preprocess(zone_with_diffs, &req).await;

        let ControlFlow::Break(mut stream) = res else {
            panic!("IXFR failed");
        };

        // could be replied to with the following full zone transfer message:
        let zone_soa = get_zone_soa(&zone).await;

        let mut expected_records: ExpectedRecords = vec![
            (n("JAIN.AD.JP."), zone_soa.clone().into()),
            (n("JAIN.AD.JP."), Ns::new(n("NS.JAIN.AD.JP.")).into()),
            (n("NS.JAIN.AD.JP."), A::new(p("133.69.136.1")).into()),
            (n("JAIN-BB.JAIN.AD.JP."), A::new(p("133.69.136.3")).into()),
            (n("JAIN-BB.JAIN.AD.JP."), A::new(p("192.41.197.2")).into()),
            (n("JAIN.AD.JP."), zone_soa.into()),
        ];

        assert_stream_eq(req.message(), &mut stream, &mut expected_records)
            .await;
    }

    #[tokio::test]
    async fn ixfr_rfc1995_section7_incremental_reply() {
        // Based on https://datatracker.ietf.org/doc/html/rfc1995#section-7
        let mut diffs = Vec::new();

        // initial zone content:
        // JAIN.AD.JP.         IN SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. (
        //                                   1 600 600 3600000 604800)
        // IN NS  NS.JAIN.AD.JP.
        // NS.JAIN.AD.JP.      IN A   133.69.136.1
        // NEZU.JAIN.AD.JP.    IN A   133.69.136.5

        // Final zone content:
        let rfc_1995_zone = r#"
JAIN.AD.JP.         IN SOA NS.JAIN.AD.JP. mohta.jain.ad.jp. (
                                  3 600 600 3600000 604800)
                    IN NS  NS.JAIN.AD.JP.
NS.JAIN.AD.JP.      IN A   133.69.136.1
JAIN-BB.JAIN.AD.JP. IN A   133.69.136.3
JAIN-BB.JAIN.AD.JP. IN A   192.41.197.2
        "#;
        let zone = load_zone(rfc_1995_zone.as_bytes());

        // Diff 1: NEZU.JAIN.AD.JP. is removed and JAIN-BB.JAIN.AD.JP. is added.
        let mut diff = ZoneDiffBuilder::new();

        // -- Remove the old SOA.
        let mut rrset = Rrset::new(Rtype::SOA, Ttl::from_secs(0));
        let soa = Soa::new(
            n("NS.JAIN.AD.JP."),
            n("mohta.jain.ad.jp."),
            Serial(1),
            Ttl::from_secs(600),
            Ttl::from_secs(600),
            Ttl::from_secs(3600000),
            Ttl::from_secs(604800),
        );
        rrset.push_data(soa.into());
        diff.remove(n("JAIN.AD.JP"), Rtype::SOA, SharedRrset::new(rrset));

        // -- Remove the A record.
        let mut rrset = Rrset::new(Rtype::A, Ttl::from_secs(0));
        rrset.push_data(A::new(p("133.69.136.5")).into());
        diff.remove(n("NEZU.JAIN.AD.JP"), Rtype::A, SharedRrset::new(rrset));

        // -- Add the new SOA.
        let mut rrset = Rrset::new(Rtype::SOA, Ttl::from_secs(0));
        let soa = Soa::new(
            n("NS.JAIN.AD.JP."),
            n("mohta.jain.ad.jp."),
            Serial(2),
            Ttl::from_secs(600),
            Ttl::from_secs(600),
            Ttl::from_secs(3600000),
            Ttl::from_secs(604800),
        );
        rrset.push_data(soa.into());
        diff.add(n("JAIN.AD.JP"), Rtype::SOA, SharedRrset::new(rrset));

        // -- Add the new A records.
        let mut rrset = Rrset::new(Rtype::A, Ttl::from_secs(0));
        rrset.push_data(A::new(p("133.69.136.4")).into());
        rrset.push_data(A::new(p("192.41.197.2")).into());
        diff.add(n("JAIN-BB.JAIN.AD.JP"), Rtype::A, SharedRrset::new(rrset));

        diffs.push(diff.build().unwrap());

        // Diff 2: One of the IP addresses of JAIN-BB.JAIN.AD.JP. is changed.
        let mut diff = ZoneDiffBuilder::new();

        // -- Remove the old SOA.
        let mut rrset = Rrset::new(Rtype::SOA, Ttl::from_secs(0));
        let soa = Soa::new(
            n("NS.JAIN.AD.JP."),
            n("mohta.jain.ad.jp."),
            Serial(2),
            Ttl::from_secs(600),
            Ttl::from_secs(600),
            Ttl::from_secs(3600000),
            Ttl::from_secs(604800),
        );
        rrset.push_data(soa.into());
        diff.remove(n("JAIN.AD.JP"), Rtype::SOA, SharedRrset::new(rrset));

        // Remove the outdated IP address.
        let mut rrset = Rrset::new(Rtype::A, Ttl::from_secs(0));
        rrset.push_data(A::new(p("133.69.136.4")).into());
        diff.remove(
            n("JAIN-BB.JAIN.AD.JP"),
            Rtype::A,
            SharedRrset::new(rrset),
        );

        // -- Add the new SOA.
        let mut rrset = Rrset::new(Rtype::SOA, Ttl::from_secs(0));
        let soa = Soa::new(
            n("NS.JAIN.AD.JP."),
            n("mohta.jain.ad.jp."),
            Serial(3),
            Ttl::from_secs(600),
            Ttl::from_secs(600),
            Ttl::from_secs(3600000),
            Ttl::from_secs(604800),
        );
        rrset.push_data(soa.into());
        diff.add(n("JAIN.AD.JP"), Rtype::SOA, SharedRrset::new(rrset));

        // Add the updated IP address.
        let mut rrset = Rrset::new(Rtype::A, Ttl::from_secs(0));
        rrset.push_data(A::new(p("133.69.136.3")).into());
        diff.add(n("JAIN-BB.JAIN.AD.JP"), Rtype::A, SharedRrset::new(rrset));

        diffs.push(diff.build().unwrap());

        // Create an object that knows how to provide zone and diff data for
        // our zone and diffs.
        let zone_with_diffs = ZoneWithDiffs::new(zone.clone(), diffs);

        // The following IXFR query
        let req = mk_ixfr_request(zone.apex_name(), Serial(1), ());

        let res = do_preprocess(zone_with_diffs, &req).await;

        let ControlFlow::Break(mut stream) = res else {
            panic!("IXFR failed");
        };

        let zone_soa = get_zone_soa(&zone).await;

        // could be replied to with the following full zone transfer message:
        let mut expected_records: ExpectedRecords = vec![
            (n("JAIN.AD.JP."), zone_soa.clone().into()),
            (
                n("JAIN.AD.JP."),
                Soa::new(
                    n("NS.JAIN.AD.JP."),
                    n("mohta.jain.ad.jp."),
                    Serial(1),
                    Ttl::from_secs(600),
                    Ttl::from_secs(600),
                    Ttl::from_secs(3600000),
                    Ttl::from_secs(604800),
                )
                .into(),
            ),
            (n("NEZU.JAIN.AD.JP."), A::new(p("133.69.136.5")).into()),
            (
                n("JAIN.AD.JP."),
                Soa::new(
                    n("NS.JAIN.AD.JP."),
                    n("mohta.jain.ad.jp."),
                    Serial(2),
                    Ttl::from_secs(600),
                    Ttl::from_secs(600),
                    Ttl::from_secs(3600000),
                    Ttl::from_secs(604800),
                )
                .into(),
            ),
            (n("JAIN-BB.JAIN.AD.JP."), A::new(p("133.69.136.4")).into()),
            (n("JAIN-BB.JAIN.AD.JP."), A::new(p("192.41.197.2")).into()),
            (
                n("JAIN.AD.JP."),
                Soa::new(
                    n("NS.JAIN.AD.JP."),
                    n("mohta.jain.ad.jp."),
                    Serial(2),
                    Ttl::from_secs(600),
                    Ttl::from_secs(600),
                    Ttl::from_secs(3600000),
                    Ttl::from_secs(604800),
                )
                .into(),
            ),
            (n("JAIN-BB.JAIN.AD.JP."), A::new(p("133.69.136.4")).into()),
            (
                n("JAIN.AD.JP."),
                Soa::new(
                    n("NS.JAIN.AD.JP."),
                    n("mohta.jain.ad.jp."),
                    Serial(3),
                    Ttl::from_secs(600),
                    Ttl::from_secs(600),
                    Ttl::from_secs(3600000),
                    Ttl::from_secs(604800),
                )
                .into(),
            ),
            (n("JAIN-BB.JAIN.AD.JP."), A::new(p("133.69.136.3")).into()),
            (n("JAIN.AD.JP."), zone_soa.into()),
        ];

        let msg = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            msg.feedback(),
            Some(ServiceFeedback::BeginTransaction)
        ));

        let stream = assert_stream_eq(
            req.message(),
            &mut stream,
            &mut expected_records,
        )
        .await;

        let msg = stream.next().await.unwrap().unwrap();
        assert!(matches!(
            msg.feedback(),
            Some(ServiceFeedback::EndTransaction)
        ));
    }

    #[tokio::test]
    async fn ixfr_rfc1995_section7_udp_packet_overflow() {
        // Based on https://datatracker.ietf.org/doc/html/rfc1995#section-7
        let zone = load_zone(include_bytes!(
            "../../../../test-data/zonefiles/big.example.com.txt"
        ));

        let req = mk_udp_ixfr_request(zone.apex_name(), Serial(0), ());

        let res = do_preprocess(zone.clone(), &req).await;

        let ControlFlow::Break(mut stream) = res else {
            panic!("IXFR failed");
        };

        let zone_soa = get_zone_soa(&zone).await;

        let mut expected_records: ExpectedRecords =
            vec![(n("example.com"), zone_soa.into())];

        assert_stream_eq(req.message(), &mut stream, &mut expected_records)
            .await;
    }

    #[tokio::test]
    async fn ixfr_multi_response_tcp() {}

    #[tokio::test]
    async fn axfr_with_tsig_key() {
        // Define an XfrDataProvider that expects to receive a Request that is
        // generic over a type that we specify: Authentication. This is the
        // type over which the Request produced by TsigMiddlewareSvc is generic.
        // When the XfrMiddlewareSvc receives a Request<Octs, Authentication> it
        // passes it to the XfrDataProvider which in turn can inspect it.
        struct KeyReceivingXfrDataProvider {
            key: Arc<Key>,
            checked: Arc<AtomicBool>,
        }

        impl XfrDataProvider<Option<Arc<Key>>> for KeyReceivingXfrDataProvider {
            #[allow(clippy::type_complexity)]
            fn request<Octs>(
                &self,
                req: &Request<Octs, Option<Arc<Key>>>,
                _diff_from: Option<Serial>,
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
                Octs: Octets + Send + Sync,
            {
                let key = req.metadata().as_ref().unwrap();
                assert_eq!(key.name(), self.key.name());
                self.checked.store(true, Ordering::SeqCst);
                Box::pin(ready(Err(XfrDataProviderError::Refused)))
            }
        }

        let key_name = KeyName::from_str("some_tsig_key_name").unwrap();
        let secret = crate::utils::base64::decode::<Vec<u8>>(
            "zlCZbVJPIhobIs1gJNQfrsS3xCxxsR9pMUrGwG8OgG8=",
        )
        .unwrap();
        let key = Arc::new(
            Key::new(Algorithm::Sha256, &secret, key_name, None, None)
                .unwrap(),
        );

        let metadata = Some(key.clone());
        let req = mk_axfr_request(n("example.com"), metadata);
        let checked = Arc::new(AtomicBool::new(false));
        let xdp = KeyReceivingXfrDataProvider {
            key,
            checked: checked.clone(),
        };

        // Invoke XfrMiddlewareSvc with our custom XfrDataProvidedr.
        let _ = do_preprocess(xdp, &req).await;

        // Veirfy that our XfrDataProvider was invoked and received the expected
        // TSIG key name data.
        assert!(checked.load(Ordering::SeqCst));
    }

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

    async fn get_zone_soa(zone: &Zone) -> Soa<Name<Bytes>> {
        let read = zone.read();
        let zone_soa_answer =
            XfrMiddlewareSvc::<Vec<u8>, TestNextSvc, Zone>::read_soa(
                &read,
                zone.apex_name().to_owned(),
            )
            .await
            .unwrap();
        let AnswerContent::Data(zone_soa_rrset) =
            zone_soa_answer.content().clone()
        else {
            unreachable!()
        };
        let first_rr = zone_soa_rrset.first().unwrap();
        let ZoneRecordData::Soa(soa) = first_rr.data() else {
            unreachable!()
        };
        soa.clone()
    }

    fn mk_axfr_request<T>(
        qname: impl ToName,
        metadata: T,
    ) -> Request<Vec<u8>, T> {
        mk_axfr_request_for_transport(
            qname,
            metadata,
            TransportSpecificContext::NonUdp(NonUdpTransportContext::new(
                None,
            )),
        )
    }

    fn mk_udp_axfr_request<T>(
        qname: impl ToName,
        metadata: T,
    ) -> Request<Vec<u8>, T> {
        mk_axfr_request_for_transport(
            qname,
            metadata,
            TransportSpecificContext::Udp(UdpTransportContext::new(None)),
        )
    }

    fn mk_axfr_request_for_transport<T>(
        qname: impl ToName,
        metadata: T,
        transport_specific: TransportSpecificContext,
    ) -> Request<Vec<u8>, T> {
        let client_addr = "127.0.0.1:12345".parse().unwrap();
        let received_at = Instant::now();
        let msg = MessageBuilder::new_vec();
        let mut msg = msg.question();
        msg.push((qname, Rtype::AXFR)).unwrap();
        let msg = msg.into_message();

        Request::new(
            client_addr,
            received_at,
            msg,
            transport_specific,
            metadata,
        )
    }

    fn mk_ixfr_request<T>(
        qname: impl ToName + Clone,
        serial: Serial,
        metadata: T,
    ) -> Request<Vec<u8>, T> {
        mk_ixfr_request_for_transport(
            qname,
            serial,
            metadata,
            TransportSpecificContext::NonUdp(NonUdpTransportContext::new(
                None,
            )),
        )
    }

    fn mk_udp_ixfr_request<T>(
        qname: impl ToName + Clone,
        serial: Serial,
        metadata: T,
    ) -> Request<Vec<u8>, T> {
        mk_ixfr_request_for_transport(
            qname,
            serial,
            metadata,
            TransportSpecificContext::Udp(UdpTransportContext::new(None)),
        )
    }

    fn mk_ixfr_request_for_transport<T>(
        qname: impl ToName + Clone,
        serial: Serial,
        metadata: T,
        transport_specific: TransportSpecificContext,
    ) -> Request<Vec<u8>, T> {
        let client_addr = "127.0.0.1:12345".parse().unwrap();
        let received_at = Instant::now();
        let msg = MessageBuilder::new_vec();
        let mut msg = msg.question();
        msg.push((qname.clone(), Rtype::IXFR)).unwrap();

        let mut msg = msg.authority();
        let ttl = Ttl::from_secs(0);
        let soa = Soa::new(n("name"), n("rname"), serial, ttl, ttl, ttl, ttl);
        msg.push((qname, Class::IN, Ttl::from_secs(0), soa))
            .unwrap();
        let msg = msg.into_message();

        Request::new(
            client_addr,
            received_at,
            msg,
            transport_specific,
            metadata,
        )
    }

    async fn do_preprocess<Metadata, XDP: XfrDataProvider<Metadata>>(
        zone: XDP,
        req: &Request<Vec<u8>, Metadata>,
    ) -> ControlFlow<
        XfrMiddlewareStream<
            <TestNextSvc as Service>::Future,
            <TestNextSvc as Service>::Stream,
            <<TestNextSvc as Service>::Stream as Stream>::Item,
        >,
    > {
        XfrMiddlewareSvc::<Vec<u8>, TestNextSvc, XDP, Metadata>::preprocess(
            Arc::new(Semaphore::new(1)),
            Arc::new(Semaphore::new(1)),
            req,
            zone,
        )
        .await
    }

    async fn assert_stream_eq<
        O: octseq::Octets,
        S: Stream<Item = Result<CallResult<Vec<u8>>, ServiceError>> + Unpin,
    >(
        req: &Message<O>,
        mut stream: S,
        expected_records: &mut ExpectedRecords,
    ) -> S {
        while !expected_records.is_empty() {
            let msg = stream.next().await.unwrap().unwrap();

            let resp_builder = msg.into_inner().0.unwrap();
            let resp = resp_builder.as_message();
            assert!(resp.is_answer(req));
            let mut records = resp.answer().unwrap().peekable();

            for rec in records.by_ref() {
                let rec = rec.unwrap();

                let rec = rec
                    .into_record::<AllRecordData<_, ParsedName<_>>>()
                    .unwrap()
                    .unwrap();

                let pos = expected_records
                    .iter()
                    .position(|(name, data)| {
                        name == rec.owner() && data == rec.data()
                    })
                    .unwrap_or_else(|| {
                        panic!(
                            "XFR record {} {} {} {} was not expected",
                            rec.owner(),
                            rec.class(),
                            rec.rtype(),
                            rec.data(),
                        )
                    });

                let _ = expected_records.remove(pos);

                eprintln!(
                    "Found {} {} {}",
                    rec.owner(),
                    rec.class(),
                    rec.rtype()
                )
            }

            assert!(records.next().is_none());
        }

        stream
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

    struct ZoneWithDiffs {
        zone: Zone,
        diffs: Vec<Arc<ZoneDiff>>,
    }

    impl ZoneWithDiffs {
        fn new(zone: Zone, diffs: Vec<ZoneDiff>) -> Self {
            Self {
                zone,
                diffs: diffs.into_iter().map(Arc::new).collect(),
            }
        }
    }

    impl XfrDataProvider for ZoneWithDiffs {
        fn request<Octs>(
            &self,
            req: &Request<Octs, ()>,
            diff_from: Option<Serial>,
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
            Octs: Octets + Send + Sync,
        {
            let res = if let Ok(q) = req.message().sole_question() {
                if q.qname() == self.zone.apex_name()
                    && q.qclass() == self.zone.class()
                {
                    let diffs =
                        if self.diffs.first().map(|diff| diff.start_serial)
                            == diff_from
                        {
                            self.diffs.clone()
                        } else {
                            vec![]
                        };

                    Ok((self.zone.clone(), diffs))
                } else {
                    Err(XfrDataProviderError::UnknownZone)
                }
            } else {
                Err(XfrDataProviderError::UnknownZone)
            };

            Box::pin(ready(res))
        }
    }
}