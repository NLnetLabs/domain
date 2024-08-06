//! XFR request handling middleware.

use core::future::ready;
use core::marker::PhantomData;
use core::ops::ControlFlow;

use std::boxed::Box;
use std::sync::Arc;

use bytes::Bytes;
use futures::stream::{once, Stream};
use octseq::Octets;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::Semaphore;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{error, info, trace, warn};

use crate::base::iana::{Opcode, OptRcode};
use crate::base::message_builder::AdditionalBuilder;
use crate::base::net::IpAddr;
use crate::base::wire::Composer;
use crate::base::{
    Message, Name, ParsedName, Question, Rtype, Serial, StreamTarget, ToName,
};
use crate::net::server::batcher::ResourceRecordBatcher;
use crate::net::server::message::{Request, TransportSpecificContext};
use crate::net::server::middleware::stream::MiddlewareStream;
use crate::net::server::service::{
    CallResult, Service, ServiceFeedback, ServiceResult,
};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::{Soa, ZoneRecordData};
use crate::tsig::KeyName;
use crate::zonecatalog::catalog::{CatalogZone, ZoneError, ZoneLookup};
use crate::zonecatalog::types::{
    CompatibilityMode, XfrConfig, XfrStrategy, ZoneInfo,
};
use crate::zonetree::error::OutOfZone;
use crate::zonetree::{
    Answer, AnswerContent, ReadableZone, SharedRrset, StoredName,
};

use super::batcher::XfrRrBatcher;
use super::types::{IxfrResult, XfrMiddlewareStream, XfrMode};

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
pub struct XfrMiddlewareSvc<RequestOctets, NextSvc, ZL>
where
    ZL: ZoneLookup + Clone + Sync + Send + 'static,
{
    pub(super) next_svc: NextSvc,

    pub(super) zones: ZL,

    pub(super) zone_walking_semaphore: Arc<Semaphore>,

    pub(super) batcher_semaphore: Arc<Semaphore>,

    pub(super) xfr_mode: XfrMode,

    _phantom: PhantomData<RequestOctets>,
}

impl<RequestOctets, NextSvc, ZL> XfrMiddlewareSvc<RequestOctets, NextSvc, ZL>
where
    ZL: ZoneLookup + Clone + Sync + Send + 'static,
{
    /// Creates an empty processor instance.
    ///
    /// The processor will not respond to XFR requests until you add at least
    /// one zone to it.
    // TODO: Move extra arguments into a Config object.
    #[must_use]
    pub fn new(
        next_svc: NextSvc,
        zones: ZL,
        max_concurrency: usize,
        xfr_mode: XfrMode,
    ) -> Self {
        let zone_walking_semaphore =
            Arc::new(Semaphore::new(max_concurrency));
        let batcher_semaphore = Arc::new(Semaphore::new(max_concurrency));

        Self {
            next_svc,
            zones,
            zone_walking_semaphore,
            batcher_semaphore,
            xfr_mode,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOctets, NextSvc, ZL> XfrMiddlewareSvc<RequestOctets, NextSvc, ZL>
where
    RequestOctets: Octets + Send + Sync + 'static + Unpin,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc: Service<RequestOctets, ()> + Clone + Send + Sync + 'static,
    NextSvc::Future: Send + Sync + Unpin,
    NextSvc::Target: Composer + Default + Send + Sync,
    NextSvc::Stream: Send + Sync,
    ZL: ZoneLookup + Clone + Sync + Send + 'static,
{
    pub(super) async fn preprocess<T>(
        zone_walking_semaphore: Arc<Semaphore>,
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, T>,
        zones: ZL,
        xfr_mode: XfrMode,
        actual_tsig_key_name: Option<&KeyName>,
    ) -> ControlFlow<
        XfrMiddlewareStream<
            NextSvc::Future,
            NextSvc::Stream,
            <NextSvc::Stream as Stream>::Item,
        >,
    > {
        let msg = req.message();

        let Some(q) = Self::get_relevant_question(msg) else {
            return ControlFlow::Continue(());
        };

        let qname: Name<Bytes> = q.qname().to_name();

        // Find the zone
        let zone = match zones.get_zone(&qname, q.qclass()) {
            Ok(Some(zone)) => zone,

            Ok(None) => {
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
                return ControlFlow::Break(Self::to_stream(
                    mk_error_response(msg, OptRcode::NOTAUTH),
                ));
            }

            Err(ZoneError::TemporarilyUnavailable) => {
                // The zone is not yet loaded or has expired, both of which
                // are presumably transient conditions and thus SERVFAIL is the
                // appropriate response, not NOTAUTH, as we know we are supposed
                // to be authoritative for the zone but we just don't have the
                // data right now.
                warn!(
                    "{} for {qname} from {} refused: zone not currently available",
                    q.qtype(),
                    req.client_addr()
                );

                // TODO: Should this return REFUSED instead? (I think
                // in the secondary lifecycle Stelline test an argument
                // is made that this should be REFUSED?
                return ControlFlow::Break(Self::to_stream(
                    mk_error_response(msg, OptRcode::SERVFAIL),
                ));
            }
        };

        // Only provide XFR if allowed.
        let cat_zone = zone
            .as_ref()
            .as_any()
            .downcast_ref::<CatalogZone>()
            .unwrap();

        let xfr_config = Self::settings_for_client(
            req.client_addr().ip(),
            &qname,
            q.qtype(),
            cat_zone.info(),
        );

        if let Some(cfg) = xfr_config {
            let expected_tsig_key_name =
                cfg.tsig_key.as_ref().map(|(name, _alg)| name);
            let tsig_key_mismatch = match (expected_tsig_key_name, actual_tsig_key_name) {
                (None, Some(actual)) => {
                    Some(format!(
                        "Request was signed with TSIG key '{actual}' but should be unsigned."))
                }
                (Some(expected), None) => {
                    Some(
                        format!("Request should be signed with TSIG key '{expected}' but was unsigned"))
                }
                (Some(expected), Some(actual)) if *actual != expected => {
                    Some(format!(
                        "Request should be signed with TSIG key '{expected}' but was instead signed with TSIG key '{actual}'"))
                }
                (Some(expected), Some(_)) => {
                    trace!("Request is signed with expected TSIG key '{expected}'");
                    None
                },
                (None, None) => {
                    trace!("Request is unsigned as expected");
                    None
                }
            };
            if let Some(reason) = tsig_key_mismatch {
                warn!(
                    "{} for {qname} from {} refused: {}",
                    q.qtype(),
                    req.client_addr(),
                    reason
                );
                let response =
                    mk_error_response(req.message(), OptRcode::NOTAUTH);
                return ControlFlow::Break(Self::to_stream(response));
            }
        }

        // Read the zone SOA RR
        let read = zone.read();
        let Ok(zone_soa_answer) = Self::read_soa(&read, qname.clone()).await
        else {
            warn!(
                "{} for {qname} from {} refused: name is outside the zone",
                q.qtype(),
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

            Rtype::AXFR | Rtype::IXFR if xfr_config.is_none() => {
                ControlFlow::Break(Self::to_stream(mk_error_response(
                    msg,
                    OptRcode::REFUSED,
                )))
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
                    let stream = Self::do_axfr(
                        zone_walking_semaphore,
                        batcher_semaphore,
                        req,
                        qname,
                        &zone_soa_answer,
                        cat_zone.info(),
                        read,
                    )
                    .await
                    .unwrap_or_else(|rcode| {
                        Self::to_stream(mk_error_response(msg, rcode))
                    });
                    ControlFlow::Break(stream)
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
                    &zone_soa_answer,
                    cat_zone.info(),
                    xfr_mode,
                )
                .await
                {
                    IxfrResult::Ok(stream) => ControlFlow::Break(stream),
                    IxfrResult::FallbackToAxfr => {
                        if xfr_config.unwrap().strategy
                            != XfrStrategy::IxfrWithAxfrFallback
                        {
                            info!(
                                "IXFR for {qname} from {} refused: client is not permitted to fallback to AXFR",
                                req.client_addr()
                            );
                            ControlFlow::Break(Self::to_stream(
                                mk_error_response(msg, OptRcode::REFUSED),
                            ))
                        } else {
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
                            let stream = Self::do_axfr(
                                zone_walking_semaphore,
                                batcher_semaphore,
                                req,
                                qname,
                                &zone_soa_answer,
                                cat_zone.info(),
                                read,
                            )
                            .await
                            .unwrap_or_else(|rcode| {
                                Self::to_stream(mk_error_response(msg, rcode))
                            });
                            ControlFlow::Break(stream)
                        }
                    }

                    IxfrResult::Err(rcode) => ControlFlow::Break(
                        Self::to_stream(mk_error_response(msg, rcode)),
                    ),
                }
            }

            _ => ControlFlow::Continue(()),
        }
    }

    fn settings_for_client<'a>(
        client_ip: IpAddr,
        qname: &Name<Bytes>,
        qtype: Rtype,
        zone_info: &'a ZoneInfo,
    ) -> Option<&'a XfrConfig> {
        if qtype == Rtype::SOA {
            return None;
        }

        if zone_info.config().provide_xfr_to.is_empty() {
            warn!(
                "{qtype} for {qname} from {client_ip} refused: zone does not allow XFR",
            );
            return None;
        };

        let Some(xfr_config) =
            zone_info.config().provide_xfr_to.src(client_ip)
        else {
            warn!(
                "{qtype} for {qname} from {client_ip} refused: client is not permitted to transfer this zone",
            );
            return None;
        };

        if matches!(
            (qtype, xfr_config.strategy),
            (Rtype::AXFR, XfrStrategy::IxfrOnly)
                | (Rtype::IXFR, XfrStrategy::AxfrOnly)
        ) {
            if qtype != Rtype::SOA {
                warn!(
                    "{qtype} for {qname} from {client_ip} refused: zone does not allow {qtype}",
                );
            }
            return None;
        }

        Some(xfr_config)
    }

    #[allow(clippy::too_many_arguments)]
    async fn do_axfr<T>(
        zone_walk_semaphore: Arc<Semaphore>,
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, T>,
        qname: Name<Bytes>,
        zone_soa_answer: &Answer,
        zone_info: &ZoneInfo,
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

        let Some(xfr_config) = zone_info
            .config()
            .provide_xfr_to
            .src(req.client_addr().ip())
        else {
            unreachable!();
        };

        let compatibility_mode = xfr_config.compatibility_mode
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
                        error!("Internal error: Failed to send final AXFR SOA to batcher");
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
        zone_soa_answer: &Answer,
        zone_info: &ZoneInfo,
        xfr_mode: XfrMode,
    ) -> IxfrResult<
        XfrMiddlewareStream<
            NextSvc::Future,
            NextSvc::Stream,
            <NextSvc::Stream as Stream>::Item,
        >,
    > {
        if xfr_mode == XfrMode::AxfrOnly {
            trace!("Not responding with IXFR as mode is set to AXFR only");
            return IxfrResult::FallbackToAxfr;
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
        if let Ok(mut query_soas) = msg
            .authority()
            .map(|section| section.limit_to::<Soa<ParsedName<_>>>())
        {
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
                                    query_serial,
                                    zone_serial,
                                    zone_info,
                                    zone_soa_answer,
                                )
                                .await;
                            }
                        }
                    }

                    return IxfrResult::Err(OptRcode::SERVFAIL);
                }
            }
        }

        IxfrResult::Err(OptRcode::FORMERR)
    }

    #[allow(clippy::too_many_arguments)]
    async fn compute_ixfr<T>(
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, T>,
        query_serial: Serial,
        zone_serial: Serial,
        zone_info: &ZoneInfo,
        zone_soa_answer: &Answer,
    ) -> IxfrResult<
        XfrMiddlewareStream<
            NextSvc::Future,
            NextSvc::Stream,
            <NextSvc::Stream as Stream>::Item,
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
            return IxfrResult::Ok(Self::to_stream(response));
        }

        // Get the necessary diffs, if available
        let start_serial = query_serial;
        let end_serial = zone_serial;
        let diffs = zone_info.diffs_for_range(start_serial, end_serial).await;
        if diffs.is_empty() {
            trace!("No diff available for IXFR");
            return IxfrResult::FallbackToAxfr;
        };

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

        IxfrResult::Ok(MiddlewareStream::Result(stream))
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
                if matches!(q.qtype(), Rtype::SOA | Rtype::AXFR | Rtype::IXFR)
                {
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
