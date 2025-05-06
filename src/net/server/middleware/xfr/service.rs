use core::future::{ready, Future, Ready};
use core::marker::PhantomData;
use core::ops::ControlFlow;

use std::boxed::Box;
use std::fmt::Debug;
use std::pin::Pin;
use std::sync::Arc;
use std::vec::Vec;

use futures_util::stream::{once, Once, Stream};
use octseq::Octets;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::Semaphore;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{debug, error, info, trace, warn};

use crate::base::iana::{Opcode, OptRcode};
use crate::base::{Message, ParsedName, Question, Rtype, Serial, ToName};
use crate::net::server::message::{Request, TransportSpecificContext};
use crate::net::server::middleware::stream::MiddlewareStream;
use crate::net::server::middleware::xfr::axfr::ZoneFunneler;
use crate::net::server::middleware::xfr::data_provider::XfrDataProvider;
use crate::net::server::middleware::xfr::data_provider::XfrDataProviderError;
use crate::net::server::middleware::xfr::ixfr::DiffFunneler;
use crate::net::server::middleware::xfr::responder::BatchingRrResponder;
use crate::net::server::service::{CallResult, Service, ServiceFeedback};
use crate::net::server::util::{mk_builder_for_target, mk_error_response};
use crate::rdata::{Soa, ZoneRecordData};
use crate::zonetree::{
    Answer, AnswerContent, ReadableZone, SharedRrset, StoredName,
};

use super::util::{add_to_stream, read_soa};

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
pub struct XfrMiddlewareSvc<RequestOctets, NextSvc, RequestMeta, XDP>
where
    RequestOctets: Octets + Send + Sync + Unpin + 'static + Clone,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc:
        Service<RequestOctets, RequestMeta> + Clone + Send + Sync + 'static,
    NextSvc::Future: Sync + Unpin,
    NextSvc::Stream: Sync,
    XDP: XfrDataProvider<RequestMeta> + Clone + Sync + Send + 'static,
    XDP::Diff: Debug + Sync,
    RequestMeta: Clone + Default + Sync + Send + 'static,
{
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

    _phantom: PhantomData<(RequestOctets, RequestMeta)>,
}

impl<RequestOctets, NextSvc, RequestMeta, XDP>
    XfrMiddlewareSvc<RequestOctets, NextSvc, RequestMeta, XDP>
where
    RequestOctets: Octets + Send + Sync + Unpin + 'static + Clone,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc:
        Service<RequestOctets, RequestMeta> + Clone + Send + Sync + 'static,
    NextSvc::Future: Sync + Unpin,
    NextSvc::Stream: Sync,
    XDP: XfrDataProvider<RequestMeta> + Clone + Sync + Send + 'static,
    XDP::Diff: Debug + Sync,
    RequestMeta: Clone + Default + Sync + Send + 'static,
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

impl<RequestOctets, NextSvc, RequestMeta, XDP>
    XfrMiddlewareSvc<RequestOctets, NextSvc, RequestMeta, XDP>
where
    RequestOctets: Octets + Send + Sync + Unpin + 'static + Clone,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc:
        Service<RequestOctets, RequestMeta> + Clone + Send + Sync + 'static,
    NextSvc::Future: Sync + Unpin,
    NextSvc::Stream: Sync,
    XDP: XfrDataProvider<RequestMeta> + Clone + Sync + Send + 'static,
    XDP::Diff: Debug + Sync,
    RequestMeta: Clone + Default + Sync + Send + 'static,
{
    /// Pre-process received DNS XFR queries.
    ///
    /// Other types of query will be propagated unmodified to the next
    /// middleware or application service in the layered stack of services.
    ///
    /// Data to respond to the query will be requested from the given
    /// [`XfrDataProvider`] which will act according to its policy concerning
    /// the given [`Request`].
    pub async fn preprocess(
        zone_walking_semaphore: Arc<Semaphore>,
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, RequestMeta>,
        xfr_data_provider: XDP,
    ) -> Result<
        ControlFlow<
            XfrMiddlewareStream<
                NextSvc::Future,
                NextSvc::Stream,
                <NextSvc::Stream as Stream>::Item,
            >,
        >,
        OptRcode,
    > {
        let msg = req.message();

        // Do we support this type of request?
        let Some(q) = Self::get_relevant_question(msg) else {
            return Ok(ControlFlow::Continue(()));
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
            warn!(
                "{} for {} from {} refused: IXFR request lacks authority section SOA",
                q.qtype(),
                q.qname(),
                req.client_addr()
            );
            return Err(OptRcode::FORMERR);
        }

        // Is transfer allowed for the requested zone for this requestor?
        let xfr_data = xfr_data_provider
            .request(req, ixfr_query_serial)
            .await
            .map_err(|err| match err {
                XfrDataProviderError::ParseError(err) => {
                    debug!(
                        "{} for {} from {} refused: parse error: {err}",
                        q.qtype(),
                        q.qname(),
                        req.client_addr()
                    );
                    OptRcode::FORMERR
                }

                XfrDataProviderError::UnknownZone => {
                    // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2.1
                    // 2.2.1 Header Values
                    //   "If a server is not authoritative for the queried
                    //    zone, the server SHOULD set the value to NotAuth(9)"
                    debug!(
                        "{} for {} from {} refused: unknown zone",
                        q.qtype(),
                        q.qname(),
                        req.client_addr()
                    );
                    OptRcode::NOTAUTH
                }

                XfrDataProviderError::TemporarilyUnavailable => {
                    // The zone is not yet loaded or has expired, both of
                    // which are presumably transient conditions and thus
                    // SERVFAIL is the appropriate response, not NOTAUTH, as
                    // we know we are supposed to be authoritative for the
                    // zone but we just don't have the data right now.
                    warn!(
                        "{} for {} from {} refused: zone not currently available",
                        q.qtype(),
                        q.qname(),
                        req.client_addr()
                    );
                    OptRcode::SERVFAIL
                }

                XfrDataProviderError::Refused => {
                    warn!(
                        "{} for {} from {} refused: access denied",
                        q.qtype(),
                        q.qname(),
                        req.client_addr()
                    );
                    OptRcode::REFUSED
                }
            })?;

        // Read the zone SOA RR
        let read = xfr_data.zone().read();
        let Ok(zone_soa_answer) = read_soa(&read, q.qname().to_name()).await
        else {
            debug!(
                "{} for {} from {} refused: name is outside the zone",
                q.qtype(),
                q.qname(),
                req.client_addr()
            );
            return Err(OptRcode::SERVFAIL);
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
                warn!(
                    "{} for {} from {} refused: AXFR not supported over UDP",
                    q.qtype(),
                    q.qname(),
                    req.client_addr()
                );
                let response = mk_error_response(msg, OptRcode::NOTIMP);
                let res = Ok(CallResult::new(response));
                Ok(ControlFlow::Break(MiddlewareStream::Map(once(ready(
                    res,
                )))))
            }

            Rtype::AXFR | Rtype::IXFR if xfr_data.diffs().is_empty() => {
                if q.qtype() == Rtype::IXFR && xfr_data.diffs().is_empty() {
                    // https://datatracker.ietf.org/doc/html/rfc1995#section-4
                    // 4. Response Format
                    //    "If incremental zone transfer is not available, the
                    //     entire zone is returned.  The first and the last RR of
                    //     the response is the SOA record of the zone. I.e. the
                    //     behavior is the same as an AXFR response except the
                    //     query type is IXFR."
                    info!(
                        "IXFR for {} (serial {} from {}: diffs not available, falling back to AXFR",
                        q.qname(),
                        ixfr_query_serial.unwrap(), // SAFETY: Always Some() if IXFR
                        req.client_addr()
                    );
                } else {
                    info!(
                        "AXFR for {} from {}",
                        q.qname(),
                        req.client_addr()
                    );
                }
                let stream = Self::respond_to_axfr_query(
                    zone_walking_semaphore,
                    batcher_semaphore,
                    req,
                    q.qname().to_name(),
                    &zone_soa_answer,
                    read,
                    xfr_data.compatibility_mode(),
                )
                .await?;

                Ok(ControlFlow::Break(stream))
            }

            Rtype::IXFR => {
                // SAFETY: Always Some() if IXFR
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
                let stream = Self::respond_to_ixfr_query(
                    batcher_semaphore.clone(),
                    req,
                    ixfr_query_serial,
                    q.qname().to_name(),
                    &zone_soa_answer,
                    xfr_data.into_diffs(),
                )
                .await?;

                Ok(ControlFlow::Break(stream))
            }

            _ => {
                // Other QTYPEs should have been filtered out by get_relevant_question().
                unreachable!();
            }
        }
    }

    /// Generate and send an AXFR response for a given request and zone.
    #[allow(clippy::too_many_arguments)]
    async fn respond_to_axfr_query<T>(
        zone_walk_semaphore: Arc<Semaphore>,
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, T>,
        qname: StoredName,
        zone_soa_answer: &Answer,
        read: Box<dyn ReadableZone>,
        compatibility_mode: bool,
    ) -> Result<
        XfrMiddlewareStream<
            NextSvc::Future,
            NextSvc::Stream,
            <NextSvc::Stream as Stream>::Item,
        >,
        OptRcode,
    > {
        let AnswerContent::Data(zone_soa_rrset) =
            zone_soa_answer.content().clone()
        else {
            error!(
                "AXFR for {qname} from {} refused: zone lacks SOA RR",
                req.client_addr()
            );
            return Err(OptRcode::SERVFAIL);
        };

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

        let soft_byte_limit = Self::calc_msg_bytes_available(req);

        // Create a stream that will be immediately returned to the caller.
        // Async tasks will then push DNS response messages into the stream as
        // they become available.
        let (response_tx, response_rx) = unbounded_channel();
        let stream = UnboundedReceiverStream::new(response_rx);

        // Create a bounded queue for passing RRsets found during zone walking
        // to a task which will batch the RRs together before pushing them
        // into the result stream.
        let (batcher_tx, batcher_rx) =
            tokio::sync::mpsc::channel::<(StoredName, SharedRrset)>(100);

        let must_fit_in_single_message =
            matches!(req.transport_ctx(), TransportSpecificContext::Udp(_));

        if !must_fit_in_single_message {
            // Notify the underlying transport to expect a stream of related
            // responses. The transport should modify its behaviour to account
            // for the potentially slow and long running nature of a
            // transaction.
            add_to_stream(ServiceFeedback::BeginTransaction, &response_tx);
        }

        // Enqueue the zone SOA RRset for the batcher to process.
        if batcher_tx
            .send((qname.clone(), zone_soa_rrset.clone()))
            .await
            .is_err()
        {
            return Err(OptRcode::SERVFAIL);
        }

        let msg = req.message().clone();

        // Stream the remaining non-SOA zone RRsets in the background to the
        // batcher.
        let zone_funneler = ZoneFunneler::new(
            read,
            qname,
            zone_soa_rrset,
            batcher_tx,
            zone_walk_semaphore,
        );

        let batching_responder = BatchingRrResponder::new(
            req.message().clone(),
            zone_soa_answer.clone(),
            batcher_rx,
            response_tx.clone(),
            compatibility_mode,
            soft_byte_limit,
            must_fit_in_single_message,
            batcher_semaphore,
        );

        let cloned_msg = msg.clone();
        let cloned_response_tx = response_tx.clone();

        // Start the funneler. It will walk the zone and send all of the RRs
        // one at a time to the batching responder.
        tokio::spawn(async move {
            if let Err(rcode) = zone_funneler.run().await {
                add_to_stream(
                    mk_error_response(&cloned_msg, rcode),
                    &cloned_response_tx,
                );
            }
        });

        // Start the batching responder. It will receive RRs from the funneler
        // and push them in batches into the response stream.
        tokio::spawn(async move {
            match batching_responder.run().await {
                Ok(()) => {
                    trace!("Ending transaction");
                    add_to_stream(
                        ServiceFeedback::EndTransaction,
                        &response_tx,
                    );
                }

                Err(rcode) => {
                    add_to_stream(
                        mk_error_response(&msg, rcode),
                        &response_tx,
                    );
                }
            }
        });

        // If either the funneler or batcher responder terminate then so will
        // the other as they each own half of a send <-> receive channel and
        // abort if the other side of the channel is gone.

        Ok(MiddlewareStream::Result(stream))
    }

    // Generate and send an IXFR response for the given request and zone
    // diffs.
    #[allow(clippy::too_many_arguments)]
    async fn respond_to_ixfr_query<T>(
        batcher_semaphore: Arc<Semaphore>,
        req: &Request<RequestOctets, T>,
        query_serial: Serial,
        qname: StoredName,
        zone_soa_answer: &Answer,
        diffs: Vec<XDP::Diff>,
    ) -> Result<
        XfrMiddlewareStream<
            NextSvc::Future,
            NextSvc::Stream,
            <NextSvc::Stream as Stream>::Item,
        >,
        OptRcode,
    >
    where
        XDP::Diff: Send + 'static,
    {
        let msg = req.message();

        let AnswerContent::Data(zone_soa_rrset) =
            zone_soa_answer.content().clone()
        else {
            return Err(OptRcode::SERVFAIL);
        };
        let Some(first_rr) = zone_soa_rrset.first() else {
            return Err(OptRcode::SERVFAIL);
        };
        let ZoneRecordData::Soa(soa) = first_rr.data() else {
            return Err(OptRcode::SERVFAIL);
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
        if query_serial >= soa.serial() {
            trace!("Responding to IXFR with single SOA because query serial >= zone serial");
            let builder = mk_builder_for_target();
            let response = zone_soa_answer.to_message(msg, builder);
            let res = Ok(CallResult::new(response));
            return Ok(MiddlewareStream::Map(once(ready(res))));
        }

        // TODO: Add something like the Bind `max-ixfr-ratio` option that
        // "sets the size threshold (expressed as a percentage of the size of
        // the full zone) beyond which named chooses to use an AXFR response
        // rather than IXFR when answering zone transfer requests"?

        let soft_byte_limit = Self::calc_msg_bytes_available(req);

        // Create a stream that will be immediately returned to the caller.
        // Async tasks will then push DNS response messages into the stream as
        // they become available.
        let (response_tx, response_rx) = unbounded_channel();
        let stream = UnboundedReceiverStream::new(response_rx);

        // Create a bounded queue for passing RRsets found during diff walking
        // to a task which will batch the RRs together before pushing them
        // into the result stream.
        let (batcher_tx, batcher_rx) =
            tokio::sync::mpsc::channel::<(StoredName, SharedRrset)>(100);

        let must_fit_in_single_message =
            matches!(req.transport_ctx(), TransportSpecificContext::Udp(_));

        if !must_fit_in_single_message {
            // Notify the underlying transport to expect a stream of related
            // responses. The transport should modify its behaviour to account
            // for the potentially slow and long running nature of a
            // transaction.
            add_to_stream(ServiceFeedback::BeginTransaction, &response_tx);
        }

        // Stream the IXFR diffs in the background to the batcher.
        let diff_funneler =
            DiffFunneler::new(qname, zone_soa_rrset, diffs, batcher_tx);

        let batching_responder = BatchingRrResponder::new(
            req.message().clone(),
            zone_soa_answer.clone(),
            batcher_rx,
            response_tx.clone(),
            false,
            soft_byte_limit,
            must_fit_in_single_message,
            batcher_semaphore,
        );

        let cloned_msg = msg.clone();
        let cloned_response_tx = response_tx.clone();

        // Start the funneler. It will walk the diffs and send all of the RRs
        // one at a time to the batching responder.
        tokio::spawn(async move {
            if let Err(rcode) = diff_funneler.run().await {
                add_to_stream(
                    mk_error_response(&cloned_msg, rcode),
                    &cloned_response_tx,
                );
            }
        });

        let cloned_msg = msg.clone();

        // Start the batching responder. It will receive RRs from the funneler
        // and push them in batches into the response stream.
        tokio::spawn(async move {
            match batching_responder.run().await {
                Ok(()) => {
                    trace!("Ending transaction");
                    add_to_stream(
                        ServiceFeedback::EndTransaction,
                        &response_tx,
                    );
                }

                Err(rcode) => {
                    add_to_stream(
                        mk_error_response(&cloned_msg, rcode),
                        &response_tx,
                    );
                }
            }
        });

        // If either the funneler or batcher responder terminate then so will
        // the other as they each own half of a send <-> receive channel and
        // abort if the other side of the channel is gone.

        Ok(MiddlewareStream::Result(stream))
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

impl<RequestOctets, NextSvc, RequestMeta, XDP>
    Service<RequestOctets, RequestMeta>
    for XfrMiddlewareSvc<RequestOctets, NextSvc, RequestMeta, XDP>
where
    RequestOctets: Octets + Send + Sync + Unpin + 'static + Clone,
    for<'a> <RequestOctets as octseq::Octets>::Range<'a>: Send + Sync,
    NextSvc:
        Service<RequestOctets, RequestMeta> + Clone + Send + Sync + 'static,
    NextSvc::Future: Sync + Unpin,
    NextSvc::Stream: Sync,
    XDP: XfrDataProvider<RequestMeta> + Clone + Sync + Send + 'static,
    XDP::Diff: Debug + Sync,
    RequestMeta: Clone + Default + Sync + Send + 'static,
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
        request: Request<RequestOctets, RequestMeta>,
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
                Ok(ControlFlow::Continue(())) => {
                    let request =
                        request.with_new_metadata(Default::default());
                    let stream = next_svc.call(request).await;
                    MiddlewareStream::IdentityStream(stream)
                }

                Ok(ControlFlow::Break(stream)) => stream,

                Err(rcode) => {
                    let response =
                        mk_error_response(request.message(), rcode);
                    let res = Ok(CallResult::new(response));
                    MiddlewareStream::Map(once(ready(res)))
                }
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
