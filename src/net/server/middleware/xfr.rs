//! XFR request handling middleware.

// TODO: Add RRset combining in single responses.
use core::future::{ready, Future, Ready};
use core::marker::PhantomData;
use core::ops::ControlFlow;
use core::pin::Pin;

use core::sync::atomic::{AtomicUsize, Ordering};
use std::boxed::Box;
use std::sync::Arc;

use bytes::Bytes;
use futures::stream::{once, Once, Stream};
use octseq::Octets;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_stream::wrappers::UnboundedReceiverStream;
use tracing::{info, trace, warn};

use crate::base::iana::{Opcode, OptRcode, Rcode};
use crate::base::message_builder::AdditionalBuilder;
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
use crate::zonetree::{
    Answer, AnswerContent, ReadableZone, SharedRrset, StoredName,
};

use super::stream::MiddlewareStream;

//------------ ThreadPool ----------------------------------------------------

use crate::zonecatalog::catalog::{self, Catalog, CatalogZone};
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

    _phantom: PhantomData<RequestOctets>,
}

impl<RequestOctets, Svc> XfrMiddlewareSvc<RequestOctets, Svc> {
    /// Creates an empty processor instance.
    ///
    /// The processor will not respond to XFR requests until you add at least
    /// one zone to it.
    #[must_use]
    pub fn new(svc: Svc, catalog: Arc<Catalog>, num_threads: usize) -> Self {
        let pool = Self::mk_thread_pool(num_threads);

        Self {
            svc,
            catalog,
            pool,
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
                "{} for {}, from {} refused: unknown zone",
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
                "{} for {}, from {} refused: zone lacks SOA RR",
                q.qtype(),
                q.qname(),
                req.client_addr()
            );
            return ControlFlow::Break(Self::to_stream(mk_error_response(
                msg,
                OptRcode::SERVFAIL,
            )));
        };

        // Handle a SOA query
        if Rtype::SOA == q.qtype() {
            let builder = mk_builder_for_target();
            let response = zone_soa_answer.to_message(msg, builder);
            return ControlFlow::Break(Self::to_stream(response));
        }

        // Handle an IXFR query
        if Rtype::IXFR == q.qtype() {
            let cat_zone = zone
                .as_ref()
                .as_any()
                .downcast_ref::<CatalogZone>()
                .unwrap();

            info!("IXFR for {}, from {}", q.qname(), req.client_addr());
            if let Some(res) =
                Self::do_ixfr(msg, qname, &zone_soa_answer, cat_zone.info())
                    .await
            {
                return res;
            } else {
                info!(
                    "Falling back to AXFR for {}, from {}",
                    q.qname(),
                    req.client_addr()
                );
            }
        }

        // Handle an AXFR query, or fall back to AXFR from IXFR if IXFR is not
        // available
        info!("AXFR for {}, from {}", q.qname(), req.client_addr());
        Self::do_axfr(msg, &zone_soa_answer, read, pool).await
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
            <Svc::Stream as Stream>::Item,
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

        let msg = msg.clone();
        let zone_soa_answer = zone_soa_answer.clone();

        // Stream the RRsets in the background
        tokio::spawn(async move {
            let cloned_sender = sender.clone();
            let cloned_msg = msg.clone();

            // TODO: Add batching of RRsets into single DNS responses instead
            // of one response per RRset. Perhaps via a response combining
            // middleware service?

            // Define a zone tree walking operation like a filter map that
            // selects non-SOA RRsets and emits them to the output stream.
            let num_writes_pending = Arc::new(AtomicUsize::new(0));
            let num_writes_pending2 = num_writes_pending.clone();
            let op =
                Box::new(move |owner: StoredName, rrset: &SharedRrset| {
                    if rrset.rtype() != Rtype::SOA {
                        let cloned_owner = owner.clone();
                        let cloned_rrset = rrset.clone();
                        let cloned_msg2 = cloned_msg.clone();
                        let cloned_sender = cloned_sender.clone();
                        let cloned_num_writes_pending2 =
                            num_writes_pending2.clone();

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
                        num_writes_pending2.fetch_add(1, Ordering::SeqCst);
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
                                cloned_num_writes_pending2
                                    .fetch_sub(1, Ordering::SeqCst);
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

            loop {
                let n = num_writes_pending.load(Ordering::SeqCst);
                if n == 0 {
                    break;
                }
                trace!("Waiting for {n} stream writes to complete");
                tokio::time::sleep(tokio::time::Duration::from_millis(100))
                    .await;
            }

            Self::add_msg_to_stream(&zone_soa_answer, &msg, &sender);

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
        zone_info: &catalog::ZoneInfo,
    ) -> Option<
        ControlFlow<
            XfrMiddlewareStream<
                Svc::Future,
                Svc::Stream,
                <Svc::Stream as Stream>::Item,
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
        msg: &Arc<Message<RequestOctets>>,
        qname: Name<Bytes>,
        query_serial: Serial,
        zone_serial: Serial,
        zone_info: &catalog::ZoneInfo,
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
            return Some(ControlFlow::Break(Self::to_stream(response)));
        }

        // Get the necessary diffs, if available
        let start_serial = query_serial;
        let end_serial = zone_serial;
        let diffs = zone_info.diffs_for_range(start_serial, end_serial).await;
        if diffs.is_empty() {
            // Fallback to AXFR
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
        Self::add_msg_to_stream(zone_soa_answer, msg, &sender);

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

                Self::add_msg_to_stream(
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
                    Self::add_msg_to_stream(&answer, &msg, &sender);
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

                Self::add_msg_to_stream(
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
                    Self::add_msg_to_stream(&answer, &msg, &sender);
                }
            }

            // https://datatracker.ietf.org/doc/html/rfc1995#section-4
            // 4. Response Format
            //   "If incremental zone transfer is available, one or more
            //    difference sequences is returned.  The list of difference
            //    sequences is preceded and followed by a copy of the server's
            //    current version of the SOA."
            Self::add_msg_to_stream(&zone_soa_answer, &msg, &sender);

            Self::add_to_stream(
                CallResult::feedback_only(ServiceFeedback::EndTransaction),
                &sender,
            );
        });

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
        Box::pin(async move {
            match Self::preprocess(&request, catalog, pool).await {
                ControlFlow::Continue(()) => {
                    let stream = svc.call(request).await;
                    MiddlewareStream::IdentityStream(stream)
                }
                ControlFlow::Break(stream) => stream,
            }
        })
    }
}
