//! Loads a zone file and serves it over localhost UDP and TCP.
//!
//! Try queries such as:
//!
//!   dig @127.0.0.1 -p 8053 NS example.com
//!   dig @127.0.0.1 -p 8053 A example.com
//!   dig @127.0.0.1 -p 8053 AAAA example.com
//!   dig @127.0.0.1 -p 8053 CNAME example.com
//!
//! Also try with TCP, e.g.:
//!
//!   dig @127.0.0.1 -p 8053 +tcp A example.com
//!
//! Also try AXFR, e.g.:
//!
//!   dig @127.0.0.1 -p 8053 AXFR example.com

use domain::base::iana::{Opcode, Rcode};
use domain::base::message_builder::AdditionalBuilder;
use domain::base::{Dname, Message, Rtype, ToDname};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::middleware::cookies::CookiesMiddlewareSvc;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::service::{CallResult, ServiceError};
use domain::net::server::stream::StreamServer;
use domain::net::server::util::{mk_builder_for_target, service_fn};
use domain::zonefile::inplace;
use domain::zonetree::{Answer, Rrset};
use domain::zonetree::{Zone, ZoneTree};
use futures::stream::{once, FuturesOrdered, Once};
use futures::StreamExt;
use octseq::OctetsBuilder;
use std::future::{pending, ready, Future};
use std::io::BufReader;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tracing_subscriber::EnvFilter;

#[tokio::main()]
async fn main() {
    // Initialize tracing based logging. Override with env var RUST_LOG, e.g.
    // RUST_LOG=trace.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        .try_init()
        .ok();

    // Populate a zone tree with test data
    let mut zones = ZoneTree::new();
    let zone_bytes = include_bytes!("../test-data/zonefiles/nsd-example.txt");
    let mut zone_bytes = BufReader::new(&zone_bytes[..]);

    // We're reading from static data so this cannot fail due to I/O error.
    // Don't handle errors that shouldn't happen, keep the example focused
    // on what we want to demonstrate.
    let reader = inplace::Zonefile::load(&mut zone_bytes).unwrap();
    let zone = Zone::try_from(reader).unwrap();
    zones.insert_zone(zone).unwrap();
    let zones = Arc::new(zones);

    let addr = "127.0.0.1:8053";
    let business_svc = service_fn(my_service, zones);

    let svc = Arc::new(MandatoryMiddlewareSvc::new(EdnsMiddlewareSvc::new(
        CookiesMiddlewareSvc::with_random_secret(business_svc),
    )));

    let sock = UdpSocket::bind(addr).await.unwrap();
    let sock = Arc::new(sock);
    let mut udp_metrics = vec![];
    let num_cores = std::thread::available_parallelism().unwrap().get();
    for _i in 0..num_cores {
        let udp_srv =
            DgramServer::new(sock.clone(), VecBufSource, svc.clone());
        let metrics = udp_srv.metrics();
        udp_metrics.push(metrics);
        tokio::spawn(async move { udp_srv.run().await });
    }

    let sock = TcpListener::bind(addr).await.unwrap();
    let tcp_srv = StreamServer::new(sock, VecBufSource, svc);
    let tcp_metrics = tcp_srv.metrics();

    tokio::spawn(async move { tcp_srv.run().await });

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(5000)).await;
            for (i, metrics) in udp_metrics.iter().enumerate() {
                eprintln!(
                    "Server status: UDP[{i}]: #conn={:?}, #in-flight={}, #pending-writes={}, #msgs-recvd={}, #msgs-sent={}",
                    metrics.num_connections(),
                    metrics.num_inflight_requests(),
                    metrics.num_pending_writes(),
                    metrics.num_received_requests(),
                    metrics.num_sent_responses(),
                );
            }
            eprintln!(
                "Server status: TCP: #conn={:?}, #in-flight={}, #pending-writes={}, #msgs-recvd={}, #msgs-sent={}",
                tcp_metrics.num_connections(),
                tcp_metrics.num_inflight_requests(),
                tcp_metrics.num_pending_writes(),
                tcp_metrics.num_received_requests(),
                tcp_metrics.num_sent_responses(),
            );
        }
    });

    pending::<()>().await;
}

enum SingleOrStream {
    Single(
        Once<
            Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<
                                CallResult<Vec<u8>>,
                                ServiceError,
                            >,
                        > + Send,
                >,
            >,
        >,
    ),

    Stream(
        Box<
            dyn futures::stream::Stream<
                    Item = Result<CallResult<Vec<u8>>, ServiceError>,
                > + Unpin
                + Send,
        >,
    ),
}

impl futures::stream::Stream for SingleOrStream {
    type Item = Result<CallResult<Vec<u8>>, ServiceError>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.deref_mut() {
            SingleOrStream::Single(s) => s.poll_next_unpin(cx),
            SingleOrStream::Stream(s) => s.poll_next_unpin(cx),
        }
    }
}

#[allow(clippy::type_complexity)]
fn my_service(
    request: Request<Vec<u8>>,
    zones: Arc<ZoneTree>,
) -> SingleOrStream {
    let qtype = request.message().sole_question().unwrap().qtype();
    match qtype {
        Rtype::AXFR if request.transport_ctx().is_non_udp() => {
            SingleOrStream::Stream(Box::new(handle_axfr_request(
                request, zones,
            )))
        }
        _ => SingleOrStream::Single(once(Box::pin(handle_non_axfr_request(
            request, zones,
        )))),
    }
}

async fn handle_non_axfr_request(
    request: Request<Vec<u8>>,
    zones: Arc<ZoneTree>,
) -> Result<CallResult<Vec<u8>>, ServiceError> {
    let question = request.message().sole_question().unwrap();
    let zone = zones
        .find_zone(question.qname(), question.qclass())
        .map(|zone| zone.read());
    let answer = match zone {
        Some(zone) => {
            let qname = question.qname().to_bytes();
            let qtype = question.qtype();
            zone.query(qname, qtype).unwrap()
        }
        None => Answer::new(Rcode::NXDOMAIN),
    };

    let builder = mk_builder_for_target();
    let additional = answer.to_message(request.message(), builder);
    Ok(CallResult::new(additional))
}

fn handle_axfr_request(
    request: Request<Vec<u8>>,
    zones: Arc<ZoneTree>,
) -> FuturesOrdered<
    Pin<
        Box<
            dyn Future<Output = Result<CallResult<Vec<u8>>, ServiceError>>
                + Send,
        >,
    >,
> {
    let mut stream = FuturesOrdered::<
        Pin<
            Box<
                dyn Future<Output = Result<CallResult<Vec<u8>>, ServiceError>>
                    + Send,
            >,
        >,
    >::new();

    // Look up the zone for the queried name.
    let question = request.message().sole_question().unwrap();
    let zone = zones
        .find_zone(question.qname(), question.qclass())
        .map(|zone| zone.read());

    // If not found, return an NXDOMAIN error response.
    let Some(zone) = zone else {
        let answer = Answer::new(Rcode::NXDOMAIN);
        add_to_stream(answer, request.message(), &mut stream);
        return stream;
    };

    // https://datatracker.ietf.org/doc/html/rfc5936#section-2.2
    // 2.2: AXFR Response
    //
    // "An AXFR response that is transferring the zone's contents
    //  will consist of a series (which could be a series of
    //  length 1) of DNS messages.  In such a series, the first
    //  message MUST begin with the SOA resource record of the
    //  zone, and the last message MUST conclude with the same SOA
    //  resource record.  Intermediate messages MUST NOT contain
    //  the SOA resource record.  The AXFR server MUST copy the
    //  Question section from the corresponding AXFR query message
    //  into the first response message's Question section.  For
    //  subsequent messages, it MAY do the same or leave the
    //  Question section empty."

    // Get the SOA record as AXFR transfers must start and end with the SOA
    // record. If not found, return a SERVFAIL error response.
    let qname = question.qname().to_bytes();
    let Ok(soa_answer) = zone.query(qname, Rtype::SOA) else {
        let answer = Answer::new(Rcode::SERVFAIL);
        add_to_stream(answer, request.message(), &mut stream);
        return stream;
    };

    // Push the begin SOA response message into the stream
    add_to_stream(soa_answer.clone(), request.message(), &mut stream);

    // "The AXFR protocol treats the zone contents as an unordered
    //  collection (or to use the mathematical term, a "set") of
    //  RRs.  Except for the requirement that the transfer must
    //  begin and end with the SOA RR, there is no requirement to
    //  send the RRs in any particular order or grouped into
    //  response messages in any particular way.  Although servers
    //  typically do attempt to send related RRs (such as the RRs
    //  forming an RRset, and the RRsets of a name) as a
    //  contiguous group or, when message space allows, in the
    //  same response message, they are not required to do so, and
    //  clients MUST accept any ordering and grouping of the
    //  non-SOA RRs.  Each RR SHOULD be transmitted only once, and
    //  AXFR clients MUST ignore any duplicate RRs received.
    //
    //  Each AXFR response message SHOULD contain a sufficient
    //  number of RRs to reasonably amortize the per-message
    //  overhead, up to the largest number that will fit within a
    //  DNS message (taking the required content of the other
    //  sections into account, as described below).
    //
    //  Some old AXFR clients expect each response message to
    //  contain only a single RR.  To interoperate with such
    //  clients, the server MAY restrict response messages to a
    //  single RR.  As there is no standard way to automatically
    //  detect such clients, this typically requires manual
    //  configuration at the server."

    let stream = Arc::new(Mutex::new(stream));
    let cloned_stream = stream.clone();
    let cloned_msg = request.message().clone();

    let op = Box::new(move |owner: Dname<_>, rrset: &Rrset| {
        if rrset.rtype() != Rtype::SOA {
            let builder = mk_builder_for_target();
            let mut answer =
                builder.start_answer(&cloned_msg, Rcode::NOERROR).unwrap();
            for item in rrset.data() {
                answer.push((owner.clone(), rrset.ttl(), item)).unwrap();
            }

            let additional = answer.additional();
            let mut stream = cloned_stream.lock().unwrap();
            add_additional_to_stream(additional, &cloned_msg, &mut stream);
        }
    });
    zone.walk(op);

    let mutex = Arc::try_unwrap(stream).unwrap();
    let mut stream = mutex.into_inner().unwrap();

    // Push the end SOA response message into the stream
    add_to_stream(soa_answer, request.message(), &mut stream);

    stream
}

#[allow(clippy::type_complexity)]
fn add_to_stream(
    answer: Answer,
    msg: &Message<Vec<u8>>,
    stream: &mut FuturesOrdered<
        Pin<
            Box<
                dyn Future<Output = Result<CallResult<Vec<u8>>, ServiceError>>
                    + Send,
            >,
        >,
    >,
) {
    let builder = mk_builder_for_target();
    let additional = answer.to_message(msg, builder);
    add_additional_to_stream(additional, msg, stream);
}

#[allow(clippy::type_complexity)]
fn add_additional_to_stream(
    mut additional: AdditionalBuilder<domain::base::StreamTarget<Vec<u8>>>,
    msg: &Message<Vec<u8>>,
    stream: &mut FuturesOrdered<
        Pin<
            Box<
                dyn Future<Output = Result<CallResult<Vec<u8>>, ServiceError>>
                    + Send,
            >,
        >,
    >,
) {
    set_axfr_header(msg, &mut additional);
    stream.push_back(Box::pin(ready(Ok(CallResult::new(additional)))));
}

fn set_axfr_header<Target>(
    msg: &Message<Vec<u8>>,
    additional: &mut AdditionalBuilder<Target>,
) where
    Target: AsMut<[u8]>,
    Target: OctetsBuilder,
{
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
