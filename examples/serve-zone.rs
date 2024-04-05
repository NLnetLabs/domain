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
use domain::base::name::FlattenInto;
use domain::base::Rtype::{self, Axfr};
use domain::base::{Dname, Message, ToDname};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::service::{
    CallResult, ServiceError, Transaction, TransactionStream,
};
use domain::net::server::stream::{self, StreamServer};
use domain::net::server::util::{mk_builder_for_target, service_fn};
use domain::zonefile::inplace::Entry;
use domain::zonefile::{inplace, parsed};
use domain::zonetree::{Answer, SharedRrset};
use domain::zonetree::{Zone, ZoneTree};
use octseq::OctetsBuilder;
use std::fs::File;
use std::future::{pending, ready, Future};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::trace;
use tracing_subscriber::EnvFilter;
use domain::net::server::ConnectionConfig;

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
    let mut args = std::env::args();
    let _prog_name = args.next().unwrap();
    let mut set = JoinSet::new();
    for zonefile in args {
        set.spawn(async {
            eprintln!("Loading {zonefile}...");
            let mut zone_bytes = File::open(zonefile).unwrap();
            let reader = inplace::Zonefile::load(&mut zone_bytes).unwrap();
            let mut zonefile = parsed::Zonefile::default();

            for res in reader {
                match res {
                    Ok(Entry::Record(r)) => {
                        if let Err(_err) = zonefile.insert(r.flatten_into()) {
                            // eprintln!("Err: {err}");
                        }
                    }
                    entry => {
                        trace!(
                            "Skipping unsupported zone file entry: {entry:?}"
                        )
                    }
                }
            }

            let zone: Zone<MetaType> = zonefile.try_into().unwrap();
            zone
        });
    }

    // We're reading from static data so this cannot fail due to I/O error.
    // Don't handle errors that shouldn't happen, keep the example focused
    // on what we want to demonstrate.
    // let reader = inplace::Zonefile::load(&mut zone_bytes).unwrap();
    // let zone = Zone::try_from(reader).unwrap();
    while let Some(Ok(zone)) = set.join_next().await {
        eprintln!("Inserting zone {}", zone.apex_name());
        zones.insert_zone(zone).unwrap();
    }
    let zones = Arc::new(zones);

    let addr = "127.0.0.1:8053";
    let svc = Arc::new(service_fn(my_service, zones));

    let sock = UdpSocket::bind(addr).await.unwrap();
    let sock = Arc::new(sock);
    let mut udp_metrics = vec![];
    let num_cores = std::thread::available_parallelism().unwrap().get();
    for _i in 0..1 {//num_cores {
        let udp_srv =
            DgramServer::new(sock.clone(), VecBufSource, svc.clone());
        let metrics = udp_srv.metrics();
        udp_metrics.push(metrics);
        tokio::spawn(async move { udp_srv.run().await });
    }

    let sock = TcpListener::bind(addr).await.unwrap();
    let mut conn_config = ConnectionConfig::new();
    // conn_config.set_max_queued_responses(1024);
    let mut config = stream::Config::new();
    config.set_connection_config(conn_config);
    let tcp_srv = StreamServer::with_config(sock, VecBufSource, svc, config);
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

#[allow(clippy::type_complexity)]
fn my_service(
    request: Request<Message<Vec<u8>>>,
    zones: Arc<ZoneTree<MetaType>>,
) -> Result<
    Transaction<
        Vec<u8>,
        Vec<u8>,
        impl Future<
                Output = Result<CallResult<Vec<u8>, Vec<u8>>, ServiceError>,
            > + Send,
    >,
    ServiceError,
> {
    let qtype = request.message().sole_question().unwrap().qtype();
    match qtype {
        Axfr if request.transport().is_non_udp() => {
            let fut = handle_axfr_request(request, zones);
            Ok(Transaction::stream(Box::pin(fut)))
        }
        _ => {
            let fut = handle_non_axfr_request(request, zones);
            Ok(Transaction::single(fut))
        }
    }
}

async fn handle_non_axfr_request(
    msg: Request<Message<Vec<u8>>>,
    zones: Arc<ZoneTree<MetaType>>,
) -> Result<CallResult<Vec<u8>, Vec<u8>>, ServiceError> {
    let question = msg.message().sole_question().unwrap();
    let zone = zones
        .find_zone(question.qname(), question.qclass())
        .map(|zone| zone.read());
    let answer = match zone {
        Some(zone) => {
            let qname = question.qname().to_bytes();
            let qtype = question.qtype();
            zone.query(qname, qtype).unwrap()
        }
        None => Answer::new(Rcode::NXDomain),
    };

    let builder = mk_builder_for_target();
    let additional = answer.to_message(msg.message(), builder);
    Ok(CallResult::new(additional))
}

async fn handle_axfr_request(
    msg: Request<Message<Vec<u8>>>,
    zones: Arc<ZoneTree<MetaType>>,
) -> TransactionStream<Result<CallResult<Vec<u8>, Vec<u8>>, ServiceError>> {
    let mut stream = TransactionStream::default();
    stream.wait(3).await;

    // Look up the zone for the queried name.
    let question = msg.message().sole_question().unwrap();
    let zone = zones
        .find_zone(question.qname(), question.qclass())
        .map(|zone| zone.read());

    // If not found, return an NXDOMAIN error response.
    let Some(zone) = zone else {
        let answer = Answer::new(Rcode::NXDomain);
        add_to_stream(answer, msg.message(), &stream).await;
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
    let Ok(soa_answer) = zone.query(qname, Rtype::Soa) else {
        let answer = Answer::new(Rcode::ServFail);
        add_to_stream(answer, msg.message(), &stream).await;
        return stream;
    };

    // Push the begin SOA response message into the stream
    eprintln!("******** SENDING START SOA ********");
    add_to_stream(soa_answer.clone(), msg.message(), &stream).await;

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

    let cloned_stream = stream.clone();
    let cloned_msg = msg.message().clone();
    let semaphore = Arc::new(Semaphore::new(3));

    tokio::spawn(async move {
        let op = move |owner: Dname<_>,
                       rrset: SharedRrset,
                       meta: Option<MetaType>| {
            do_it(owner, rrset.clone(), meta)
        };

        let meta = MetaType::new(
            cloned_msg.clone(),
            semaphore.clone(),
            cloned_stream.clone(),
        );

        zone.walk(Box::pin(op), meta);

        // Push the end SOA response message into the stream
        eprintln!("******** SENDING END SOA ********");
        add_to_stream(soa_answer, msg.message(), &cloned_stream).await;

        cloned_stream.done();
    });

    stream
}

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug)]
struct MetaType {
    message: Arc<Message<Vec<u8>>>,
    semaphore: Arc<Semaphore>,
    transaction_stream:
        TransactionStream<Result<CallResult<Vec<u8>, Vec<u8>>, ServiceError>>,
}

#[allow(clippy::type_complexity)]
impl MetaType {
    pub fn new(
        message: Arc<Message<Vec<u8>>>,
        semaphore: Arc<Semaphore>,
        transaction_stream: TransactionStream<
            Result<CallResult<Vec<u8>, Vec<u8>>, ServiceError>,
        >,
    ) -> Self {
        Self {
            message,
            semaphore,
            transaction_stream,
        }
    }

    pub fn message(&self) -> &Arc<Message<Vec<u8>>> {
        &self.message
    }

    pub fn semaphore(&self) -> &Arc<Semaphore> {
        &self.semaphore
    }

    pub fn transaction_stream(
        &self,
    ) -> &TransactionStream<Result<CallResult<Vec<u8>, Vec<u8>>, ServiceError>>
    {
        &self.transaction_stream
    }
}

// fn s<Octs: AsRef<[u8]> + Clone + Send + 'static>(
//     owner: Dname<Octs>,
//     rrset: &SharedRrset,
//     meta: MetaType,
// ) -> Pin<Box<Pin<Box<dyn Future<Output = ()>>>>> {
//     Box::pin(t(
//         owner,
//         rrset,
//         meta,
//     ))
// }

fn do_it<Octs: AsRef<[u8]> + Clone + Send + Sync + 'static>(
    owner: Dname<Octs>,
    rrset: SharedRrset,
    meta: Option<MetaType>,
) -> Pin<Box<(dyn Future<Output = ()> + Send + Sync + 'static)>> {
    let Some(meta) = meta else { unreachable!() };
    Box::pin(async move {
        if rrset.rtype() != Rtype::Soa {
            let cloned_meta = meta.clone();
            let cloned_rrset = rrset.clone();
            // let permit = meta.transaction_stream().acquire_rate_permit().await;
            meta.transaction_stream()
                .push(async move {
                    let builder = mk_builder_for_target();
                    let mut answer = builder
                        .start_answer(cloned_meta.message(), Rcode::NoError)
                        .unwrap();
                    for item in cloned_rrset.data() {
                        answer
                            .push((owner.clone(), cloned_rrset.ttl(), item))
                            .unwrap();
                    }
                    let mut additional = answer.additional();
                    set_axfr_header(cloned_meta.message(), &mut additional);
                    // drop(permit); // Force moving of the permit into the async task
                    Ok(CallResult::new(additional))
                })
                .await;
        }
    })
}

#[allow(clippy::type_complexity)]
async fn add_to_stream(
    answer: Answer,
    msg: &Message<Vec<u8>>,
    stream: &TransactionStream<
        Result<CallResult<Vec<u8>, Vec<u8>>, ServiceError>,
    >,
) {
    let builder = mk_builder_for_target();
    let additional = answer.to_message(msg, builder);
    add_additional_to_stream(additional, msg, stream).await;
}

#[allow(clippy::type_complexity)]
async fn add_additional_to_stream(
    mut additional: AdditionalBuilder<domain::base::StreamTarget<Vec<u8>>>,
    msg: &Message<Vec<u8>>,
    stream: &TransactionStream<
        Result<CallResult<Vec<u8>, Vec<u8>>, ServiceError>,
    >,
) {
    set_axfr_header(msg, &mut additional);
    stream.push(ready(Ok(CallResult::new(additional)))).await;
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
    header.set_opcode(Opcode::Query);
    header.set_aa(true);
    header.set_tc(false);
    header.set_rd(msg.header().rd());
    header.set_ra(false);
    header.set_z(false);
    header.set_ad(false);
    header.set_cd(false);
}

//     // if rrset.rtype() != Rtype::Soa {
//     //     let cloned_msg2 = cloned_msg.clone();
//     //     let cloned_rrset = rrset.clone();
//     //     let cloned_sem = semaphore.clone();
//     //     let stream = cloned_stream.lock().unwrap().deref_mut();
//     //     stream.push(async move {
//     //         let _permit = cloned_sem.acquire().await.unwrap();
//     //         let builder = mk_builder_for_target();
//     //         let mut answer = builder
//     //             .start_answer(&cloned_msg2, Rcode::NoError)
//     //             .unwrap();
//     //         for item in cloned_rrset.data() {
//     //             answer
//     //                 .push((owner.clone(), cloned_rrset.ttl(), item))
//     //                 .unwrap();
//     //         }
//     //         let mut additional = answer.additional();
//     //         set_axfr_header(&cloned_msg2, &mut additional);
//     //         Ok(CallResult::new(additional))
//     //     });
//     // }
