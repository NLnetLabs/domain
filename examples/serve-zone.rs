//! Loads a zone file and serves it over localhost UDP and TCP.

use domain::base::{Message, ToDname};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::service::{CallResult, ServiceError, Transaction};
use domain::net::server::stream::StreamServer;
use domain::net::server::util::{mk_builder_for_target, service_fn};
use domain::zonefile::inplace;
use domain::zonetree::Answer;
use domain::zonetree::{Zone, ZoneSet};
use std::future::{pending, Future};
use std::io::BufReader;
use std::sync::Arc;
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
    let mut zones = ZoneSet::new();
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
    let svc = Arc::new(service_fn(my_service, zones));

    let sock = UdpSocket::bind(addr).await.unwrap();
    let udp_srv = DgramServer::new(sock, VecBufSource, svc.clone());

    let sock = TcpListener::bind(addr).await.unwrap();
    let tcp_srv = StreamServer::new(sock, VecBufSource, svc);

    tokio::spawn(async move { udp_srv.run().await });
    tokio::spawn(async move { tcp_srv.run().await });

    let () = pending().await;
}

#[allow(clippy::type_complexity)]
fn my_service(
    msg: Request<Message<Vec<u8>>>,
    zones: Arc<ZoneSet>,
) -> Result<
    Transaction<
        Result<CallResult<Vec<u8>, Vec<u8>>, ServiceError>,
        impl Future<
                Output = Result<CallResult<Vec<u8>, Vec<u8>>, ServiceError>,
            > + Send,
    >,
    ServiceError,
> {
    let fut = async move {
        let question = msg.message().sole_question().unwrap();
        let zone = zones
            .find_zone(question.qname(), question.qclass())
            .map(|zone| zone.read());
        let answer = match zone {
            Some(zone) => {
                let qname = question.qname().to_bytes();
                let qtype = question.qtype();
                match zone.is_async() {
                    true => zone.query_async(qname, qtype).await,
                    false => zone.query(qname, qtype),
                }
                .unwrap()
            }
            None => Answer::refused(),
        };

        let builder = mk_builder_for_target();
        let additional = answer.to_message(msg.message(), builder);
        Ok(CallResult::new(additional))
    };
    Ok(Transaction::single(fut))
}
