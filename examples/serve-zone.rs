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

use core::future::{ready, Future};
use core::pin::Pin;
use core::str::FromStr;

use std::collections::HashMap;
use std::future::pending;
use std::io::BufReader;
use std::process::exit;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use octseq::Octets;
use rand::distributions::Alphanumeric;
use rand::Rng;
use tokio::net::{TcpListener, UdpSocket};
use tracing_subscriber::EnvFilter;

use domain::base::iana::{Class, Rcode};
use domain::base::name::OwnedLabel;
use domain::base::net::IpAddr;
use domain::base::{Name, Rtype, Serial, ToName, Ttl};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
#[cfg(feature = "siphasher")]
use domain::net::server::middleware::cookies::CookiesMiddlewareSvc;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::middleware::notify::{
    Notifiable, NotifyError, NotifyMiddlewareSvc,
};
use domain::net::server::middleware::tsig::TsigMiddlewareSvc;
use domain::net::server::middleware::xfr::{
    XfrData, XfrDataProvider, XfrDataProviderError, XfrMiddlewareSvc,
};
use domain::net::server::service::{CallResult, ServiceResult};
use domain::net::server::stream::StreamServer;
use domain::net::server::util::{mk_builder_for_target, service_fn};
use domain::tsig::{Algorithm, Key, KeyName};
use domain::zonefile::inplace;
use domain::zonetree::{
    Answer, InMemoryZoneDiff, Rrset, SharedRrset, StoredName,
};
use domain::zonetree::{Zone, ZoneTree};

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

    // Create a TSIG key store with a demo key.
    let mut key_store = HashMap::<(KeyName, Algorithm), Key>::new();
    let key_name = KeyName::from_str("demo-key").unwrap();
    let secret = domain::utils::base64::decode::<Vec<u8>>(
        "zlCZbVJPIhobIs1gJNQfrsS3xCxxsR9pMUrGwG8OgG8=",
    )
    .unwrap();
    let key =
        Key::new(Algorithm::Sha256, &secret, key_name.clone(), None, None)
            .unwrap();
    key_store.insert((key_name, Algorithm::Sha256), key);

    // Populate a zone tree with test data
    let zone_bytes = include_bytes!("../test-data/zonefiles/nsd-example.txt");
    let mut zone_bytes = BufReader::new(&zone_bytes[..]);

    // We're reading from static data so this cannot fail due to I/O error.
    // Don't handle errors that shouldn't happen, keep the example focused
    // on what we want to demonstrate.
    let mut zones = ZoneTree::new();
    let reader =
        inplace::Zonefile::load(&mut zone_bytes).unwrap_or_else(|err| {
            eprintln!("Error reading zone file bytes: {err}");
            exit(1);
        });
    let zone = Zone::try_from(reader).unwrap_or_else(|errors| {
        eprintln!(
            "{} zone file entries could not be parsed, aborting:",
            errors.len()
        );
        for (name, err) in errors {
            eprintln!("  {name}: {err}");
        }
        exit(1);
    });
    zones.insert_zone(zone).unwrap();
    let zones = Arc::new(zones);

    // Create an XFR data provider that can serve diffs for our zone.
    let zones_and_diffs = ZoneTreeWithDiffs::new(zones.clone());

    // Create a server with middleware layers and an application service
    // listening on localhost port 8053.
    let addr = "127.0.0.1:8053";
    let svc = service_fn(my_service, zones.clone());

    #[cfg(feature = "siphasher")]
    let svc = CookiesMiddlewareSvc::<Vec<u8>, _, _>::with_random_secret(svc);
    let svc = EdnsMiddlewareSvc::<Vec<u8>, _, _>::new(svc);
    let svc = XfrMiddlewareSvc::<Vec<u8>, _, _, _>::new(
        svc,
        zones_and_diffs.clone(),
        1,
    );
    let svc = NotifyMiddlewareSvc::new(svc, DemoNotifyTarget);
    let svc = MandatoryMiddlewareSvc::<Vec<u8>, _, _>::new(svc);
    let svc = TsigMiddlewareSvc::new(svc, key_store);
    let svc = Arc::new(svc);

    let sock = UdpSocket::bind(&addr).await.unwrap();
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

    eprintln!("Listening on {addr}");
    eprintln!("Try:");
    eprintln!("  dig @127.0.0.1 -p 8053 example.com");
    eprintln!("  dig @127.0.0.1 -p 8053 example.com AXFR");
    eprintln!("  dig @127.0.0.1 -p 8053 -y hmac-sha256:demo-key:zlCZbVJPIhobIs1gJNQfrsS3xCxxsR9pMUrGwG8OgG8= example.com AXFR");
    eprintln!("  dig @127.0.0.1 -p 8053 +opcode=notify example.com SOA");
    eprintln!("  cargo run --example ixfr-client --all-features -- 127.0.0.1:8053 example.com 2020080302");
    eprintln!();
    eprintln!("Tip: set env var RUST_LOG=info (or debug or trace) for more log output.");

    // Print some status information every 5 seconds
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(5000)).await;

            let mut udp_num_connections = 0;
            let mut udp_num_inflight_requests = 0;
            let mut udp_num_pending_writes = 0;
            let mut udp_num_received_requests = 0;
            let mut udp_num_sent_responses = 0;

            for metrics in udp_metrics.iter() {
                udp_num_connections += metrics.num_connections();
                udp_num_inflight_requests += metrics.num_inflight_requests();
                udp_num_pending_writes += metrics.num_pending_writes();
                udp_num_received_requests += metrics.num_received_requests();
                udp_num_sent_responses += metrics.num_sent_responses();
            }
            eprintln!(
                "Server status: #conn/#in-flight/#pending-writes/#msgs-recvd/#msgs-sent: UDP={}/{}/{}/{}/{} TCP={}/{}/{}/{}/{}",
                udp_num_connections,
                udp_num_inflight_requests,
                udp_num_pending_writes,
                udp_num_received_requests,
                udp_num_sent_responses,
                tcp_metrics.num_connections(),
                tcp_metrics.num_inflight_requests(),
                tcp_metrics.num_pending_writes(),
                tcp_metrics.num_received_requests(),
                tcp_metrics.num_sent_responses(),
            );
        }
    });

    // Mutate our own zone every 10 seconds.
    tokio::spawn(async move {
        let zone_name = Name::<Vec<u8>>::from_str("example.com").unwrap();
        let mut label: Option<OwnedLabel> = None;

        loop {
            tokio::time::sleep(Duration::from_millis(10000)).await;

            let zone = zones.get_zone(&zone_name, Class::IN).unwrap();
            let mut writer = zone.write().await;
            {
                let node = writer.open(true).await.unwrap();

                if let Some(old_label) = label {
                    let node = node.update_child(&old_label).await.unwrap();
                    node.remove_rrset(Rtype::A).await.unwrap();
                }

                let random_string: String = rand::thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(7)
                    .map(char::from)
                    .collect();
                let new_label = OwnedLabel::from_str(&random_string).unwrap();

                let node = node.update_child(&new_label).await.unwrap();
                let mut rrset = Rrset::new(Rtype::A, Ttl::from_secs(60));
                let rec = domain::rdata::A::new("127.0.0.1".parse().unwrap());
                rrset.push_data(rec.into());
                node.update_rrset(SharedRrset::new(rrset)).await.unwrap();

                label = Some(new_label);
            }
            let diff = writer.commit(true).await.unwrap();
            if let Some(diff) = diff {
                zones_and_diffs.add_diff(diff);
            }
            eprintln!(
                "Added {} A record to zone example.com",
                label.unwrap()
            );
        }
    });

    pending::<()>().await;
}

#[allow(clippy::type_complexity)]
fn my_service(
    request: Request<Vec<u8>>,
    zones: Arc<ZoneTree>,
) -> ServiceResult<Vec<u8>> {
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

#[derive(Copy, Clone, Default, Debug)]
struct DemoNotifyTarget;

impl Notifiable for DemoNotifyTarget {
    fn notify_zone_changed(
        &self,
        class: Class,
        apex_name: &StoredName,
        serial: Option<Serial>,
        source: IpAddr,
    ) -> Pin<
        Box<dyn Future<Output = Result<(), NotifyError>> + Sync + Send + '_>,
    > {
        eprintln!("Notify received from {source} of change to zone {apex_name} in class {class} with serial {serial:?}");

        let res = match apex_name.to_string().to_lowercase().as_str() {
            "example.com" => Ok(()),
            "othererror.com" => Err(NotifyError::Other),
            _ => Err(NotifyError::NotAuthForZone),
        };

        Box::pin(ready(res))
    }
}

#[derive(Clone)]
struct ZoneTreeWithDiffs {
    zones: Arc<ZoneTree>,
    diffs: Arc<Mutex<Vec<InMemoryZoneDiff>>>,
}

impl ZoneTreeWithDiffs {
    fn new(zones: Arc<ZoneTree>) -> Self {
        Self {
            zones,
            diffs: Default::default(),
        }
    }

    fn add_diff(&self, diff: InMemoryZoneDiff) {
        self.diffs.lock().unwrap().push(diff);
    }

    fn get_diffs(&self, diff_from: Option<Serial>) -> Vec<InMemoryZoneDiff> {
        let diffs = self.diffs.lock().unwrap();
        if let Some(idx) = diffs
            .iter()
            .position(|diff| Some(diff.start_serial) == diff_from)
        {
            diffs[idx..].to_vec()
        } else {
            vec![]
        }
    }
}

impl XfrDataProvider<Option<Key>> for ZoneTreeWithDiffs {
    type Diff = InMemoryZoneDiff;

    fn request<Octs>(
        &self,
        req: &Request<Octs, Option<Key>>,
        diff_from: Option<Serial>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        XfrData<Self::Diff>,
                        XfrDataProviderError,
                    >,
                > + Sync
                + Send,
        >,
    >
    where
        Octs: Octets + Send + Sync,
    {
        if req.metadata().is_none() {
            eprintln!("Rejecting");
            return Box::pin(ready(Err(XfrDataProviderError::Refused)));
        }
        let res = req
            .message()
            .sole_question()
            .map_err(XfrDataProviderError::ParseError)
            .and_then(|q| {
                if let Some(zone) =
                    self.zones.find_zone(q.qname(), q.qclass())
                {
                    Ok(XfrData::new(
                        zone.clone(),
                        self.get_diffs(diff_from),
                        false,
                    ))
                } else {
                    Err(XfrDataProviderError::UnknownZone)
                }
            });

        Box::pin(ready(res))
    }
}
