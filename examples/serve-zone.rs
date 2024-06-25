//! Loads a zone file and serves it over localhost UDP and TCP.
//!
//! Try queries such as:
//!
//!   dig @127.0.0.1 -p 8053 NS example.com dig @127.0.0.1 -p 8053 A
//!   example.com dig @127.0.0.1 -p 8053 AAAA example.com dig @127.0.0.1 -p
//!   8053 CNAME example.com
//!
//! Also try with TCP, e.g.:
//!
//!   dig @127.0.0.1 -p 8053 +tcp A example.com
//!
//! Also try AXFR, e.g.:
//!
//!   dig @127.0.0.1 -p 8053 AXFR example.com
//!
//! With a large zone and the following dig options and an XFR thread pool of
//! size 16 a peak rate of 110MB/s (localhost only) was recorded:
//!
//!   $ dig -4 @127.0.0.1 -p 8053 +noanswer +tries=1 +noidnout AXFR de.
//!   ; <<>> DiG 9.18.24 <<>> +noanswer -4 @127.0.0.1 -p 8053 +tries +noidnout AXFR de.
//!   ; (1 server found)
//!   ;; global options: +cmd
//!   ;; Query time: 47669 msec
//!   ;; SERVER: 127.0.0.1#8053(127.0.0.1) (TCP)
//!   ;; WHEN: Thu May 02 00:14:04 CEST 2024
//!   ;; XFR size: 43347447 records (messages 16393621, bytes 2557835040)

use core::str::FromStr;

use std::env::args;
use std::future::pending;
use std::io::{self, BufReader, Write};
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};
use tracing::{debug, info, trace};
use tracing_subscriber::EnvFilter;

use bytes::Bytes;
use domain::base::iana::{Class, Rcode};
use domain::base::record::ComposeRecord;
use domain::base::{
    Name, ParsedName, ParsedRecord, Record, Rtype, ToName, Ttl,
};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
#[cfg(feature = "siphasher")]
use domain::net::server::middleware::cookies::CookiesMiddlewareSvc;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::middleware::notify::NotifyMiddlewareSvc;
use domain::net::server::middleware::xfr::{
    PerClientSettings, XfrMiddlewareSvc, XfrMode,
};
use domain::net::server::service::{CallResult, ServiceResult};
use domain::net::server::stream::{self, StreamServer};
use domain::net::server::util::{mk_builder_for_target, service_fn};
use domain::net::server::ConnectionConfig;
use domain::rdata::ZoneRecordData;
use domain::tsig::{Algorithm, Key, KeyName};
use domain::utils::base64;
use domain::zonecatalog::catalog::{
    self, Acl, Catalog, CatalogKeyStore, NotifyAcl, TransportStrategy,
    TypedZone, XfrAcl, XfrSettings, XfrStrategy, ZoneType,
};
use domain::zonefile::inplace;
use domain::zonetree::{Answer, Rrset, SharedRrset, ZoneBuilder};
use domain::zonetree::{WritableZone, Zone, ZoneStore};
use octseq::Parser;
use tokio::sync::mpsc;

#[tokio::main()]
async fn main() {
    // Initialize tracing based logging. Override with env var RUST_LOG, e.g.
    // RUST_LOG=trace.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .try_init()
        .ok();

    let mut args = args();
    let _bin_name = args.next();
    let primary = args.next();

    let (primary, addr) = match primary {
        Some(v) if v == "secondary" => {
            eprintln!("Acting as secondary");
            (false, "127.0.0.1:8054")
        }
        Some(v) if v == "primary" => {
            eprintln!("Acting as primary");
            (true, "127.0.0.1:8053")
        }
        _ => {
            eprintln!("Specify either primary or secondary as the first command line arg.");
            exit(1);
        }
    };

    let zone_path = args.next().unwrap_or_default();

    eprintln!("Will listen on {addr}.");

    // Populate a zone tree with test data
    let zone_bytes = include_bytes!("../test-data/zonefiles/nsd-example.txt");
    let mut zone_bytes = match std::fs::File::open(&zone_path) {
        Ok(file) => {
            eprintln!("Loading zone from {zone_path}");
            Box::new(file) as Box<dyn io::Read>
        }
        Err(_) => {
            Box::new(BufReader::new(&zone_bytes[..])) as Box<dyn io::Read>
        }
    };

    // We're reading from static data so this cannot fail due to I/O error.
    // Don't handle errors that shouldn't happen, keep the example focused
    // on what we want to demonstrate.
    let reader = inplace::Zonefile::load(&mut zone_bytes).unwrap();
    let zone = match primary {
        true => Zone::try_from(reader).unwrap(),
        false => {
            let builder = ZoneBuilder::new(
                Name::from_str("example.com").unwrap(),
                Class::IN,
            );
            builder.build()
        }
    };
    let z_apex_name = zone.apex_name().clone();
    let z_class = zone.class();

    let zone = ArchiveZone {
        store: zone.into_inner(),
    };
    let zone = Zone::new(zone);

    let mut key_store = CatalogKeyStore::new();
    let secret = base64::decode::<Vec<u8>>(
        "zlCZbVJPIhobIs1gJNQfrsS3xCxxsR9pMUrGwG8OgG8=", // generated by BIND9 tsig-keygen
    )
    .unwrap();
    let key_name = KeyName::from_str("sec1-key").unwrap();
    let key =
        Key::new(Algorithm::Sha256, &secret, key_name.clone(), None, None)
            .unwrap();
    let key = Arc::new(key);
    key_store.insert((key_name.clone(), Algorithm::Sha256), key);
    let key_store = Arc::new(tokio::sync::RwLock::new(key_store));

    let zone_type = match primary {
        true => {
            let mut notify = Acl::new();
            notify.allow_to("127.0.0.1:8054".parse().unwrap(), None);

            let mut allow_xfr = XfrAcl::new();
            let xfr_settings = XfrSettings {
                strategy: XfrStrategy::AxfrOnly,
                ixfr_transport: TransportStrategy::Tcp,
            };
            allow_xfr.allow_from(
                "127.0.0.1".parse().unwrap(),
                (xfr_settings, None),
            );

            ZoneType::new_primary(allow_xfr, notify)
        }
        false => {
            let mut allow_notify = NotifyAcl::new();
            allow_notify.allow_from("127.0.0.1".parse().unwrap(), None);

            let mut request_xfr = XfrAcl::new();
            let xfr_settings = XfrSettings {
                strategy: XfrStrategy::IxfrWithAxfrFallback,
                ixfr_transport: TransportStrategy::Tcp,
            };
            request_xfr.allow_to(
                "127.0.0.1:8055".parse().unwrap(),
                (xfr_settings, Some((key_name.clone(), Algorithm::Sha256))),
            );

            ZoneType::new_secondary(allow_notify, request_xfr)
        }
    };
    let zone = TypedZone::new(zone, zone_type);

    // Create a catalog that will handle outbound XFR for zones

    let config = catalog::Config::new(key_store.clone());
    let catalog = Catalog::new_with_config(config);
    let catalog = Arc::new(catalog);
    catalog.insert_zone(zone).await.unwrap();

    let svc = service_fn(my_service, catalog.clone());

    // Insert XFR middleware to automagically handle AXFR and IXFR requests.
    let num_xfr_threads =
        std::thread::available_parallelism().unwrap().get() / 2;
    println!("Using {num_xfr_threads} threads for XFR");
    let svc = XfrMiddlewareSvc::<Vec<u8>, _>::new(
        svc,
        catalog.clone(),
        num_xfr_threads,
        XfrMode::AxfrAndIxfr,
        PerClientSettings::new(),
    );
    let svc = NotifyMiddlewareSvc::<Vec<u8>, _>::new(svc, catalog.clone());

    #[cfg(feature = "siphasher")]
    let svc = CookiesMiddlewareSvc::<Vec<u8>, _>::with_random_secret(svc);
    let svc = EdnsMiddlewareSvc::<Vec<u8>, _>::new(svc);
    let svc = MandatoryMiddlewareSvc::<Vec<u8>, _>::new(svc);
    let svc = Arc::new(svc);

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
    let mut conn_config = ConnectionConfig::new();
    conn_config.set_max_queued_responses(1024);
    let mut config = stream::Config::new();
    config.set_connection_config(conn_config);
    let tcp_srv = StreamServer::with_config(sock, VecBufSource, svc, config);
    let tcp_metrics = tcp_srv.metrics();

    tokio::spawn(async move { tcp_srv.run().await });

    let catalog_clone = catalog.clone();
    tokio::spawn(async move { catalog_clone.run().await });

    eprintln!("Ready");

    let catalog_clone = catalog.clone();
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

            if let Ok(report) = catalog_clone
                .zone_status(
                    &Name::from_str("example.com").unwrap(),
                    Class::IN,
                )
                .await
            {
                eprintln!("{report}");
            }
        }
    });

    tokio::time::sleep(Duration::from_secs(15)).await;

    // Modify zone
    if primary {
        // Make changes to a zone to create a diff for IXFR use.
        let c_zones = catalog.zones();
        let zone = c_zones.get_zone(&z_apex_name, z_class).unwrap();
        let mut writer = zone.write().await;
        {
            let node = writer.open(true).await.unwrap();
            let mut new_ns = Rrset::new(Rtype::NS, Ttl::from_secs(60));
            let ns_rec = domain::rdata::Ns::new(
                Name::from_str("write-test.example.com").unwrap(),
            );
            new_ns.push_data(ns_rec.into());
            node.update_rrset(SharedRrset::new(new_ns)).await.unwrap();
        }
        let _diff = writer.commit(true).await.unwrap();
    }

    // // Send NOTIFY
    // if primary {
    //     let secondary_addr = "127.0.0.1:8054";
    //     eprintln!("Sending NOTIFY to secondary at {secondary_addr}...");

    //     let mut msg = MessageBuilder::new_vec();
    //     msg.header_mut().set_opcode(Opcode::NOTIFY);
    //     let mut msg = msg.question();
    //     msg.push((Name::vec_from_str("example.com").unwrap(), Rtype::SOA))
    //         .unwrap();
    //     let req = RequestMessage::new(msg);

    //     let server_addr = secondary_addr.parse().unwrap();
    //     let udp_connect = UdpConnect::new(server_addr);
    //     let mut dgram_config = Config::new();
    //     dgram_config.set_max_parallel(1);
    //     dgram_config.set_read_timeout(Duration::from_millis(1000));
    //     dgram_config.set_max_retries(1);
    //     dgram_config.set_udp_payload_size(Some(1400));
    //     let dgram_conn = Connection::with_config(udp_connect, dgram_config);
    //     dgram_conn.send_request(req).get_response().await.unwrap();
    // }

    pending::<()>().await;
}

#[allow(clippy::type_complexity)]
fn my_service(
    request: Request<Vec<u8>>,
    catalog: Arc<Catalog>,
) -> ServiceResult<Vec<u8>> {
    let question = request.message().sole_question().unwrap();
    let zones = catalog.zones();
    trace!("my_service: zones dump: {zones:#?}");
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

//------------ ArchiveZone ---------------------------------------------------

// https://datatracker.ietf.org/doc/html/rfc5936#section-6
// 6.  Zone Integrity
//   "An AXFR client MUST ensure that only a successfully transferred copy of
//    the zone data can be used to serve this zone.  Previous description and
//    implementation practice has introduced a two-stage model of the whole
//    zone synchronization procedure:  Upon a trigger event (e.g., when
//    polling of a SOA resource record detects a change in the SOA serial
//    number, or when a DNS NOTIFY request [RFC1996] is received), the AXFR
//    session is initiated, whereby the zone data are saved in a zone file or
//    database (this latter step is necessary anyway to ensure proper restart
//    of the server);"
//
// ArchiveZone demonstrates persisting a zone on commit, e.g. as part of XFR.
// By wrapping a Zone in an ArchiveZone and then using it with the Catalog the
// ArchiveZone will see the commit operation performed by the Catalog as part
// of XFR processing and can persist the data to disk at that point.
//
// One known issue at present is that there is no way for ArchiveZone to see
// the new version of the zone pre-commit, only post-commit. Ideally we would
// verify that the zone has been persisted before allowing the commit to
// continue.
#[derive(Debug)]
struct ArchiveZone {
    store: Arc<dyn ZoneStore>,
}

impl ZoneStore for ArchiveZone {
    fn class(&self) -> Class {
        self.store.class()
    }

    fn apex_name(&self) -> &domain::zonetree::StoredName {
        self.store.apex_name()
    }

    fn read(self: Arc<Self>) -> Box<dyn domain::zonetree::ReadableZone> {
        self.store.clone().read()
    }

    fn write(
        self: Arc<Self>,
    ) -> std::pin::Pin<
        Box<
            dyn futures::prelude::Future<
                    Output = Box<dyn domain::zonetree::WritableZone>,
                > + Send,
        >,
    > {
        let fut = self.store.clone().write();
        Box::pin(async move {
            let writable_zone = fut.await;
            let writable_zone = WritableArchiveZone {
                writable_zone,
                store: self.store.clone(),
            };
            Box::new(writable_zone) as Box<dyn WritableZone>
        })
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}

struct WritableArchiveZone {
    writable_zone: Box<dyn WritableZone>,
    store: Arc<dyn ZoneStore>,
}

impl WritableZone for WritableArchiveZone {
    fn open(
        &self,
        create_diff: bool,
    ) -> std::pin::Pin<
        Box<
            dyn futures::prelude::Future<
                    Output = Result<
                        Box<dyn domain::zonetree::WritableZoneNode>,
                        std::io::Error,
                    >,
                > + Send,
        >,
    > {
        self.writable_zone.open(create_diff)
    }

    fn commit(
        &mut self,
        bump_soa_serial: bool,
    ) -> std::pin::Pin<
        Box<
            dyn futures::prelude::Future<
                    Output = Result<
                        Option<domain::zonetree::ZoneDiff>,
                        std::io::Error,
                    >,
                > + Send,
        >,
    > {
        let fut = self.writable_zone.commit(bump_soa_serial);
        let store = self.store.clone();
        Box::pin(async move {
            debug!("Committing zone");
            let res = fut.await;

            let path = format!("/tmp/{}.txt", store.apex_name());
            info!("Writing zone to file: {path}");
            let mut file = std::fs::File::create(path).unwrap();
            let (tx, mut rx) = mpsc::unbounded_channel::<String>();
            let read = store.read();

            tokio::spawn(async move {
                while let Some(line) = rx.recv().await {
                    writeln!(file, "{}", line).unwrap();
                }
            });

            read.walk(Box::new(move |owner, rrset| {
                dump_rrset(owner, rrset, &tx);
            }));

            info!("Write complete");
            res
        })
    }
}

// Copied from examples/query-zone.rs.
fn dump_rrset(
    owner: Name<Bytes>,
    rrset: &Rrset,
    sender: &mpsc::UnboundedSender<String>,
) {
    //
    // The following code renders an owner + rrset (IN class, TTL, RDATA)
    // into zone presentation format. This can be used for diagnostic
    // dumping.
    //
    let mut target = Vec::<u8>::new();
    for item in rrset.data() {
        let record = Record::new(owner.clone(), Class::IN, rrset.ttl(), item);
        if record.compose_record(&mut target).is_ok() {
            let mut parser = Parser::from_ref(&target);
            if let Ok(parsed_record) = ParsedRecord::parse(&mut parser) {
                if let Ok(Some(record)) = parsed_record
                    .into_record::<ZoneRecordData<_, ParsedName<_>>>()
                {
                    sender.send(format!("{record}")).unwrap();
                }
            }
        }
    }
}
