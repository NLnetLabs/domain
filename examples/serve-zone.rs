//! Loads a zone file and serves it over localhost UDP and TCP.
//!
//! Try queries such as:
//!
//! ```sh
//!   dig @127.0.0.1 -p 8053 NS example.com
//!   dig @127.0.0.1 -p 8053 A example.com
//!   dig @127.0.0.1 -p 8053 AAAA example.com
//!   dig @127.0.0.1 -p 8053 CNAME example.com
//! ```
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
use std::fs::File;
use std::future::pending;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use domain::zonecatalog::catalog::{self, Catalog, TypedZone};
use domain::zonecatalog::types::{
    CatalogKeyStore, CompatibilityMode, NotifyConfig, TransportStrategy,
    XfrConfig, XfrStrategy, ZoneConfig,
};
use octseq::Parser;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;
use tracing::{debug, info};
use tracing_subscriber::EnvFilter;

use domain::base::iana::{Class, Rcode};
use domain::base::record::ComposeRecord;
use domain::base::{Name, ParsedName, ParsedRecord, Record, ToName};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::middleware::cookies::CookiesMiddlewareSvc;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::middleware::notify::NotifyMiddlewareSvc;
use domain::net::server::middleware::tsig::TsigMiddlewareSvc;
use domain::net::server::middleware::xfr::{XfrMiddlewareSvc, XfrMode};
use domain::net::server::service::{CallResult, ServiceResult};
use domain::net::server::stream::{self, StreamServer};
use domain::net::server::util::{mk_builder_for_target, service_fn};
use domain::net::server::ConnectionConfig;
use domain::rdata::ZoneRecordData;
use domain::tsig::{Algorithm, Key, KeyName};
use domain::utils::base64;
use domain::zonefile::inplace;
use domain::zonetree::{Answer, Rrset, ZoneBuilder};
use domain::zonetree::{WritableZone, Zone, ZoneStore};

#[tokio::main()]
async fn main() {
    // Initialize tracing based logging. Override with env var RUST_LOG, e.g.
    // RUST_LOG=trace.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .try_init()
        .ok();

    let config = match parse_args() {
        Ok(config) => config,
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        }
    };

    // Create a catalog that will handle outbound XFR for zones
    let cat_config = catalog::Config::new(config.key_store.clone());
    let catalog = Catalog::new_with_config(cat_config);
    let catalog = Arc::new(catalog);
    catalog.insert_zone(config.zone).await.unwrap();

    let max_concurrency =
        std::thread::available_parallelism().unwrap().get() / 2;
    println!("Using max concurrency {max_concurrency} for XFR");

    // Create a service to answer queries for the zone.
    let svc = service_fn(my_service, catalog.clone());
    let svc: XfrMiddlewareSvc<Vec<u8>, _, Arc<CatalogKeyStore>> =
        XfrMiddlewareSvc::<Vec<u8>, _, _>::new(
            svc,
            catalog.clone(),
            max_concurrency,
            XfrMode::AxfrAndIxfr,
        );
    let svc =
        NotifyMiddlewareSvc::<Vec<u8>, _, _, _>::new(svc, catalog.clone());
    let svc = CookiesMiddlewareSvc::<Vec<u8>, _, _>::with_random_secret(svc);
    let svc = EdnsMiddlewareSvc::<Vec<u8>, _, _>::new(svc);
    let svc = MandatoryMiddlewareSvc::<Vec<u8>, _, _>::new(svc);
    let svc = TsigMiddlewareSvc::<Vec<u8>, _, _>::new(svc, config.key_store);
    let svc = Arc::new(svc);

    println!(
        "Listening on {} for incoming UDP connections",
        config.udp_listen_addr
    );
    let sock = UdpSocket::bind(config.udp_listen_addr).await.unwrap();
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

    println!(
        "Listening on {} for incoming TCP connections",
        config.tcp_listen_addr
    );
    let sock = TcpListener::bind(config.tcp_listen_addr).await.unwrap();
    let mut conn_config = ConnectionConfig::new();
    conn_config.set_max_queued_responses(1024);
    let mut stream_config = stream::Config::new();
    stream_config.set_connection_config(conn_config);
    let tcp_srv =
        StreamServer::with_config(sock, VecBufSource, svc, stream_config);
    let tcp_metrics = tcp_srv.metrics();
    tokio::spawn(async move { tcp_srv.run().await });

    let catalog_clone = catalog.clone();
    tokio::spawn(async move { catalog_clone.run().await });

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

    // // Modify zone
    // if primary {
    //     // Make changes to a zone to create a diff for IXFR use.
    //     let c_zones = catalog.zones();
    //     let zone = c_zones.get_zone(&z_apex_name, z_class).unwrap();
    //     let mut writer = zone.write().await;
    //     {
    //         let node = writer.open(true).await.unwrap();
    //         let mut new_ns = Rrset::new(Rtype::NS, Ttl::from_secs(60));
    //         let ns_rec = domain::rdata::Ns::new(
    //             Name::from_str("write-test.example.com").unwrap(),
    //         );
    //         new_ns.push_data(ns_rec.into());
    //         node.update_rrset(SharedRrset::new(new_ns)).await.unwrap();
    //     }
    //     let _diff = writer.commit(true).await.unwrap();
    // }

    pending::<()>().await;
}

fn my_service(
    request: Request<Vec<u8>>,
    catalog: Arc<Catalog<Arc<CatalogKeyStore>>>,
) -> ServiceResult<Vec<u8>> {
    let question = request.message().sole_question().unwrap();
    let zones = catalog.zones();
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
    write_path: Option<PathBuf>,
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
                > + Send
                + Sync,
        >,
    > {
        if let Some(write_path) = self.write_path.clone() {
            let fut = self.store.clone().write();
            Box::pin(async move {
                let writable_zone = fut.await;
                let writable_zone = WritableArchiveZone {
                    writable_zone,
                    store: self.store.clone(),
                    write_path,
                };
                Box::new(writable_zone) as Box<dyn WritableZone>
            })
        } else {
            self.store.clone().write()
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self as &dyn std::any::Any
    }
}

struct WritableArchiveZone {
    writable_zone: Box<dyn WritableZone>,
    store: Arc<dyn ZoneStore>,
    write_path: PathBuf,
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
                > + Send
                + Sync,
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
                > + Send
                + Sync,
        >,
    > {
        let fut = self.writable_zone.commit(bump_soa_serial);
        let store = self.store.clone();
        let write_path = self.write_path.clone();

        Box::pin(async move {
            debug!("Committing zone");
            let res = fut.await;

            info!("Writing zone to file: {}", write_path.display());
            let mut file = File::create(write_path).unwrap();
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

struct Config {
    pub udp_listen_addr: SocketAddr,
    pub tcp_listen_addr: SocketAddr,
    pub zone: TypedZone,
    pub key_store: Arc<CatalogKeyStore>,
}

fn parse_args() -> Result<Config, String> {
    let mut args = args();
    let bin_name = args.next().unwrap();

    let def_listen_addr =
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8053);
    let usage = format!(
        r###"Usage: {bin_name} <zone-name> [<zone-file-path>] OPTIONS

Arguments:
  zone-name:                       Name of the zone to serve, e.g. example.com.
  zone-file-path:                  Optional path to the zone file to serve.
                                   Zone content must be received via XFR if no path is given.

Options:
  --help:                          This help text.
  --listen <ip>:<port>:            UDP and TCP address to listen on [default {def_listen_addr}].
  --listen-udp <ip>:<port>:        UDP address to listen on [default {def_listen_addr}].
  --listen-tcp <ip>:<port>:        TCP address to listen on [default {def_listen_addr}].
  --xfr-src <ip>:<port>:           Accept NOTIFY from <ip> and request XFR from <ip>:<port>.
  --xfr-dst <ip>:<port>:           Send NOTIFY to <ip>:<port> and accept XFR requests from <ip>.
  --tsig-key <name>:[<alg>]:<key>: E.g. "my key":hmac-sha256:<base64 key data>.
                                   Applies to the next --xfr-src|dst argument.
  --zone-dump-path <path>:         Save received updates to the served zone to this path.
    "###
    );

    let mut zone_name = None;
    let mut zone_path = None;
    let mut udp_listen_addr = None;
    let mut tcp_listen_addr = None;
    let mut zone_dump_path = None;

    let mut zone_cfg = ZoneConfig::new();
    let mut key_store = CatalogKeyStore::new();

    let mut xfr_cfg = XfrConfig {
        strategy: XfrStrategy::IxfrWithAxfrFallback,
        ixfr_transport: TransportStrategy::Tcp,
        compatibility_mode: CompatibilityMode::Default,
        tsig_key: None,
    };

    let mut notify_cfg = NotifyConfig { tsig_key: None };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" => return Err(usage),

            "--listen" => {
                let arg =
                    args.next().ok_or("Error: Missing listen address")?;
                let listen_addr =
                    SocketAddr::from_str(&arg).map_err(|err| {
                        format!(
                            "Error: Invalid listen address '{arg}': {err}"
                        )
                    })?;
                udp_listen_addr = Some(listen_addr);
                tcp_listen_addr = Some(listen_addr);
            }

            "--listen-udp" => {
                let arg =
                    args.next().ok_or("Error: Missing listen UDP address")?;
                let listen_addr =
                    SocketAddr::from_str(&arg).map_err(|err| {
                        format!(
                            "Error: Invalid listen UDP address '{arg}': {err}"
                        )
                    })?;
                udp_listen_addr = Some(listen_addr);
            }

            "--listen-tcp" => {
                let arg =
                    args.next().ok_or("Error: Missing listen TCP address")?;
                let listen_addr =
                    SocketAddr::from_str(&arg).map_err(|err| {
                        format!(
                            "Error: Invalid listen TCP address '{arg}': {err}"
                        )
                    })?;
                tcp_listen_addr = Some(listen_addr);
            }

            "--xfr-src" => {
                let arg = args.next().ok_or("Error: Missing XFR source")?;
                let src = SocketAddr::from_str(&arg).map_err(|err| {
                    format!("Error: Invalid XFR source '{arg}': {err}")
                })?;

                zone_cfg
                    .allow_notify_from
                    .add_src(src.ip(), notify_cfg.clone());
                zone_cfg.request_xfr_from.add_dst(src, xfr_cfg.clone());
            }

            "--xfr-dst" => {
                let arg = args.next().ok_or("Error: Missing XFR dest")?;
                let dst = SocketAddr::from_str(&arg).map_err(|err| {
                    format!("Error: Invalid XFR dest '{arg}': {err}")
                })?;

                zone_cfg.send_notify_to.add_dst(dst, notify_cfg.clone());
                zone_cfg.provide_xfr_to.add_src(dst.ip(), xfr_cfg.clone());
            }

            "--tsig-key" => {
                let key_parts: Vec<String> = args
                    .next()
                    .map(|s| s.split(':').map(ToString::to_string).collect())
                    .ok_or(
                        "Error: TSIG key value should be colon ':' separated",
                    )?;

                let key_name = key_parts[0].trim_matches('"');

                let (alg, base64) = match key_parts.len() {
                    2 => (Algorithm::Sha256, key_parts[1].clone()),
                    3 => {
                        let alg = Algorithm::from_str(&key_parts[1])
                        .map_err(|_| format!("Error: Invalid '{}' is not a valid TSIG algorithm", key_parts[1]))?;
                        (alg, key_parts[2].clone())
                    }
                    _ => return Err(usage),
                };

                let key_name =
                    KeyName::from_str(key_name).map_err(|err| format!("Error: Invalid TSIG key name '{key_name}': {err}"))?;
                let secret =
                    base64::decode::<Vec<u8>>(&base64).map_err(|err| format!("Error: Invalid base64 encoded TSIG key secret '{base64}': {err}"))?;
                let key = Key::new(alg, &secret, key_name, None, None)
                    .map_err(|err| {
                        format!("Error: Invalid TSIG key inputs: {err}")
                    })?;

                let key_id = (key.name().clone(), key.algorithm());
                key_store.insert(key_id.clone(), key);
                xfr_cfg.tsig_key = Some(key_id.clone());
                notify_cfg.tsig_key = Some(key_id);
            }

            "--zone-dump-path" => {
                let arg = args
                    .next()
                    .ok_or("Error: Missing zone dump path argument")?;
                let path = PathBuf::from_str(&arg).map_err(|err| {
                    format!("Error: Invalid zone dump path '{arg}': {err}")
                })?;
                zone_dump_path = Some(path);
            }

            _ if arg.starts_with("--") => return Err(usage)?,

            _ => {
                // Must be a positional argument
                if zone_name.is_none() {
                    zone_name = Some(arg);
                } else if zone_path.is_none() {
                    zone_path = Some(arg);
                } else {
                    return Err(usage);
                }
            }
        }
    }

    if zone_path.is_none() && !zone_cfg.is_secondary() {
        return Err(
            "Error: Either a zone path or an XFR source must be specified"
                .to_string(),
        );
    }

    let zone_name = zone_name.ok_or(usage)?;
    let zone = match zone_path {
        Some(zone_path) => {
            // Load the specified zone file.
            println!("Loading zone file for zone '{zone_name}' from '{zone_path}'..");
            let mut zone_bytes = File::open(&zone_path).map_err(|err| {
                format!(
                    "Error: Failed to open zone file at '{zone_path}': {err}"
                )
            })?;
            let reader = inplace::Zonefile::load(&mut zone_bytes).map_err(|err| {
                format!("Error: Failed to load zone file from '{zone_path}': {err}")
            })?;
            Zone::try_from(reader)
                .map_err(|err| format!("Failed to parse zone: {err}"))?
        }

        None => {
            let apex_name = Name::from_str(&zone_name).map_err(|err| {
                format!("Error: Invalid zone name '{zone_name}': {err}")
            })?;
            let builder = ZoneBuilder::new(apex_name, Class::IN);
            builder.build()
        }
    };

    let zone = ArchiveZone {
        store: zone.into_inner(),
        write_path: zone_dump_path,
    };
    let zone = Zone::new(zone);
    let zone = TypedZone::new(zone, zone_cfg);

    Ok(Config {
        udp_listen_addr: udp_listen_addr.unwrap_or(def_listen_addr),
        tcp_listen_addr: tcp_listen_addr.unwrap_or(def_listen_addr),
        zone,
        key_store: Arc::new(key_store),
    })
}
