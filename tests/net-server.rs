#![cfg(feature = "net")]
use core::str::FromStr;

use std::boxed::Box;
use std::collections::VecDeque;
use std::fs::File;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use octseq::Octets;
use rstest::rstest;
use tracing::instrument;
use tracing::warn;

use domain::base::iana::Rcode;
use domain::base::name::{Name, ToName};
use domain::base::wire::Composer;
use domain::net::client::{dgram, stream};
use domain::net::server;
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
#[cfg(feature = "siphasher")]
use domain::net::server::middleware::cookies::CookiesMiddlewareSvc;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::service::{CallResult, Service, ServiceResult};
use domain::net::server::stream::StreamServer;
use domain::net::server::util::mk_builder_for_target;
use domain::net::server::util::service_fn;
use domain::zonecatalog::catalog::CompatibilityMode;
use domain::zonefile::inplace::Zonefile;

use domain::net::server::middleware::xfr::XfrMiddlewareSvc;
use domain::stelline::channel::ClientServerChannel;
use domain::stelline::client::do_client;
use domain::stelline::client::ClientFactory;
use domain::stelline::client::{
    CurrStepValue, PerClientAddressClientFactory, QueryTailoredClientFactory,
};
use domain::stelline::parse_stelline;
use domain::stelline::parse_stelline::parse_file;
use domain::stelline::parse_stelline::Config;
use domain::stelline::parse_stelline::Matches;
use domain::tsig::{Algorithm, KeyName};
use domain::utils::base16;
use domain::zonecatalog::catalog::{
    Acl, Catalog, DefaultConnFactory, TransportStrategy, XfrAcl, XfrSettings,
    XfrStrategy, ZoneType,
};
use domain::zonetree::Answer;

//----------- Tests ----------------------------------------------------------

/// Stelline test cases for which the .rpl file defines a server: config block.
///
/// Note: Adding or removing .rpl files on disk won't be detected until the
/// test is re-compiled.
// #[cfg(feature = "mock-time")] # Needed for the cookies test but that is
// currently disabled by renaming it to .rpl.not.
#[instrument(skip_all, fields(rpl = rpl_file.file_name().unwrap().to_str()))]
#[rstest]
#[tokio::test(start_paused = true)]
async fn server_tests(#[files("test-data/server/*.rpl")] rpl_file: PathBuf) {
    // Load the test .rpl file that determines which queries will be sent
    // and which responses will be expected, and how the server that
    // answers them should be configured.

    // Initialize tracing based logging. Override with env var RUST_LOG, e.g.
    // RUST_LOG=trace. DEBUG level will show the .rpl file name, Stelline step
    // numbers and types as they are being executed.

    use core::str::FromStr;
    use domain::base::iana::Class;
    use domain::net::server::middleware::xfr::XfrMode;
    use domain::zonecatalog::catalog::{self, TypedZone};
    use domain::zonetree::{Zone, ZoneBuilder};

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        .try_init()
        .ok();

    let file = File::open(&rpl_file).unwrap();
    let stelline = parse_file(&file, rpl_file.to_str().unwrap());
    let server_config = parse_server_config(&stelline.config);

    // Create a service to answer queries received by the DNS servers.
    let key_store = Default::default();
    let conn_factory = DefaultConnFactory;
    let catalog_config =
        catalog::Config::with_conn_factory(key_store, conn_factory);
    let catalog = Catalog::new_with_config(catalog_config);
    let catalog = Arc::new(catalog);

    if let Some(zone_config) = &server_config.zone {
        let zone = match &zone_config.zone_file {
            Some(zone_file) => Zone::try_from(zone_file.clone()).unwrap(),
            None => {
                let builder = ZoneBuilder::new(
                    Name::from_str("test").unwrap(),
                    Class::IN,
                );
                builder.build()
            }
        };

        let zone = TypedZone::new(zone, zone_config.zone_type.clone());
        catalog.insert_zone(zone).await.unwrap();
    }

    let with_cookies = server_config.cookies.enabled
        && server_config.cookies.secret.is_some();

    let svc = service_fn(test_service, catalog.clone());

    // Start the catalog background service so that incoming XFR/NOTIFY
    // requests will be handled.
    let catalog_clone = catalog.clone();
    tokio::spawn(async move { catalog_clone.run().await });

    // TODO: Cookies and keepalive shoulnd't be mutually exclusive. However,
    // PR #336 already solves this issue so leave this as-is for now.
    if with_cookies {
        #[cfg(not(feature = "siphasher"))]
        panic!("The test uses cookies but the required 'siphasher' feature is not enabled.");

        #[cfg(feature = "siphasher")]
        let secret = server_config.cookies.secret.unwrap();
        let secret = base16::decode_vec(secret).unwrap();
        let secret = <[u8; 16]>::try_from(secret).unwrap();
        let svc = CookiesMiddlewareSvc::new(svc, secret)
            .with_denied_ips(server_config.cookies.ip_deny_list.clone());
        finish_svc(svc, server_config, &stelline).await;
    } else if server_config.edns_tcp_keepalive {
        let svc = EdnsMiddlewareSvc::new(svc);
        finish_svc(svc, server_config, &stelline).await;
    } else {
        // TODO: It should be possible to use XFR/NOTIFY middleware also when
        // using cookies or EDNS middleware.
        const MAX_XFR_CONCURRENCY: usize = 1;
        let svc = XfrMiddlewareSvc::<Vec<u8>, _>::new(
            svc,
            catalog,
            MAX_XFR_CONCURRENCY,
            XfrMode::AxfrAndIxfr,
        );
        // let svc = NotifyMiddlewareSvc::<Vec<u8>, _>::new(svc, catalog);
        finish_svc(svc, server_config, &stelline).await;
    }

    async fn finish_svc<'a, RequestOctets, Svc>(
        svc: Svc,
        server_config: ServerConfig<'a>,
        stelline: &parse_stelline::Stelline,
    ) where
        RequestOctets: Octets + Send + Sync + Unpin,
        Svc: Service<RequestOctets> + Send + Sync + 'static,
        // TODO: Why are the following bounds needed to persuade the compiler
        // that the `svc` value created _within the function_ (not the one
        // passed in as an argument) is actually an impl of the Service trait?
        MandatoryMiddlewareSvc<Vec<u8>, Svc>: Service + Send + Sync,
        <MandatoryMiddlewareSvc<Vec<u8>, Svc> as Service>::Target:
            Composer + Default + Send + Sync,
        <MandatoryMiddlewareSvc<Vec<u8>, Svc> as Service>::Stream:
            Send + Sync,
        <MandatoryMiddlewareSvc<Vec<u8>, Svc> as Service>::Future:
            Send + Sync,
    {
        let svc = MandatoryMiddlewareSvc::<Vec<u8>, _>::new(svc);
        let svc = Arc::new(svc);

        // Create dgram and stream servers for answering requests
        let (dgram_srv, dgram_conn, stream_srv, stream_conn) =
            mk_servers(svc, &server_config);

        // Create a client factory for sending requests
        let client_factory = mk_client_factory(dgram_conn, stream_conn);

        // Create Stelline "mock" UDP

        // Run the Stelline test!
        let step_value = Arc::new(CurrStepValue::new());
        do_client(stelline, &step_value, client_factory).await;

        // Await shutdown
        if !dgram_srv.await_shutdown(Duration::from_secs(5)).await {
            warn!("Datagram server did not shutdown on time.");
        }

        if !stream_srv.await_shutdown(Duration::from_secs(5)).await {
            warn!("Stream server did not shutdown on time.");
        }
    }
}

//----------- test helpers ---------------------------------------------------

#[allow(clippy::type_complexity)]
fn mk_servers<Svc>(
    service: Arc<Svc>,
    server_config: &ServerConfig,
) -> (
    Arc<DgramServer<ClientServerChannel, VecBufSource, Arc<Svc>>>,
    ClientServerChannel,
    Arc<StreamServer<ClientServerChannel, VecBufSource, Arc<Svc>>>,
    ClientServerChannel,
)
where
    Svc: Service + Send + Sync + 'static,
    Svc::Future: Send,
    Svc::Target: Composer + Default + Send + Sync,
    Svc::Stream: Send,
{
    // Prepare middleware to be used by the DNS servers to pre-process
    // received requests and post-process created responses.
    let (dgram_config, stream_config) = mk_server_configs(server_config);

    // Create a dgram server for handling UDP requests.
    let dgram_server_conn = ClientServerChannel::new_dgram();
    let dgram_server = DgramServer::with_config(
        dgram_server_conn.clone(),
        VecBufSource,
        service.clone(),
        dgram_config,
    );
    let dgram_server = Arc::new(dgram_server);
    let cloned_dgram_server = dgram_server.clone();
    tokio::spawn(async move { cloned_dgram_server.run().await });

    // Create a stream server for handling TCP requests, i.e. Stelline queries
    // with "MATCH TCP".
    let stream_server_conn = ClientServerChannel::new_stream();
    let stream_server = StreamServer::with_config(
        stream_server_conn.clone(),
        VecBufSource,
        service,
        stream_config,
    );
    let stream_server = Arc::new(stream_server);
    let cloned_stream_server = stream_server.clone();
    tokio::spawn(async move { cloned_stream_server.run().await });

    (
        dgram_server,
        dgram_server_conn,
        stream_server,
        stream_server_conn,
    )
}

fn mk_client_factory(
    dgram_server_conn: ClientServerChannel,
    stream_server_conn: ClientServerChannel,
) -> impl ClientFactory {
    // Create a TCP client factory that only creates a client if (a) no
    // existing TCP client exists for the source address of the Stelline query,
    // and (b) if the query specifies "MATCHES TCP". Clients created by this
    // factory connect to the TCP server created above.
    let only_for_tcp_queries = |entry: &parse_stelline::Entry| {
        matches!(entry.matches, Some(Matches { tcp: true, .. }))
    };

    let tcp_client_factory = PerClientAddressClientFactory::new(
        move |_source_addr| {
            let stream = stream_server_conn.connect();
            let (conn, transport) = stream::Connection::new(stream);
            tokio::spawn(transport.run());
            Box::new(conn)
        },
        only_for_tcp_queries,
    );

    // Create a UDP client factory that only creates a client if (a) no
    // existing UDP client exists for the source address of the Stelline query.
    let for_all_other_queries = |_: &_| true;

    let udp_client_factory = PerClientAddressClientFactory::new(
        move |_| Box::new(dgram::Connection::new(dgram_server_conn.clone())),
        for_all_other_queries,
    );

    // Create a combined client factory that will allow the Stelline runner to
    // use existing or create new client connections as appropriate for the
    // Stelline query being evaluated.
    QueryTailoredClientFactory::new(vec![
        Box::new(tcp_client_factory),
        Box::new(udp_client_factory),
    ])
}

fn mk_server_configs(
    config: &ServerConfig,
) -> (server::dgram::Config, server::stream::Config) {
    let dgram_config = server::dgram::Config::default();

    let mut stream_config = server::stream::Config::default();
    if let Some(idle_timeout) = config.idle_timeout {
        let mut connection_config = server::ConnectionConfig::default();
        connection_config.set_idle_timeout(idle_timeout);
        stream_config.set_connection_config(connection_config);
    }

    (dgram_config, stream_config)
}

// A test `Service` impl.
//
// This function can be used with `service_fn()` to create a `Service`
// instance designed to respond to test queries.
//
// The functionality provided is the mininum common set of behaviour needed
// by the tests that use it.
//
// It's behaviour should be influenced to match the conditions under test by:
//   - Using different `MiddlewareChain` setups with the server(s) to which
//     the `Service` will be passed.
//   - Controlling the content of the `Zonefile` passed to instances of
//     this `Service` impl.
#[allow(clippy::type_complexity)]
fn test_service(
    request: Request<Vec<u8>>,
    catalog: Arc<Catalog>,
) -> ServiceResult<Vec<u8>> {
    let question = request.message().sole_question().unwrap();

    let zone = catalog
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
    let mut additional = answer.to_message(request.message(), builder);
    // As we serve all answers from our own zones we are the
    // authority for the domain in question.
    additional.header_mut().set_aa(true);
    Ok(CallResult::new(additional))
}

//----------- Stelline config block parsing -----------------------------------

struct ServerZone {
    /// None if we fetch it via XFR
    zone_file: Option<Zonefile>,

    zone_type: ZoneType,
}

#[derive(Default)]
struct ServerConfig<'a> {
    cookies: CookieConfig<'a>,
    edns_tcp_keepalive: bool,
    idle_timeout: Option<Duration>,
    zone: Option<ServerZone>,
}

#[derive(Default)]
struct CookieConfig<'a> {
    enabled: bool,
    secret: Option<&'a str>,
    ip_deny_list: Vec<IpAddr>,
}

fn parse_server_config(config: &Config) -> ServerConfig {
    let mut parsed_config = ServerConfig::default();
    let mut zone_file_bytes = VecDeque::<u8>::new();
    let mut in_server_block = false;
    let mut allow_xfr = XfrAcl::new();

    for line in config.lines() {
        if line.starts_with("server:") {
            in_server_block = true;
        } else if in_server_block {
            if !line.starts_with(|c: char| c.is_whitespace()) {
                in_server_block = false;
            } else if let Some((setting, value)) = line.trim().split_once(':')
            {
                // Trim off whitespace and trailing comments.
                let setting = setting.trim();
                let value = value
                    .split_once('#')
                    .map_or(value, |(value, _rest)| value)
                    .trim();

                match (setting, value) {
                    ("answer-cookie", "yes") => {
                        parsed_config.cookies.enabled = true
                    }
                    ("cookie-secret", v) => {
                        parsed_config.cookies.secret =
                            Some(v.trim_matches('"'));
                    }
                    ("access-control", v) => {
                        // TODO: Strictly speaking the "ip" is a netblock
                        // "given as an IPv4 or IPv6 address /size appended
                        // for a classless network block", but we only handle
                        // an IP address here for now.
                        // See: https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html?highlight=edns-tcp-keepalive#unbound-conf-access-control
                        if let Some((ip, action)) =
                            v.split_once(|c: char| c.is_whitespace())
                        {
                            match action {
                                "allow_cookie" => {
                                    if let Ok(ip) = ip.parse() {
                                        parsed_config
                                            .cookies
                                            .ip_deny_list
                                            .push(ip);
                                    } else {
                                        eprintln!("Ignoring malformed IP address '{ip}' in 'access-control' setting");
                                    }
                                }

                                _ => {
                                    eprintln!("Ignoring unknown action '{action}' for 'access-control' setting");
                                }
                            }
                        }
                    }
                    ("local-data", v) => {
                        if !zone_file_bytes.is_empty() {
                            zone_file_bytes.push_back(b'\n');
                        }
                        zone_file_bytes
                            .extend(v.trim_matches('"').as_bytes().iter());
                        zone_file_bytes.push_back(b'\n');
                    }
                    ("edns-tcp-keepalive", "yes") => {
                        parsed_config.edns_tcp_keepalive = true;
                    }
                    ("edns-tcp-keepalive-timeout", v) => {
                        if parsed_config.edns_tcp_keepalive {
                            parsed_config.idle_timeout = Some(
                                Duration::from_millis(v.parse().unwrap()),
                            );
                        }
                    }
                    ("provide-xfr", v) => {
                        // provide-xfr: [AXFR|UDP] <ip-address> <key-name | NOKEY> [COMPATIBLE]
                        let mut pieces = v.split(|c: char| c.is_whitespace());
                        let flags_or_ip = pieces.next().unwrap();
                        let strategy;
                        let ixfr_transport;
                        let ip = match flags_or_ip {
                            "AXFR" => {
                                strategy = XfrStrategy::AxfrOnly;
                                ixfr_transport = TransportStrategy::Tcp;
                                pieces.next().unwrap()
                            }
                            "UDP" => {
                                strategy = XfrStrategy::IxfrWithAxfrFallback;
                                ixfr_transport = TransportStrategy::Udp;
                                pieces.next().unwrap()
                            }
                            ip => {
                                strategy = XfrStrategy::IxfrWithAxfrFallback;
                                ixfr_transport = TransportStrategy::Tcp;
                                ip
                            }
                        };

                        let ip = ip.parse().unwrap();
                        let key_name = pieces.next().unwrap();
                        let tsig_key = match key_name {
                            "NOKEY" => None,
                            "TEST" => Some((
                                KeyName::from_str("test").unwrap(),
                                Algorithm::Sha256,
                            )),
                            _ => panic!("Unsupported key name value '{key_name}' for 'provide-xfr' setting"),
                        };
                        let compatibility_mode = match pieces.next() {
                            Some("COMPATIBLE") => CompatibilityMode::BackwardCompatible,
                            Some(data) => panic!("Unsupported trailing data '{data}' for 'provide-xfr' setting"),
                            None => CompatibilityMode::Default,
                        };

                        let xfr_settings = XfrSettings {
                            strategy,
                            ixfr_transport,
                            compatibility_mode,
                        };

                        allow_xfr.allow_from(ip, (xfr_settings, tsig_key));
                    }
                    _ => {
                        eprintln!("Ignoring unknown server setting '{setting}' with value: {value}");
                    }
                }
            }
        }
    }

    if !zone_file_bytes.is_empty() || !allow_xfr.is_empty() {
        let zone_file = (!zone_file_bytes.is_empty())
            .then(|| Zonefile::load(&mut zone_file_bytes).unwrap());

        let zone_type = ZoneType::new_primary(allow_xfr, Acl::new());

        parsed_config.zone = Some(ServerZone {
            zone_file,
            zone_type,
        });
    }

    parsed_config
}
