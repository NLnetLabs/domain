use core::fmt::Debug;
use core::future::ready;
use core::pin::Pin;
use core::str::FromStr;

use std::boxed::Box;
use std::collections::VecDeque;
use std::fs::File;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::string::{String, ToString};
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use futures::Future;
use octseq::Octets;
use ring::test::rand::FixedByteRandom;
use rstest::rstest;
use tracing::warn;
use tracing::{instrument, trace};

use super::mock_dgram_client;
use crate::base::iana::Class;
use crate::base::iana::Rcode;
use crate::base::name::{Name, ToName};
use crate::base::net::IpAddr;
use crate::base::wire::Composer;
use crate::net::client::request::{
    RequestMessage, RequestMessageMulti, SendRequest, SendRequestMulti,
};
use crate::net::client::{dgram, stream, tsig, xfr};
use crate::net::server;
use crate::net::server::buf::VecBufSource;
use crate::net::server::dgram::DgramServer;
use crate::net::server::message::Request;
use crate::net::server::middleware::cookies::CookiesMiddlewareSvc;
use crate::net::server::middleware::edns::EdnsMiddlewareSvc;
use crate::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use crate::net::server::middleware::notify::NotifyMiddlewareSvc;
use crate::net::server::middleware::tsig::TsigMiddlewareSvc;
use crate::net::server::middleware::xfr::{XfrMiddlewareSvc, XfrMode};
use crate::net::server::service::{CallResult, Service, ServiceResult};
use crate::net::server::stream::StreamServer;
use crate::net::server::util::{mk_builder_for_target, service_fn};
//use crate::net::server::tests::integration::tsig::AuthenticatedRequestMessage;
use crate::stelline;
use crate::stelline::channel::ClientServerChannel;
use crate::stelline::client::{
    do_client, do_client_multi, ClientFactory, ClientFactoryMulti,
    CurrStepValue, PerClientAddressClientFactory,
    PerClientAddressClientFactoryMulti, QueryTailoredClientFactory,
    QueryTailoredClientFactoryMulti,
};
use crate::stelline::parse_stelline::{
    self, parse_file, Config, Matches, Stelline,
};
use crate::tsig::{Algorithm, Key, KeyName, KeyStore};
use crate::utils::base16;
use crate::zonecatalog::catalog::{
    self, Catalog, ConnectionFactory, TypedZone, ZoneError, ZoneLookup,
};
use crate::zonecatalog::types::{
    CatalogKeyStore, CompatibilityMode, NotifyConfig, TransportStrategy,
    XfrConfig, XfrStrategy, ZoneConfig,
};
use crate::zonefile::inplace::Zonefile;
use crate::zonetree::Answer;
use crate::zonetree::{Zone, ZoneBuilder};

const MAX_XFR_CONCURRENCY: usize = 1;

//----------- Tests ----------------------------------------------------------

/// Stelline test cases for which the .rpl file defines a server: config
/// block.
///
/// Note: Adding or removing .rpl files on disk won't be detected until the
/// test is re-compiled.
#[instrument(skip_all, fields(rpl = rpl_file.file_name().unwrap().to_str()))]
#[rstest]
#[tokio::test(start_paused = true)]
async fn server_tests(#[files("test-data/server/*.rpl")] rpl_file: PathBuf) {
    // Initialize tracing based logging. Override with env var RUST_LOG, e.g.
    // RUST_LOG=trace. DEBUG level will show the .rpl file name, Stelline step
    // numbers and types as they are being executed.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_thread_ids(true)
        // .without_time()
        .try_init()
        .ok();

    // Load the test .rpl file that determines which queries will be sent
    // and which responses will be expected, and how the server that
    // answers them should be configured.
    let file = File::open(&rpl_file).unwrap();
    let stelline = parse_file(&file, rpl_file.to_str().unwrap());
    let server_config = parse_server_config(&stelline.config);

    // Create a TSIG key store containing a 'TESTKEY'
    let mut key_store = CatalogKeyStore::new();
    let key_name = KeyName::from_str("TESTKEY").unwrap();
    let rng = FixedByteRandom { byte: 0u8 };
    let (key, _) =
        Key::generate(Algorithm::Sha256, &rng, key_name.clone(), None, None)
            .unwrap();
    key_store.insert((key_name, Algorithm::Sha256), key);
    let key_store = Arc::new(key_store);

    // Create a connection factory.
    let dgram_server_conn = ClientServerChannel::new_dgram();
    let stream_server_conn = ClientServerChannel::new_stream();
    let step_value = Arc::new(CurrStepValue::new());
    let conn_factory =
        MockServerConnFactory::new(stelline.clone(), step_value.clone());

    // Create a zone catalog. For now this is only used by the service to
    // query zones, and for XFR-in testing. In future it could also be used
    // with XFR-out and NOTIFY-in/out testing.
    let catalog_config = catalog::Config::new_with_conn_factory(
        key_store.clone(),
        conn_factory,
    );
    let catalog = Catalog::new_with_config(catalog_config);
    let catalog = Arc::new(catalog);

    // Build and insert the test defined zone, if any, into the zone catalog
    if let Some(zone_config) = &server_config.zone {
        let zone = match (&zone_config.zone_name, &zone_config.zone_file) {
            (_, Some(zone_file)) => {
                // This is a primary zone with content already defined.
                Zone::try_from(zone_file.clone()).unwrap()
            }
            (Some(zone_name), None) => {
                // This is a secondary zone with content to be received via
                // XFR.
                let builder = ZoneBuilder::new(
                    Name::from_str(zone_name).unwrap(),
                    Class::IN,
                );
                builder.build()
            }
            _ => unreachable!(),
        };

        let zone = TypedZone::new(zone, zone_config.zone_config.clone());
        catalog.insert_zone(zone).await.unwrap();
    }

    // Start the catalog background service so that incoming XFR/NOTIFY
    // requests will be handled.
    let catalog_clone = catalog.clone();
    tokio::spawn(async move { catalog_clone.run().await });

    // Prepare cookie middleware configuration settings.
    let with_cookies = server_config.cookies.enabled
        && server_config.cookies.secret.is_some();

    let secret = if with_cookies {
        let secret = server_config.cookies.secret.unwrap();
        let secret = base16::decode_vec(secret).unwrap();
        <[u8; 16]>::try_from(secret).unwrap()
    } else {
        Default::default()
    };

    // Create a layered service to respond to received DNS queries. The layers
    // are created top to bottom, with the application specific logic service
    // on top and generic DNS logic below. Behaviour required by implemented
    // DNS RFCs will be applied/enforced before the application logic receives
    // it and without it having to know or do anything about it.

    // 1. Application logic service
    let svc = service_fn(test_service, catalog.clone());

    // 2. DNS COOKIES middleware service
    let svc = CookiesMiddlewareSvc::new(svc, secret)
        .with_denied_ips(server_config.cookies.ip_deny_list.clone())
        .enable(with_cookies);

    // 3. EDNS middleware service
    let svc =
        EdnsMiddlewareSvc::new(svc).enable(server_config.edns_tcp_keepalive);

    // 4. XFR(-in) middleware service (XFR-out is handled by the Catalog).
    let svc = XfrMiddlewareSvc::<Vec<u8>, _, _>::new(
        svc,
        catalog.clone(),
        MAX_XFR_CONCURRENCY,
        XfrMode::AxfrAndIxfr,
    );

    // 5. NOTIFY(-in) middleware service (relayed to the Catalog for handling,
    // and the Catalog is also responsible for NOTIFY-out).
    let svc = NotifyMiddlewareSvc::<Vec<u8>, _, _, _>::new(svc, catalog);

    // 6. Mandatory DNS behaviour (e.g. RFC 1034/35 rules).
    let svc = MandatoryMiddlewareSvc::new(svc);

    // 7. TSIG message authentication.
    let svc = TsigMiddlewareSvc::new(svc, key_store.clone());

    // NOTE: TSIG middleware *MUST* be the first middleware in the chain per
    // RFC 8945 as it has to see incoming messages prior to any modification
    // in order to verify the signature, and has to sign outgoing messages in
    // their final state without any modification occuring thereafter.

    // 8. The dgram and stream servers that receive DNS queries and dispatch
    // them to the service layers above.
    let (dgram_srv, stream_srv) = mk_servers(
        svc,
        &server_config,
        dgram_server_conn.clone(),
        stream_server_conn.clone(),
    );

    // Create a client factory for creating DNS clients per Stelline STEP with
    // the appropriate configuration (as defined by the .rpl content) to
    // submit requests to our DNS servers. No actual network communication
    // takes place, these clients and servers use a direct in-memory channel
    // to exchange messages instead of actual network sockets.
    let client_factory =
        mk_client_factory(dgram_server_conn, stream_server_conn, key_store);

    // Run the Stelline test!
    do_client(&stelline, &step_value, client_factory).await;

    // Await shutdown
    if !dgram_srv.await_shutdown(Duration::from_secs(5)).await {
        warn!("Datagram server did not shutdown on time.");
    }

    if !stream_srv.await_shutdown(Duration::from_secs(5)).await {
        warn!("Stream server did not shutdown on time.");
    }
}

/// Stelline test cases for which the .rpl file defines a server: config
/// block.
///
/// Note: Adding or removing .rpl files on disk won't be detected until the
/// test is re-compiled.
#[instrument(skip_all, fields(rpl = rpl_file.file_name().unwrap().to_str()))]
#[rstest]
#[tokio::test(start_paused = true)]
async fn server_tests_multi(
    #[files("test-data/server/multi/*.rpl")] rpl_file: PathBuf,
) {
    // Initialize tracing based logging. Override with env var RUST_LOG, e.g.
    // RUST_LOG=trace. DEBUG level will show the .rpl file name, Stelline step
    // numbers and types as they are being executed.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_thread_ids(true)
        // .without_time()
        .try_init()
        .ok();

    // Load the test .rpl file that determines which queries will be sent
    // and which responses will be expected, and how the server that
    // answers them should be configured.
    let file = File::open(&rpl_file).unwrap();
    let stelline = parse_file(&file, rpl_file.to_str().unwrap());
    let server_config = parse_server_config(&stelline.config);

    // Create a TSIG key store containing a 'TESTKEY'
    let mut key_store = CatalogKeyStore::new();
    let key_name = KeyName::from_str("TESTKEY").unwrap();
    let rng = FixedByteRandom { byte: 0u8 };
    let (key, _) =
        Key::generate(Algorithm::Sha256, &rng, key_name.clone(), None, None)
            .unwrap();
    key_store.insert((key_name, Algorithm::Sha256), key);
    let key_store = Arc::new(key_store);

    // Create a connection factory.
    let dgram_server_conn = ClientServerChannel::new_dgram();
    let stream_server_conn = ClientServerChannel::new_stream();
    let step_value = Arc::new(CurrStepValue::new());
    let conn_factory =
        MockServerConnFactory::new(stelline.clone(), step_value.clone());

    // Create a zone catalog. For now this is only used by the service to
    // query zones, and for XFR-in testing. In future it could also be used
    // with XFR-out and NOTIFY-in/out testing.
    let catalog_config = catalog::Config::new_with_conn_factory(
        key_store.clone(),
        conn_factory,
    );
    let catalog = Catalog::new_with_config(catalog_config);
    let catalog = Arc::new(catalog);

    // Build and insert the test defined zone, if any, into the zone catalog
    if let Some(zone_config) = &server_config.zone {
        let zone = match (&zone_config.zone_name, &zone_config.zone_file) {
            (_, Some(zone_file)) => {
                // This is a primary zone with content already defined.
                Zone::try_from(zone_file.clone()).unwrap()
            }
            (Some(zone_name), None) => {
                // This is a secondary zone with content to be received via
                // XFR.
                let builder = ZoneBuilder::new(
                    Name::from_str(zone_name).unwrap(),
                    Class::IN,
                );
                builder.build()
            }
            _ => unreachable!(),
        };

        let zone = TypedZone::new(zone, zone_config.zone_config.clone());
        catalog.insert_zone(zone).await.unwrap();
    }

    // Start the catalog background service so that incoming XFR/NOTIFY
    // requests will be handled.
    let catalog_clone = catalog.clone();
    tokio::spawn(async move { catalog_clone.run().await });

    // Prepare cookie middleware configuration settings.
    let with_cookies = server_config.cookies.enabled
        && server_config.cookies.secret.is_some();

    let secret = if with_cookies {
        let secret = server_config.cookies.secret.unwrap();
        let secret = base16::decode_vec(secret).unwrap();
        <[u8; 16]>::try_from(secret).unwrap()
    } else {
        Default::default()
    };

    // Create a layered service to respond to received DNS queries. The layers
    // are created top to bottom, with the application specific logic service
    // on top and generic DNS logic below. Behaviour required by implemented
    // DNS RFCs will be applied/enforced before the application logic receives
    // it and without it having to know or do anything about it.

    // 1. Application logic service
    let svc = service_fn(test_service, catalog.clone());

    // 2. DNS COOKIES middleware service
    let svc = CookiesMiddlewareSvc::new(svc, secret)
        .with_denied_ips(server_config.cookies.ip_deny_list.clone())
        .enable(with_cookies);

    // 3. EDNS middleware service
    let svc =
        EdnsMiddlewareSvc::new(svc).enable(server_config.edns_tcp_keepalive);

    // 4. XFR(-in) middleware service (XFR-out is handled by the Catalog).
    let svc = XfrMiddlewareSvc::<Vec<u8>, _, _>::new(
        svc,
        catalog.clone(),
        MAX_XFR_CONCURRENCY,
        XfrMode::AxfrAndIxfr,
    );

    // 5. NOTIFY(-in) middleware service (relayed to the Catalog for handling,
    // and the Catalog is also responsible for NOTIFY-out).
    let svc = NotifyMiddlewareSvc::<Vec<u8>, _, _, _>::new(svc, catalog);

    // 6. Mandatory DNS behaviour (e.g. RFC 1034/35 rules).
    let svc = MandatoryMiddlewareSvc::new(svc);

    // 7. TSIG message authentication.
    let svc = TsigMiddlewareSvc::new(svc, key_store.clone());

    // NOTE: TSIG middleware *MUST* be the first middleware in the chain per
    // RFC 8945 as it has to see incoming messages prior to any modification
    // in order to verify the signature, and has to sign outgoing messages in
    // their final state without any modification occuring thereafter.

    // 8. The dgram and stream servers that receive DNS queries and dispatch
    // them to the service layers above.
    let (dgram_srv, stream_srv) = mk_servers(
        svc,
        &server_config,
        dgram_server_conn.clone(),
        stream_server_conn.clone(),
    );

    // Create a client factory for creating DNS clients per Stelline STEP with
    // the appropriate configuration (as defined by the .rpl content) to
    // submit requests to our DNS servers. No actual network communication
    // takes place, these clients and servers use a direct in-memory channel
    // to exchange messages instead of actual network sockets.
    let client_factory =
        mk_client_factory_multi(stream_server_conn, key_store);

    // Run the Stelline test!
    do_client_multi(&stelline, &step_value, client_factory).await;

    // Await shutdown
    if !dgram_srv.await_shutdown(Duration::from_secs(5)).await {
        warn!("Datagram server did not shutdown on time.");
    }

    if !stream_srv.await_shutdown(Duration::from_secs(5)).await {
        warn!("Stream server did not shutdown on time.");
    }
}

//----------- test helpers ---------------------------------------------------

#[allow(clippy::type_complexity)]
fn mk_servers<Svc>(
    service: Svc,
    server_config: &ServerConfig,
    dgram_server_conn: ClientServerChannel,
    stream_server_conn: ClientServerChannel,
) -> (
    Arc<DgramServer<ClientServerChannel, VecBufSource, Svc>>,
    Arc<StreamServer<ClientServerChannel, VecBufSource, Svc>>,
)
where
    Svc: Clone + Service + Send + Sync,
    <Svc as Service>::Future: Send,
    <Svc as Service>::Target: Composer + Default + Send + Sync,
    <Svc as Service>::Stream: Send,
{
    // Prepare middleware to be used by the DNS servers to pre-process
    // received requests and post-process created responses.
    let (dgram_config, stream_config) = mk_server_configs(server_config);

    // Create a dgram server for handling UDP requests.
    let dgram_server = DgramServer::<_, _, Svc>::with_config(
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
    let stream_server = StreamServer::with_config(
        stream_server_conn.clone(),
        VecBufSource,
        service,
        stream_config,
    );
    let stream_server = Arc::new(stream_server);
    let cloned_stream_server = stream_server.clone();
    tokio::spawn(async move { cloned_stream_server.run().await });

    (dgram_server, stream_server)
}

fn mk_client_factory(
    dgram_server_conn: ClientServerChannel,
    stream_server_conn: ClientServerChannel,
    key_store: Arc<CatalogKeyStore>,
) -> impl ClientFactory {
    // Create a TCP client factory that only creates a client if (a) no
    // existing TCP client exists for the source address of the Stelline query,
    // and (b) if the query specifies "MATCHES TCP". Clients created by this
    // factory connect to the TCP server created above.
    let only_for_tcp_queries = |entry: &parse_stelline::Entry| {
        matches!(entry.matches, Some(Matches { tcp: true, .. }))
    };

    let tcp_key_store = key_store.clone();
    let tcp_client_factory = PerClientAddressClientFactory::new(
        move |source_addr, entry| {
            let key = entry.key_name.as_ref().and_then(|key_name| {
                tcp_key_store.get_key(&key_name, Algorithm::Sha256)
            });
            let (client, transport) =
                stream::Connection::<_, RequestMessageMulti<Vec<u8>>>::new(
                    stream_server_conn
                        .connect(Some(SocketAddr::new(*source_addr, 0))),
                );

            tokio::spawn(async move {
                transport.run().await;
                trace!("TCP connection terminated");
            });

            let client = xfr::Connection::new(None, client);
            Box::new(tsig::Connection::new(key, client))
        },
        only_for_tcp_queries,
    );

    // Create a UDP client factory that only creates a client if no existing
    // UDP client exists for the source address of the Stelline query.
    let for_all_other_queries = |_: &_| true;

    let udp_client_factory = PerClientAddressClientFactory::new(
        move |source_addr, entry| {
            let connect = dgram_server_conn
                .new_client(Some(SocketAddr::new(*source_addr, 0)));

            match entry.matches.as_ref().map(|v| v.mock_client) {
                Some(true) => {
                    Box::new(mock_dgram_client::Connection::new(connect))
                }
                _ => {
                    let key = entry.key_name.as_ref().and_then(|key_name| {
                        key_store.get_key(&key_name, Algorithm::Sha256)
                    });
                    let client = dgram::Connection::new(connect);
                    // While AXFR is TCP only, IXFR can also be done over UDP.
                    let client = xfr::Connection::new(None, client);
                    Box::new(tsig::Connection::new(key, client))
                }
            }
        },
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

fn mk_client_factory_multi(
    stream_server_conn: ClientServerChannel,
    key_store: Arc<CatalogKeyStore>,
) -> impl ClientFactoryMulti {
    // Create a TCP client factory that only creates a client if (a) no
    // existing TCP client exists for the source address of the Stelline query,
    // and (b) if the query specifies "MATCHES TCP". Clients created by this
    // factory connect to the TCP server created above.
    let only_for_tcp_queries = |entry: &parse_stelline::Entry| {
        matches!(entry.matches, Some(Matches { tcp: true, .. }))
    };

    let tcp_key_store = key_store.clone();
    let tcp_client_factory = PerClientAddressClientFactoryMulti::new(
        move |source_addr, entry| {
            let key = entry.key_name.as_ref().and_then(|key_name| {
                tcp_key_store.get_key(&key_name, Algorithm::Sha256)
            });
            let (client, transport) =
                stream::Connection::<RequestMessage<Vec<u8>>, _>::new(
                    stream_server_conn
                        .connect(Some(SocketAddr::new(*source_addr, 0))),
                );

            tokio::spawn(async move {
                transport.run().await;
                trace!("TCP connection terminated");
            });

            let client = xfr::Connection::new(None, client);
            Box::new(tsig::Connection::new(key, client))
        },
        only_for_tcp_queries,
    );

    // Create a UDP client factory that only creates a client if no existing
    // UDP client exists for the source address of the Stelline query.
    // let for_all_other_queries = |_: &_| true;

    // UDP cannot do Multi
    /*
    let udp_client_factory = PerClientAddressClientFactoryMulti::new(
        move |source_addr, entry| {
            let connect = dgram_server_conn
                .new_client(Some(SocketAddr::new(*source_addr, 0)));

            match entry.matches.as_ref().map(|v| v.mock_client) {
                Some(true) => {
                    Box::new(mock_dgram_client::Connection::new(connect))
                }
                _ => {
                    let key = entry.key_name.as_ref().and_then(|key_name| {
                        key_store.get_key(&key_name, Algorithm::Sha256)
                    });
                    let client = dgram::Connection::new(connect);
                    // While AXFR is TCP only, IXFR can also be done over UDP.
                    let client = xfr::Connection::new(None, client);
                    Box::new(tsig::Connection::new(key, client))
                }
            }
        },
        for_all_other_queries,
    );
    */

    // Create a combined client factory that will allow the Stelline runner to
    // use existing or create new client connections as appropriate for the
    // Stelline query being evaluated.
    QueryTailoredClientFactoryMulti::new(vec![
        Box::new(tcp_client_factory),
        // Box::new(udp_client_factory),
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
fn test_service<T: ZoneLookup>(
    request: Request<Vec<u8>>,
    catalog: T,
) -> ServiceResult<Vec<u8>> {
    let question = request.message().sole_question().unwrap();

    let answer = match catalog.find_zone(question.qname(), question.qclass())
    {
        Ok(Some(zone)) => {
            let readable_zone = zone.read();
            let qname = question.qname().to_bytes();
            let qtype = question.qtype();
            readable_zone.query(qname, qtype).unwrap()
        }
        Ok(None) => Answer::new(Rcode::NXDOMAIN),
        Err(ZoneError::TemporarilyUnavailable) => {
            Answer::new(Rcode::SERVFAIL)
        }
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
    /// Used for an empty secondary zone. Ignored if zone_file is Some.
    zone_name: Option<String>,

    zone_file: Option<Zonefile>,

    zone_config: ZoneConfig,
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
    let mut zone_name = None;
    let mut zone_config = ZoneConfig::default();

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
                    ("allow-notify", v) => {
                        // allow-notify: <ip-address> <key-name | NOKEY>
                        let mut pieces = v.split(|c: char| c.is_whitespace());

                        let ip = pieces.next().unwrap();
                        let ip = ip.parse().unwrap();

                        let key_name = pieces.next().unwrap();
                        let tsig_key = match key_name {
                            "NOKEY" => None,
                            name => Some((
                                KeyName::from_str(name).unwrap(),
                                Algorithm::Sha256,
                            )),
                        };

                        let notify_config = NotifyConfig { tsig_key };

                        zone_config
                            .allow_notify_from
                            .add_src(ip, notify_config);
                    }
                    ("provide-xfr", v) | ("request-xfr", v) => {
                        // provide-xfr: [AXFR|UDP] <ip-address> <key-name | NOKEY> [COMPATIBLE]
                        // request-xfr: [AXFR|UDP] <ip-address>[:<port>] <key-name | NOKEY> [COMPATIBLE]
                        let mut pieces = v.split(|c: char| c.is_whitespace());
                        let flags_or_ip = pieces.next().unwrap();
                        let strategy;
                        let ixfr_transport;
                        let addr = match flags_or_ip {
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

                        let key_name = pieces.next().unwrap();
                        let tsig_key = match key_name {
                            "NOKEY" => None,
                            name => Some((
                                KeyName::from_str(name).unwrap(),
                                Algorithm::Sha256,
                            )),
                        };

                        let compatibility_mode = if setting == "provide-xfr" {
                            match pieces.next() {
                                Some("COMPATIBLE") => CompatibilityMode::BackwardCompatible,
                                Some(data) => panic!("Unsupported trailing data '{data}' for 'provide-xfr' setting"),
                                None => CompatibilityMode::Default,
                            }
                        } else {
                            CompatibilityMode::Default
                        };

                        let xfr_config = XfrConfig {
                            strategy,
                            ixfr_transport,
                            compatibility_mode,
                            tsig_key,
                        };

                        match setting {
                            "request-xfr" => {
                                let addr = addr
                                    .parse()
                                    .or_else(|_| format!("{addr}:53").parse())
                                    .unwrap();
                                zone_config
                                    .request_xfr_from
                                    .add_dst(addr, xfr_config);
                            }
                            "provide-xfr" => {
                                zone_config.provide_xfr_to.add_src(
                                    addr.parse().unwrap(),
                                    xfr_config,
                                );
                            }
                            _ => unreachable!(),
                        }
                    }
                    ("zone", v) => {
                        // zone: <name>
                        zone_name = Some(v.to_string());
                    }
                    _ => {
                        eprintln!("Ignoring unknown server setting '{setting}' with value: {value}");
                    }
                }
            }
        }
    }

    let zone_file = (!zone_file_bytes.is_empty())
        .then(|| Zonefile::load(&mut zone_file_bytes).unwrap());

    parsed_config.zone = Some(ServerZone {
        zone_name,
        zone_file,
        zone_config,
    });

    parsed_config
}

#[allow(dead_code)]
#[derive(Clone, Default)]
struct TestServerConnFactory {
    dgram_server_conn: ClientServerChannel,
    stream_server_conn: ClientServerChannel,
}

/*
impl ConnectionFactory for TestServerConnFactory {
    type Error = String;

    fn get<K, Octs>(
        &self,
        _dest: SocketAddr,
        strategy: TransportStrategy,
        key: Option<K>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Option<
                            Box<
                                dyn SendRequest<RequestMessage<Octs>>
                                    + Send
                                    + Sync
                                    + 'static,
                            >,
                        >,
                        Self::Error,
                    >,
                > + Send
                + Sync
                + 'static,
        >,
    >
    where
        K: Clone + Debug + AsRef<Key> + Send + Sync + 'static,
        Octs: Octets + Debug + Send + Sync + 'static,
    {
        let client = match strategy {
            TransportStrategy::None => Ok(None),

            TransportStrategy::Udp => {
                let mut dgram_config = dgram::Config::new();
                dgram_config.set_max_parallel(1);
                dgram_config.set_read_timeout(Duration::from_millis(1000));
                dgram_config.set_max_retries(1);
                dgram_config.set_udp_payload_size(Some(1400));

                let client = dgram::Connection::with_config(
                    self.dgram_server_conn.new_client(None),
                    dgram_config,
                );
                Ok(Some(Box::new(tsig::Connection::new(key, client))
                    as Box<
                        dyn SendRequest<RequestMessage<Octs>> + Send + Sync,
                    >))
            }

            TransportStrategy::Tcp => {
                let mut stream_config = stream::Config::new();
                stream_config.set_response_timeout(Duration::from_secs(2));
                // Allow time between the SOA query response and sending the
                // AXFR/IXFR request.
                stream_config.set_idle_timeout(Duration::from_secs(5));
                // Allow much more time for an XFR streaming response.
                stream_config
                    .set_streaming_response_timeout(Duration::from_secs(30));

                let (client, transport) = {
                    stream::Connection::<_, RequestMessageMulti<Vec<u8>>>::with_config(
                        self.stream_server_conn.connect(None),
                        stream_config,
                    )
                };

                tokio::spawn(async move {
                    transport.run().await;
                    trace!("TCP connection terminated");
                });

                Ok(Some(Box::new(tsig::Connection::new(key, client))
                    as Box<
                        dyn SendRequest<RequestMessage<Octs>> + Send + Sync,
                    >))
            }
        };

        Box::pin(ready(client))
    }
}
*/

#[derive(Clone)]
struct MockServerConnFactory {
    stelline: Stelline,
    step_value: Arc<CurrStepValue>,
}

impl Default for MockServerConnFactory {
    fn default() -> Self {
        unimplemented!()
    }
}

impl MockServerConnFactory {
    fn new(stelline: Stelline, step_value: Arc<CurrStepValue>) -> Self {
        Self {
            stelline,
            step_value,
        }
    }
}

impl ConnectionFactory for MockServerConnFactory {
    type Error = String;

    fn get<K, Octs>(
        &self,
        _dest: SocketAddr,
        strategy: TransportStrategy,
        key: Option<K>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Option<
                            Box<
                                dyn SendRequest<RequestMessage<Octs>>
                                    + Send
                                    + Sync
                                    + 'static,
                            >,
                        >,
                        Self::Error,
                    >,
                > + Send
                + Sync
                + 'static,
        >,
    >
    where
        K: Clone + Debug + AsRef<Key> + Send + Sync + 'static,
        Octs: Octets + Debug + Send + Sync + 'static,
    {
        let client = match strategy {
            TransportStrategy::None => Ok(None),

            TransportStrategy::Udp => {
                let mut dgram_config = dgram::Config::new();
                dgram_config.set_max_parallel(1);
                dgram_config.set_read_timeout(Duration::from_millis(1000));
                dgram_config.set_max_retries(1);
                dgram_config.set_udp_payload_size(Some(1400));

                let dgram_conn = stelline::dgram::Dgram::new(
                    self.stelline.clone(),
                    self.step_value.clone(),
                );
                let client =
                    dgram::Connection::with_config(dgram_conn, dgram_config);
                Ok(Some(Box::new(tsig::Connection::new(key, client))
                    as Box<
                        dyn SendRequest<RequestMessage<Octs>> + Send + Sync,
                    >))
            }

            TransportStrategy::Tcp => {
                let mut stream_config = stream::Config::new();
                stream_config.set_response_timeout(Duration::from_secs(2));
                // Allow time between the SOA query response and sending the
                // AXFR/IXFR request.
                stream_config.set_idle_timeout(Duration::from_secs(5));
                // Allow much more time for an XFR streaming response.
                stream_config
                    .set_streaming_response_timeout(Duration::from_secs(30));

                let (client, transport) = {
                    let stream_conn = stelline::connection::Connection::new(
                        self.stelline.clone(),
                        self.step_value.clone(),
                    );
                    stream::Connection::<_, RequestMessageMulti<Vec<u8>>>::with_config(
                        stream_conn,
                        stream_config,
                    )
                };

                tokio::spawn(async move {
                    transport.run().await;
                    trace!("TCP connection terminated");
                });

                Ok(Some(Box::new(tsig::Connection::new(key, client))
                    as Box<
                        dyn SendRequest<RequestMessage<Octs>> + Send + Sync,
                    >))
            }
        };

        Box::pin(ready(client))
    }
    fn get_multi<K, Octs>(
        &self,
        _dest: SocketAddr,
        strategy: TransportStrategy,
        key: Option<K>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        Option<
                            Box<
                                dyn SendRequestMulti<
                                        RequestMessageMulti<Octs>,
                                    > + Send
                                    + Sync
                                    + 'static,
                            >,
                        >,
                        Self::Error,
                    >,
                > + Send
                + Sync
                + 'static,
        >,
    >
    where
        K: Clone + Debug + AsRef<Key> + Send + Sync + 'static,
        Octs: Octets + Debug + Send + Sync + 'static,
    {
        let client = match strategy {
            TransportStrategy::None => Ok(None),

            TransportStrategy::Udp => {
                // We cannot do Multi for UDP.
                todo!();
                /*
                        let mut dgram_config = dgram::Config::new();
                        dgram_config.set_max_parallel(1);
                        dgram_config.set_read_timeout(Duration::from_millis(1000));
                        dgram_config.set_max_retries(1);
                        dgram_config.set_udp_payload_size(Some(1400));

                        let dgram_conn = stelline::dgram::Dgram::new(
                            self.stelline.clone(),
                            self.step_value.clone(),
                        );
                        let client =
                            dgram::Connection::with_config(dgram_conn, dgram_config);
                        Ok(Some(Box::new(tsig::Connection::new(key, client))
                            as Box<
                                dyn SendRequestMulti<RequestMessageMulti<Octs>> + Send + Sync,
                            >))
                */
            }

            TransportStrategy::Tcp => {
                let mut stream_config = stream::Config::new();
                stream_config.set_response_timeout(Duration::from_secs(2));
                // Allow time between the SOA query response and sending the
                // AXFR/IXFR request.
                stream_config.set_idle_timeout(Duration::from_secs(5));
                // Allow much more time for an XFR streaming response.
                stream_config
                    .set_streaming_response_timeout(Duration::from_secs(30));

                let (client, transport) = {
                    let stream_conn = stelline::connection::Connection::new(
                        self.stelline.clone(),
                        self.step_value.clone(),
                    );
                    stream::Connection::<RequestMessage<Vec<u8>>, _>::with_config(
                        stream_conn,
                        stream_config,
                    )
                };

                tokio::spawn(async move {
                    transport.run().await;
                    trace!("TCP connection terminated");
                });

                Ok(Some(Box::new(tsig::Connection::new(key, client))
                    as Box<
                        dyn SendRequestMulti<RequestMessageMulti<Octs>>
                            + Send
                            + Sync,
                    >))
            }
        };

        Box::pin(ready(client))
    }
}
