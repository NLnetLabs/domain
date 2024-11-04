use core::future::{ready, Future};
use core::ops::Deref;
use core::pin::Pin;
use core::str::FromStr;

use std::boxed::Box;
use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::result::Result;
use std::string::{String, ToString};
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use ring::test::rand::FixedByteRandom;
use rstest::rstest;
use tracing::instrument;
use tracing::{trace, warn};

use crate::base::iana::{Class, Rcode};
use crate::base::name::ToName;
use crate::base::net::IpAddr;
use crate::base::wire::Composer;
use crate::base::Name;
use crate::base::Rtype;
use crate::net::client::request::{RequestMessage, RequestMessageMulti};
use crate::net::client::{dgram, stream, tsig};
use crate::net::server;
use crate::net::server::buf::VecBufSource;
use crate::net::server::dgram::DgramServer;
use crate::net::server::message::Request;
use crate::net::server::middleware::cookies::CookiesMiddlewareSvc;
use crate::net::server::middleware::edns::EdnsMiddlewareSvc;
use crate::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use crate::net::server::middleware::notify::{
    Notifiable, NotifyError, NotifyMiddlewareSvc,
};
use crate::net::server::middleware::tsig::TsigMiddlewareSvc;
use crate::net::server::middleware::xfr::XfrMiddlewareSvc;
use crate::net::server::service::{CallResult, Service, ServiceResult};
use crate::net::server::stream::StreamServer;
use crate::net::server::util::{mk_builder_for_target, service_fn};
use crate::stelline::channel::ClientServerChannel;
use crate::stelline::client::{
    do_client, Client, ClientFactory, CurrStepValue,
    PerClientAddressClientFactory, QueryTailoredClientFactory,
};
use crate::stelline::parse_stelline::{self, parse_file, Config, Matches};
use crate::stelline::simple_dgram_client;
use crate::tsig::{Algorithm, Key, KeyName, KeyStore};
use crate::utils::base16;
use crate::zonefile::inplace::Zonefile;
use crate::zonetree::{Answer, Zone};
use crate::zonetree::{StoredName, ZoneBuilder, ZoneTree};

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
    // Load the test .rpl file that determines which queries will be sent and
    // which responses will be expected, and how the server that answers them
    // should be configured.

    // Initialize tracing based logging. Override with env var RUST_LOG, e.g.
    // RUST_LOG=trace. DEBUG level will show the .rpl file name, Stelline step
    // numbers and types as they are being executed.
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        .try_init()
        .ok();

    // Load the test .rpl file that determines which queries will be sent
    // and which responses will be expected, and how the server that
    // answers them should be configured.
    let file = File::open(&rpl_file).unwrap();
    let stelline = parse_file(&file, rpl_file.to_str().unwrap());
    let server_config = parse_server_config(&stelline.config);

    // Create a TSIG key store containing a 'TESTKEY'
    let mut key_store = TestKeyStore::new();
    let key_name = KeyName::from_str("TESTKEY").unwrap();
    let rng = FixedByteRandom { byte: 0u8 };
    let (key, _) =
        Key::generate(Algorithm::Sha256, &rng, key_name.clone(), None, None)
            .unwrap();
    key_store.insert((key_name, Algorithm::Sha256), key.into());
    let key_store = Arc::new(key_store);

    // Create a connection factory.
    let dgram_server_conn = ClientServerChannel::new_dgram();
    let stream_server_conn = ClientServerChannel::new_stream();

    // Build the test defined zone, if any.
    let mut zones = ZoneTree::new();
    match &server_config.zone {
        ServerZone {
            zone_files: zfs, ..
        } if !zfs.is_empty() => {
            // One or more primary zone with content already defined.
            for zone_file in zfs {
                zones
                    .insert_zone(Zone::try_from(zone_file.clone()).unwrap())
                    .unwrap();
            }
        }

        ServerZone {
            zone_name: Some(zone_name),
            ..
        } => {
            // This is a secondary zone with content to be received via
            // XFR.
            let builder = ZoneBuilder::new(
                Name::from_str(zone_name).unwrap(),
                Class::IN,
            );
            zones.insert_zone(builder.build()).unwrap();
        }

        ServerZone {
            zone_files: zfs,
            zone_name: None,
        } if zfs.is_empty() => {
            // No zones defined at all.
        }

        _ => {
            unimplemented!()
        }
    }
    let zones = Arc::new(zones);

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
    let svc = service_fn(test_service, zones.clone());

    // 2. DNS COOKIES middleware service
    let svc = CookiesMiddlewareSvc::new(svc, secret)
        .with_denied_ips(server_config.cookies.ip_deny_list.clone())
        .enable(with_cookies);

    // 3. EDNS middleware service
    let svc =
        EdnsMiddlewareSvc::new(svc).enable(server_config.edns_tcp_keepalive);

    // 4. RFC 5936 AXFR and RFC 1995 IXFR middleware service.
    let svc = XfrMiddlewareSvc::<Vec<u8>, _, Option<Arc<Key>>, _>::new(
        svc, zones, 1,
    );

    // 5. RFC 1996 NOTIFY support.
    let svc = NotifyMiddlewareSvc::new(svc, TestNotifyTarget);

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
    let step_value = Arc::new(CurrStepValue::new());
    do_client(&stelline, &step_value, client_factory).await;

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
    key_store: Arc<TestKeyStore>,
) -> impl ClientFactory {
    // Create a TCP client factory that only creates a client if (a) no
    // existing TCP client exists for the source address of the Stelline
    // query, and (b) if the query specifies "MATCHES TCP". Clients created by
    // this factory connect to the TCP server created above.
    let only_for_tcp_queries = |entry: &parse_stelline::Entry| {
        matches!(entry.matches, Some(Matches { tcp: true, .. }))
    };

    let tcp_key_store = key_store.clone();
    let tcp_client_factory = PerClientAddressClientFactory::new(
        move |source_addr, entry| {
            let stream = stream_server_conn
                .connect(Some(SocketAddr::new(*source_addr, 0)));

            let key = entry.key_name.as_ref().and_then(|key_name| {
                tcp_key_store.get_key(&key_name, Algorithm::Sha256)
            });

            if let Some(key) = key {
                let (conn, transport) = stream::Connection::<
                    tsig::RequestMessage<RequestMessage<Vec<u8>>, Arc<Key>>,
                    tsig::RequestMessage<
                        RequestMessageMulti<Vec<u8>>,
                        Arc<Key>,
                    >,
                >::new(stream);

                tokio::spawn(transport.run());

                let conn = Box::new(tsig::Connection::new(key, conn));

                if let Some(sections) = &entry.sections {
                    if let Some(q) = sections.question.first() {
                        if matches!(q.qtype(), Rtype::AXFR | Rtype::IXFR) {
                            return Client::Multi(conn);
                        }
                    }
                }
                Client::Single(conn)
            } else {
                let (conn, transport) = stream::Connection::<
                    RequestMessage<Vec<u8>>,
                    RequestMessageMulti<Vec<u8>>,
                >::new(stream);

                tokio::spawn(transport.run());

                let conn = Box::new(conn);

                if let Some(sections) = &entry.sections {
                    if let Some(q) = sections.question.first() {
                        if matches!(q.qtype(), Rtype::AXFR | Rtype::IXFR) {
                            return Client::Multi(conn);
                        }
                    }
                }
                Client::Single(conn)
            }
        },
        only_for_tcp_queries,
    );

    // Create a UDP client factory that only creates a client if (a) no
    // existing UDP client exists for the source address of the Stelline
    // query.
    let for_all_other_queries = |_: &_| true;

    let udp_client_factory = PerClientAddressClientFactory::new(
        move |source_addr, entry| {
            let connect = dgram_server_conn
                .new_client(Some(SocketAddr::new(*source_addr, 0)));

            let key = entry.key_name.as_ref().and_then(|key_name| {
                key_store.get_key(&key_name, Algorithm::Sha256)
            });

            if let Some(key) = key {
                match entry.matches.as_ref().map(|v| v.mock_client) {
                    Some(true) => {
                        Client::Single(Box::new(tsig::Connection::new(
                            key,
                            simple_dgram_client::Connection::new(connect),
                        )))
                    }

                    _ => Client::Single(Box::new(tsig::Connection::new(
                        key,
                        dgram::Connection::new(connect),
                    ))),
                }
            } else {
                match entry.matches.as_ref().map(|v| v.mock_client) {
                    Some(true) => Client::Single(Box::new(
                        simple_dgram_client::Connection::new(connect),
                    )),

                    _ => {
                        let mut config = dgram::Config::new();
                        config.set_max_retries(0);
                        Client::Single(Box::new(
                            dgram::Connection::with_config(connect, config),
                        ))
                    }
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
// The functionality provided is the mininum common set of behaviour needed by
// the tests that use it.
//
// It's behaviour should be influenced to match the conditions under test by:
//   - Using different `MiddlewareChain` setups with the server(s) to which
//     the `Service` will be passed.
//   - Controlling the content of the `Zonefile` passed to instances of this
//     `Service` impl.
#[allow(clippy::type_complexity)]
fn test_service<RequestMeta>(
    request: Request<Vec<u8>, RequestMeta>,
    zones: Arc<ZoneTree>,
) -> ServiceResult<Vec<u8>> {
    let question = request.message().sole_question().unwrap();

    let answer = match zones.find_zone(question.qname(), question.qclass()) {
        Some(zone) => {
            let readable_zone = zone.read();
            let qname = question.qname().to_bytes();
            let qtype = question.qtype();
            readable_zone.query(qname, qtype).unwrap()
        }
        None => Answer::new(Rcode::NXDOMAIN),
    };

    let builder = mk_builder_for_target();
    let additional = answer.to_message(request.message(), builder);
    Ok(CallResult::new(additional))
}

//----------- Stelline config block parsing -----------------------------------

#[derive(Default)]
struct ServerZone {
    /// Used for an empty secondary zone. Ignored if zone_files is non-empty.
    zone_name: Option<String>,
    zone_files: Vec<Zonefile>,
}

#[derive(Default)]
struct ServerConfig<'a> {
    cookies: CookieConfig<'a>,
    edns_tcp_keepalive: bool,
    idle_timeout: Option<Duration>,
    zone: ServerZone,
}

#[derive(Default)]
struct CookieConfig<'a> {
    enabled: bool,
    secret: Option<&'a str>,
    ip_deny_list: Vec<IpAddr>,
}

fn parse_server_config(config: &Config) -> ServerConfig {
    let mut parsed_config = ServerConfig::default();
    let mut in_server_block = false;
    let mut zone_name = None;
    let mut zone_file_bytes = VecDeque::<u8>::new();
    let mut zone_files = vec![];

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
                        // an IP address here for now. See:
                        // https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html?highlight=edns-tcp-keepalive#unbound-conf-access-control
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
                    ("local-file", v) => {
                        let zone_path =
                            Path::new("test-data").join(v.trim_matches('"'));
                        let zone_file = Zonefile::load(
                            &mut File::open(zone_path).unwrap(),
                        )
                        .unwrap();
                        zone_files.push(zone_file);
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
                    ("zone", v) => {
                        // zone: <name>
                        zone_file_bytes = Default::default();
                        zone_name = Some(v.to_string());
                    }
                    _ => {
                        eprintln!("Ignoring unknown server setting '{setting}' with value: {value:?}");
                    }
                }
            }
        }
    }

    if let Some(zone_file) = (!zone_file_bytes.is_empty())
        .then(|| Zonefile::load(&mut zone_file_bytes).unwrap())
    {
        zone_files.push(zone_file);
    }

    parsed_config.zone = ServerZone {
        zone_name,
        zone_files,
    };

    parsed_config
}

//------------ NoOpNotifyTarget -----------------------------------------------

#[derive(Copy, Clone, Default, Debug)]
struct TestNotifyTarget;

impl Notifiable for TestNotifyTarget {
    fn notify_zone_changed(
        &self,
        class: Class,
        apex_name: &StoredName,
        source: IpAddr,
    ) -> Pin<
        Box<dyn Future<Output = Result<(), NotifyError>> + Sync + Send + '_>,
    > {
        trace!("Notify received from {source} of change to zone {apex_name} in class {class}");

        let res = match apex_name.to_string().to_lowercase().as_str() {
            "example.com" => Ok(()),
            "othererror.com" => Err(NotifyError::Other),
            _ => Err(NotifyError::NotAuthForZone),
        };

        Box::pin(ready(res))
    }
}

//------------ TestKeyStore ---------------------------------------------------

// KeyStore is impl'd elsewhere for HashMap<(KeyName, Algorithm), K, S>.
type TestKeyStore = HashMap<(KeyName, Algorithm), Arc<Key>>;

impl KeyStore for Arc<TestKeyStore> {
    type Key = Arc<Key>;

    fn get_key<N: ToName>(
        &self,
        name: &N,
        algorithm: Algorithm,
    ) -> Option<Self::Key> {
        Arc::deref(self).get_key(name, algorithm)
    }
}
