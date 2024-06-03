#![cfg(feature = "net")]

use std::collections::VecDeque;
use std::fs::File;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use octseq::Octets;
use rstest::rstest;
use tracing::instrument;
use tracing::{trace, warn};

use domain::base::iana::Rcode;
use domain::base::name::{Name, ToName};
use domain::base::wire::Composer;
use domain::net::client::{dgram, stream};
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::middleware::builder::MiddlewareBuilder;
#[cfg(feature = "siphasher")]
use domain::net::server::middleware::processors::cookies::CookiesMiddlewareProcessor;
use domain::net::server::middleware::processors::edns::EdnsMiddlewareProcessor;
use domain::net::server::service::{
    CallResult, Service, ServiceError, Transaction,
};
use domain::net::server::stream::StreamServer;
use domain::net::server::util::{mk_builder_for_target, service_fn};
use domain::utils::base16;
use domain::zonefile::inplace::{Entry, ScannedRecord, Zonefile};

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

    let file = File::open(&rpl_file).unwrap();
    let stelline = parse_file(&file, rpl_file.to_str().unwrap());
    let server_config = parse_server_config(&stelline.config);

    // Create a service to answer queries received by the DNS servers.
    let zonefile = server_config.zonefile.clone();
    let service: Arc<_> = service_fn(test_service, zonefile).into();

    // Create dgram and stream servers for answering requests
    let (dgram_srv, dgram_conn, stream_srv, stream_conn) =
        mk_servers(service, &server_config);

    // Create a client factory for sending requests
    let client_factory = mk_client_factory(dgram_conn, stream_conn);

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

fn mk_server_configs<RequestOctets, Target>(
    config: &ServerConfig,
) -> (
    domain::net::server::dgram::Config<RequestOctets, Target>,
    domain::net::server::stream::Config<RequestOctets, Target>,
)
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    let mut middleware = MiddlewareBuilder::minimal();

    if config.cookies.enabled {
        #[cfg(feature = "siphasher")]
        if let Some(secret) = config.cookies.secret {
            let secret = base16::decode_vec(secret).unwrap();
            let secret = <[u8; 16]>::try_from(secret).unwrap();
            let processor = CookiesMiddlewareProcessor::new(secret);
            let processor = processor
                .with_denied_ips(config.cookies.ip_deny_list.clone());
            middleware.push(processor.into());
        }

        #[cfg(not(feature = "siphasher"))]
        panic!("The test uses cookies but the required 'siphasher' feature is not enabled.");
    }

    if config.edns_tcp_keepalive {
        let processor = EdnsMiddlewareProcessor::new();
        middleware.push(processor.into());
    }

    let middleware = middleware.build();

    let mut dgram_config = domain::net::server::dgram::Config::default();
    dgram_config.set_middleware_chain(middleware.clone());

    let mut stream_config = domain::net::server::stream::Config::default();
    if let Some(idle_timeout) = config.idle_timeout {
        let mut connection_config =
            domain::net::server::ConnectionConfig::default();
        connection_config.set_idle_timeout(idle_timeout);
        connection_config.set_middleware_chain(middleware);
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
    zonefile: Zonefile,
) -> Result<
    Transaction<
        Vec<u8>,
        impl Future<Output = Result<CallResult<Vec<u8>>, ServiceError>> + Send,
    >,
    ServiceError,
> {
    fn as_record_and_dname(
        r: ScannedRecord,
    ) -> Option<(ScannedRecord, Name<Vec<u8>>)> {
        let dname = r.owner().to_name();
        Some((r, dname))
    }

    fn as_records(
        e: Result<Entry, domain::zonefile::inplace::Error>,
    ) -> Option<ScannedRecord> {
        match e {
            Ok(Entry::Record(r)) => Some(r),
            Ok(_) => None,
            Err(err) => panic!(
                "Error while extracting records from the zonefile: {err}"
            ),
        }
    }

    trace!("Service received request");
    Ok(Transaction::single(async move {
        trace!("Service is constructing a single response");
        // If given a single question:
        let answer = request
            .message()
            .sole_question()
            .ok()
            .and_then(|q| {
                // Walk the zone to find the queried name
                zonefile
                    .clone()
                    .filter_map(as_records)
                    .filter_map(as_record_and_dname)
                    .find(|(_record, dname)| dname == q.qname())
            })
            .map_or_else(
                || {
                    // The Qname was not found in the zone:
                    mk_builder_for_target()
                        .start_answer(request.message(), Rcode::NXDOMAIN)
                        .unwrap()
                },
                |(record, _)| {
                    // Respond with the found record:
                    let mut answer = mk_builder_for_target()
                        .start_answer(request.message(), Rcode::NOERROR)
                        .unwrap();
                    // As we serve all answers from our own zones we are the
                    // authority for the domain in question.
                    answer.header_mut().set_aa(true);
                    answer.push(record).unwrap();
                    answer
                },
            );

        Ok(CallResult::new(answer.additional()))
    }))
}

//----------- Stelline config block parsing -----------------------------------

#[derive(Default)]
struct ServerConfig<'a> {
    cookies: CookieConfig<'a>,
    edns_tcp_keepalive: bool,
    idle_timeout: Option<Duration>,
    zonefile: Zonefile,
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
                    _ => {
                        eprintln!("Ignoring unknown server setting '{setting}' with value: {value}");
                    }
                }
            }
        }
    }

    if !zone_file_bytes.is_empty() {
        parsed_config.zonefile =
            Zonefile::load(&mut zone_file_bytes).unwrap();
    }

    parsed_config
}
