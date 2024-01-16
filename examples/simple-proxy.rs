//! Simple DNS proxy

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use clap::Parser;
use domain::base::iana::Rtype;
use domain::base::message_builder::PushError;
use domain::base::opt::{Opt, OptRecord};
use domain::base::{
    Message, MessageBuilder, ParsedDname, StaticCompressor, StreamTarget,
};
use domain::dep::octseq::Octets;
use domain::net::client::dgram;
use domain::net::client::dgram_stream;
use domain::net::client::multi_stream;
use domain::net::client::protocol::TlsConnect;
use domain::net::client::protocol::{TcpConnect, UdpConnect};
use domain::net::client::redundant;
use domain::net::client::request::SendRequest;
use domain::net::client::request::{ComposeRequest, RequestMessage};
use domain::rdata::AllRecordData;
use domain::net::server::buf::BufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::service::{
    CallResult, Service, ServiceError, Transaction,
};
use futures_util::stream::Stream;
use futures_util::{future::BoxFuture, FutureExt};
use rustls::ClientConfig;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::Debug;
use std::fs::File;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// Arguments parser.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Option for the local port.
    #[arg(long = "locport", value_parser = clap::value_parser!(u16))]
    locport: Option<u16>,

    /// Configuration
    config: String,
}

/// Top level configuration structure.
#[derive(Debug, Deserialize, Serialize)]
struct Config {
    /// Config for upstream connections
    upstream: TransportConfig,
}

/// Configure for client transports
#[derive(Debug, Deserialize, Serialize)]
enum TransportConfig {
    /// Redudant upstreams
    #[serde(rename = "redundant")]
    Redundant(RedundantConfig),

    /// TCP upstream
    #[serde(rename = "TCP")]
    Tcp(TcpConfig),

    /// TLS upstream
    #[serde(rename = "TLS")]
    Tls(TlsConfig),

    /// UDP upstream that does not switch to TCP when the reply is truncated
    #[serde(rename = "UDP-only")]
    Udp(UdpConfig),

    /// UDP upstream that switchs to TCP when the reply is truncated
    #[serde(rename = "UDP")]
    UdpTcp(UdpTcpConfig),
}

/// Config for a redundant transport
#[derive(Debug, Deserialize, Serialize)]
struct RedundantConfig {
    /// List of transports to be used by a redundant transport
    transports: Vec<TransportConfig>,
}

/// Config for a TCP transport
#[derive(Debug, Deserialize, Serialize)]
struct TcpConfig {
    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Config for a TLS transport
#[derive(Debug, Deserialize, Serialize)]
struct TlsConfig {
    /// Name of the remote resolver
    servername: String,

    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Config for a UDP-only transport
#[derive(Debug, Deserialize, Serialize)]
struct UdpConfig {
    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Config for a UDP+TCP transport
#[derive(Debug, Deserialize, Serialize)]
struct UdpTcpConfig {
    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Convert a Message into a MessageBuilder.
fn to_builder<Octs1: Octets>(
    source: &Message<Octs1>,
) -> Result<MessageBuilder<StaticCompressor<StreamTarget<Vec<u8>>>>, PushError>
{
    let mut target = MessageBuilder::from_target(StaticCompressor::new(
        StreamTarget::new_vec(),
    ))
    .unwrap();

    let header = source.header();
    *target.header_mut() = header;

    let source = source.question();
    let mut target = target.additional().builder().question();
    for rr in source {
        let rr = rr.unwrap();
        target.push(rr)?;
    }
    let mut source = source.answer().unwrap();
    let mut target = target.answer();
    for rr in &mut source {
        let rr = rr.unwrap();
        let rr = rr
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .unwrap();
        target.push(rr)?;
    }

    let mut source = source.next_section().unwrap().unwrap();
    let mut target = target.authority();
    for rr in &mut source {
        let rr = rr.unwrap();
        let rr = rr
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .unwrap();
        target.push(rr)?;
    }

    let source = source.next_section().unwrap().unwrap();
    let mut target = target.additional();
    for rr in source {
        let rr = rr.unwrap();
        if rr.rtype() == Rtype::Opt {
            let rr = rr.into_record::<Opt<_>>().unwrap().unwrap();
            let opt_record = OptRecord::from_record(rr);
            target
                .opt(|newopt| {
                    newopt
                        .set_udp_payload_size(opt_record.udp_payload_size());
                    newopt.set_version(opt_record.version());
                    newopt.set_dnssec_ok(opt_record.dnssec_ok());

                    // Copy the transitive options that we support. Nothing
                    // at the moment.
                    /*
                                for option in opt_record.opt().iter::<AllOptData<_, _>>()
                                {
                                let option = option.unwrap();
                                if let AllOptData::TcpKeepalive(_) = option {
                                    panic!("handle keepalive");
                                } else {
                                    newopt.push(&option).unwrap();
                                }
                                }
                    */
                    Ok(())
                })
                .unwrap();
        } else {
            let rr = rr
                .into_record::<AllRecordData<_, ParsedDname<_>>>()
                .unwrap()
                .unwrap();
            target.push(rr)?;
        }
    }

    // It would be nice to use .builder() here. But that one deletes all
    // section. We have to resort to .as_builder() which gives a
    // reference and then .clone()
    Ok(target.as_builder().clone())
}

/// Convert a Message into a StreamTarget.
fn to_stream_target<Octs1: Octets>(
    source: &Message<Octs1>,
) -> Result<StreamTarget<Vec<u8>>, PushError> {
    let builder = to_builder(source).unwrap();
    Ok(builder.as_target().as_target().clone())
}

/// Function that returns a Service trait.
///
/// This is a trick to capture the Future by an async block into a type.
fn query_service<
    RequestOctets: AsRef<[u8]> + Debug + Octets + Send + Sync + 'static,
>(
    conn: impl SendRequest<RequestMessage<RequestOctets>>
        + Clone
        + Send
        + Sync
        + 'static,
) -> impl Service<RequestOctets, Message<RequestOctets>>
where
    for<'a> &'a RequestOctets: AsRef<[u8]> + Debug,
{
    /// Basic query function for Service.
    fn query<RequestOctets: AsRef<[u8]> + Debug + Octets>(
        message: Message<RequestOctets>,
        conn: impl SendRequest<RequestMessage<RequestOctets>> + Send + Sync,
    ) -> Transaction<
        impl Future<Output = Result<CallResult<Vec<u8>>, ServiceError<()>>>,
        impl Stream<Item = Result<CallResult<Vec<u8>>, ServiceError<()>>>,
    >
    where
        for<'a> &'a RequestOctets: AsRef<[u8]> + Debug,
    {
        Transaction::<_, NoStream<Vec<u8>>>::Single(async move {
            // Extract the ID. We need to set it in the reply.
            let id = message.header().id();
            // We get a Message, but the client transport needs a
            // BaseMessageBuilder. Convert.
            println!("request {:?}", message);
            let request_msg = RequestMessage::new(message);
            println!("request {:?}", request_msg);
            let mut query = conn.send_request(request_msg);
            let reply = query.get_response().await.unwrap();
            println!("got reply {:?}", reply);

            // Set the ID
            let mut reply: Message<Vec<u8>> =
                Message::from_octets(reply.as_slice().to_vec()).unwrap();
            reply.header_mut().set_id(id);

            // We get the reply as Message from the client transport but
            // we need to return a StreamTarget. Convert.
            let stream = to_stream_target::<_>(&reply).unwrap();
            Ok(CallResult::new(stream))
        })
    }

    move |message| Ok(query::<RequestOctets>(message, conn.clone()))
}

/*
/// Function that returns a Service trait.
///
/// This is a trick to capture the Future by an async block into a type.
fn udptcp_service<RequestOctets: AsRef<[u8]> + Octets + Send + Sync + 'static>(
    conn: udp_tcp::Connection<Vec<u8>>,
) -> impl Service<RequestOctets>
where
    for<'a> &'a RequestOctets: AsRef<[u8]>,
{
    /// Basic query function for Service.
    fn query<RequestOctets: AsRef<[u8]> + Octets, ReplyOcts>(
        message: Message<RequestOctets>,
        conn: udp_tcp::Connection<Vec<u8>>,
    ) -> Transaction<
        impl Future<Output = Result<CallResult<Vec<u8>>, ServiceError<()>>>,
        impl Stream<Item = Result<CallResult<Vec<u8>>, ServiceError<()>>>,
    >
    where
        for<'a> &'a RequestOctets: AsRef<[u8]>,
    {
        Transaction::<_, NoStream<Vec<u8>>>::Single(async move {
            // Extract the ID. We need to set it in the reply.
            let id = message.header().id();
            // We get a Message, but the client transport needs a
            // MessageBuilder. Convert.
            println!("request {:?}", message);
            let mut msg_builder = to_builder(&message).unwrap();
            println!("request {:?}", msg_builder);
            let mut query = conn.query(&mut msg_builder).await.unwrap();
            let reply = query.get_result().await.unwrap();
            println!("got reply {:?}", reply);

            // Set the ID
            let mut reply: Message<Vec<u8>> = OctetsFrom::octets_from(reply);
            reply.header_mut().set_id(id);

            // We get the reply as Message from the client transport but
            // we need to return a StreamTarget. Convert.
            let stream = to_stream_target::<_, Vec<u8>>(&reply).unwrap();
            Ok(CallResult::new(stream))
        })
    }

    move |message| Ok(query::<RequestOctets, Vec<u8>>(message, conn.clone()))
}
*/

/// Dummy stream
struct NoStream<Octs> {
    /// This is needed to handle the Octs type parameter.
    phantom: PhantomData<Octs>,
}

impl<Octs> Stream for NoStream<Octs> {
    type Item = Result<CallResult<Octs>, ServiceError<()>>;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        todo!()
    }
}

/// A buffer based on Vec.
struct VecBufSource;

impl BufSource for VecBufSource {
    type Output = Vec<u8>;

    fn create_buf(&self) -> Self::Output {
        vec![0; 1024]
    }

    fn create_sized(&self, size: usize) -> Self::Output {
        vec![0; size]
    }
}

/// A single optional call result based on a Vector.
struct VecSingle(Option<CallResult<Vec<u8>>>);

impl Future for VecSingle {
    type Output = Result<CallResult<Vec<u8>>, ServiceError<()>>;

    fn poll(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        Poll::Ready(Ok(self.0.take().unwrap()))
    }
}

/// Vector of octets
type VecU8 = Vec<u8>;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let conf = Config {
        upstream: TransportConfig::Redundant(RedundantConfig {
            transports: vec![TransportConfig::Udp(UdpConfig {
                addr: "::1".to_owned(),
                port: None,
            })],
        }),
    };
    let str = serde_json::to_string(&conf).unwrap();
    println!("got {}", str);

    let f = File::open(args.config).unwrap();
    let conf: Config = serde_json::from_reader(f).unwrap();

    println!("Got: {:?}", conf);

    let locport = args.locport.unwrap_or_else(|| "8053".parse().unwrap());
    let buf_source = Arc::new(VecBufSource);
    let udpsocket2 =
        UdpSocket::bind(SocketAddr::new("::1".parse().unwrap(), locport))
            .await
            .unwrap();

    // We cannot use get_transport because we cannot pass a Box<dyn ...> to
    // query_service because it lacks Clone.
    let udp_join_handle = match conf.upstream {
        TransportConfig::Redundant(redun_conf) => {
            let redun = get_redun::<RequestMessage<VecU8>>(redun_conf).await;
            start_service(redun, udpsocket2, buf_source)
        }
        TransportConfig::Tcp(tcp_conf) => {
            let tcp = get_tcp::<RequestMessage<VecU8>>(tcp_conf);
            start_service(tcp, udpsocket2, buf_source)
        }
        TransportConfig::Tls(tls_conf) => {
            let tls = get_tls::<RequestMessage<VecU8>>(tls_conf);
            start_service(tls, udpsocket2, buf_source)
        }
        TransportConfig::Udp(udp_conf) => {
            let udp = get_udp::<RequestMessage<VecU8>>(udp_conf);
            start_service(udp, udpsocket2, buf_source)
        }
        TransportConfig::UdpTcp(udptcp_conf) => {
            let udptcp = get_udptcp::<RequestMessage<VecU8>>(udptcp_conf);
            start_service(udptcp, udpsocket2, buf_source)
        }
    };

    udp_join_handle.await.unwrap().unwrap();
}

/// Get a redundant transport based on its config
async fn get_redun<
    CR: ComposeRequest + Clone + Debug + Send + Sync + 'static,
>(
    config: RedundantConfig,
) -> redundant::Connection<CR> {
    println!("Creating new redundant::Connection");
    let (redun, transport) = redundant::Connection::new();
    tokio::spawn(async move {
        transport.run().await;
    });
    println!("Adding to redundant::Connection");
    for e in config.transports {
        println!("Add to redundant::Connection");
        redun.add(get_transport(e).await).await.unwrap();
        println!("After Add to redundant::Connection");
    }
    redun
}

/// Get a TCP transport based on its config
fn get_tcp<CR: ComposeRequest + Clone + 'static>(
    config: TcpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 53);
    let tcp_connect = TcpConnect::new(sockaddr);

    let (conn, transport) = multi_stream::Connection::new(tcp_connect);
    tokio::spawn(async move {
        transport.run().await;
        println!("run terminated");
    });

    conn
}

/// Get a TLS transport based on its config
fn get_tls<CR: ComposeRequest + Clone + 'static>(
    config: TlsConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 853);

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(
        |ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        },
    ));
    let client_config = Arc::new(
        ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );

    let tls_connect = TlsConnect::new(
        client_config,
        config.servername.as_str().try_into().unwrap(),
        sockaddr,
    );
    let (conn, transport) = multi_stream::Connection::new(tls_connect);
    tokio::spawn(async move {
        transport.run().await;
        println!("run terminated");
    });

    conn
}

/// Get a UDP-only transport based on its config
fn get_udp<CR: ComposeRequest + Clone + 'static>(
    config: UdpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 53);

    let udp_connect = UdpConnect::new(sockaddr);
    dgram::Connection::new(udp_connect)
}

/// Get a UDP+TCP transport based on its config
fn get_udptcp<CR: ComposeRequest + Clone + 'static>(
    config: UdpTcpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 53);
    let udp_connect = UdpConnect::new(sockaddr);
    let tcp_connect = TcpConnect::new(sockaddr);
    let (conn, transport) =
        dgram_stream::Connection::new(udp_connect, tcp_connect);
    tokio::spawn(async move {
        transport.run().await;
        println!("run terminated");
    });
    conn
}

/// Get a transport based on its config
fn get_transport<CR: ComposeRequest + Clone + 'static>(
    config: TransportConfig,
) -> BoxFuture<'static, Box<dyn SendRequest<CR> + Send + Sync>> {
    // We have an indirectly recursive async function. This function calls
    // get_redun which calls this function. The solution is to return a
    // boxed future.
    async move {
        println!("got config {:?}", config);
        let a: Box<dyn SendRequest<CR> + Send + Sync> = match config {
            TransportConfig::Redundant(redun_conf) => {
                Box::new(get_redun(redun_conf).await)
            }
            TransportConfig::Tcp(tcp_conf) => Box::new(get_tcp(tcp_conf)),
            TransportConfig::Tls(tls_conf) => Box::new(get_tls(tls_conf)),
            TransportConfig::Udp(udp_conf) => Box::new(get_udp(udp_conf)),
            TransportConfig::UdpTcp(udptcp_conf) => {
                Box::new(get_udptcp(udptcp_conf))
            }
        };
        a
    }
    .boxed()
}

/// Start a service based on a transport, a UDP server socket and a buffer
fn start_service(
    conn: impl SendRequest<RequestMessage<VecU8>> + Clone + Send + Sync + 'static,
    socket: UdpSocket,
    buf_source: Arc<VecBufSource>,
) -> JoinHandle<Result<(), std::io::Error>> {
    let svc = query_service(conn);
    let srv = Arc::new(DgramServer::new(socket, buf_source, Arc::new(svc)));
    tokio::spawn(srv.run())
}

/// Get a socket address for an IP address, and optional port and a
/// default port.
fn get_sockaddr(
    addr: &str,
    port: Option<&str>,
    default_port: u16,
) -> SocketAddr {
    let port = match port {
        Some(str) => str.parse().unwrap(),
        None => default_port,
    };

    SocketAddr::new(IpAddr::from_str(addr).unwrap(), port)
}
