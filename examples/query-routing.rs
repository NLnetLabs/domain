use core::future::ready;

use core::fmt;
use core::fmt::Debug;
use core::future::{Future, Ready};
use core::ops::ControlFlow;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::RwLock;

use octseq::{FreezeBuilder, Octets};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::time::Instant;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;
use tokio_tfo::{TfoListener, TfoStream};
//use tracing_subscriber::EnvFilter;

use domain::base::iana::{Class, Rcode};
use domain::base::message_builder::{AdditionalBuilder, PushError};
use domain::base::name::ToLabelIter;
use domain::base::wire::Composer;
use domain::base::{MessageBuilder, Name, StreamTarget};
use domain::net::client::dgram as client_dgram;
use domain::net::client::protocol::UdpConnect;
use domain::net::server::adapter::ClientTransportToSrService;
use domain::net::server::adapter::SrServiceToService;
use domain::net::server::buf::VecBufSource;
use domain::net::server::dgram;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::middleware::builder::MiddlewareBuilder;
use domain::net::server::middleware::processor::MiddlewareProcessor;
#[cfg(feature = "siphasher")]
use domain::net::server::middleware::processors::cookies::CookiesMiddlewareProcessor;
use domain::net::server::middleware::processors::mandatory::MandatoryMiddlewareProcessor;
use domain::net::server::query_router::QueryRouter;
use domain::net::server::service::{
    CallResult, ServiceError, ServiceFeedback, Transaction,
};
use domain::net::server::sock::AsyncAccept;
use domain::net::server::sr_service::ReplyMessage;
use domain::net::server::stream;
use domain::net::server::stream::StreamServer;
use domain::net::server::util::{mk_builder_for_target, service_fn};
use domain::net::server::ConnectionConfig;
use domain::rdata::A;

//----------- mk_answer() ----------------------------------------------------

// Helper fn to create a dummy response to send back to the client
fn mk_answer<Target>(
    msg: &Request<Vec<u8>>,
    builder: MessageBuilder<StreamTarget<Target>>,
) -> Result<AdditionalBuilder<StreamTarget<Target>>, PushError>
where
    Target: Octets + Composer + FreezeBuilder<Octets = Target>,
    <Target as octseq::OctetsBuilder>::AppendError: fmt::Debug,
{
    let mut answer =
        builder.start_answer(msg.message(), Rcode::NOERROR).unwrap();
    answer.push((
        Name::root_ref(),
        Class::IN,
        86400,
        A::from_octets(192, 0, 2, 1),
    ))?;
    Ok(answer.additional())
}

//----------- Example Service trait implementations --------------------------

//--- name_to_ip()

/// This function shows how to implement [`Service`] logic by matching the
/// function signature required by the [`Service`] trait.
///
/// The function signature is slightly more complex than when using
/// [`service_fn`] (see the [`query`] example below).
#[allow(clippy::type_complexity)]
fn name_to_ip<Target>(
    request: Request<Vec<u8>>,
) -> Result<
    Transaction<
        Target,
        impl Future<Output = Result<CallResult<Target>, ServiceError>> + Send,
    >,
    ServiceError,
>
where
    Target:
        Composer + Octets + FreezeBuilder<Octets = Target> + Default + Send,
    <Target as octseq::OctetsBuilder>::AppendError: Debug,
{
    let mut out_answer = None;
    if let Ok(question) = request.message().sole_question() {
        let qname = question.qname();
        let num_labels = qname.label_count();
        if num_labels >= 5 {
            let mut iter = qname.iter_labels();
            let a = iter.nth(num_labels - 5).unwrap();
            let b = iter.next().unwrap();
            let c = iter.next().unwrap();
            let d = iter.next().unwrap();
            let a_rec: Result<A, _> = format!("{a}.{b}.{c}.{d}").parse();
            if let Ok(a_rec) = a_rec {
                let builder = mk_builder_for_target();
                let mut answer = builder
                    .start_answer(request.message(), Rcode::NOERROR)
                    .unwrap();
                answer
                    .push((Name::root_ref(), Class::IN, 86400, a_rec))
                    .unwrap();
                out_answer = Some(answer);
            }
        }
    }

    if out_answer.is_none() {
        let builder = mk_builder_for_target();
        eprintln!("Refusing request, only requests for A records in IPv4 dotted quad format are accepted by this service.");
        out_answer = Some(
            builder
                .start_answer(request.message(), Rcode::REFUSED)
                .unwrap(),
        );
    }

    let additional = out_answer.unwrap().additional();
    let item = Ok(CallResult::new(additional));
    Ok(Transaction::single(ready(item)))
}

//--- query()

/// This function shows how to implement [`Service`] logic by matching the
/// function signature required by [`service_fn`].
///
/// The function signature is slightly simpler to write than when not using
/// [`service_fn`] and supports passing in meta data without any extra
/// boilerplate.
#[allow(clippy::type_complexity)]
fn query(
    request: Request<Vec<u8>>,
    count: Arc<AtomicU8>,
) -> Result<
    Transaction<
        Vec<u8>,
        impl Future<Output = Result<CallResult<Vec<u8>>, ServiceError>> + Send,
    >,
    ServiceError,
> {
    let cnt = count
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
            Some(if x > 0 { x - 1 } else { 0 })
        })
        .unwrap();

    // This fn blocks the server until it returns. By returning a future that
    // handles the request we allow the server to execute the future in the
    // background without blocking the server.
    let fut = async move {
        eprintln!("Sleeping for 100ms");
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Note: A real service would have application logic here to process
        // the request and generate an response.

        let idle_timeout = Duration::from_millis((50 * cnt).into());
        let cmd = ServiceFeedback::Reconfigure {
            idle_timeout: Some(idle_timeout),
        };
        eprintln!("Setting idle timeout to {idle_timeout:?}");

        let builder = mk_builder_for_target();
        let answer = mk_answer(&request, builder)?;
        let res = CallResult::new(answer).with_feedback(cmd);
        Ok(res)
    };
    Ok(Transaction::single(fut))
}

//----------- Example socket trait implementations ---------------------------

//--- DoubleListener

struct DoubleListener {
    a: TcpListener,
    b: TcpListener,
    alt: AtomicBool,
}

impl DoubleListener {
    fn new(a: TcpListener, b: TcpListener) -> Self {
        let alt = AtomicBool::new(false);
        Self { a, b, alt }
    }
}

/// Combine two streams into one by interleaving the output of both as it is
/// produced.
impl AsyncAccept for DoubleListener {
    type Error = io::Error;
    type StreamType = TcpStream;
    type Future = Ready<Result<Self::StreamType, io::Error>>;

    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Future, SocketAddr), io::Error>> {
        let (x, y) = match self.alt.fetch_xor(true, Ordering::SeqCst) {
            false => (&self.a, &self.b),
            true => (&self.b, &self.a),
        };

        match TcpListener::poll_accept(x, cx)
            .map(|res| res.map(|(stream, addr)| (ready(Ok(stream)), addr)))
        {
            Poll::Ready(res) => Poll::Ready(res),
            Poll::Pending => TcpListener::poll_accept(y, cx).map(|res| {
                res.map(|(stream, addr)| (ready(Ok(stream)), addr))
            }),
        }
    }
}

//--- LocalTfoListener

struct LocalTfoListener(TfoListener);

impl std::ops::DerefMut for LocalTfoListener {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::ops::Deref for LocalTfoListener {
    type Target = TfoListener;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsyncAccept for LocalTfoListener {
    type Error = io::Error;
    type StreamType = TfoStream;
    type Future = Ready<Result<Self::StreamType, io::Error>>;

    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Future, SocketAddr), io::Error>> {
        TfoListener::poll_accept(self, cx)
            .map(|res| res.map(|(stream, addr)| (ready(Ok(stream)), addr)))
    }
}

//--- BufferedTcpListener

struct BufferedTcpListener(TcpListener);

impl std::ops::DerefMut for BufferedTcpListener {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::ops::Deref for BufferedTcpListener {
    type Target = TcpListener;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsyncAccept for BufferedTcpListener {
    type Error = io::Error;
    type StreamType = tokio::io::BufReader<TcpStream>;
    type Future = Ready<Result<Self::StreamType, io::Error>>;

    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Future, SocketAddr), io::Error>> {
        match TcpListener::poll_accept(self, cx) {
            Poll::Ready(Ok((stream, addr))) => {
                let stream = tokio::io::BufReader::new(stream);
                Poll::Ready(Ok((ready(Ok(stream)), addr)))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

//--- RustlsTcpListener

pub struct RustlsTcpListener {
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl RustlsTcpListener {
    pub fn new(
        listener: TcpListener,
        acceptor: tokio_rustls::TlsAcceptor,
    ) -> Self {
        Self { listener, acceptor }
    }
}

impl AsyncAccept for RustlsTcpListener {
    type Error = io::Error;
    type StreamType = tokio_rustls::server::TlsStream<TcpStream>;
    type Future = tokio_rustls::Accept<TcpStream>;

    #[allow(clippy::type_complexity)]
    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Future, SocketAddr), io::Error>> {
        TcpListener::poll_accept(&self.listener, cx).map(|res| {
            res.map(|(stream, addr)| (self.acceptor.accept(stream), addr))
        })
    }
}

//----------- CustomMiddleware -----------------------------------------------

#[derive(Default)]
struct Stats {
    slowest_req: Duration,
    fastest_req: Duration,
    num_req_bytes: u32,
    num_resp_bytes: u32,
    num_reqs: u32,
    num_ipv4: u32,
    num_ipv6: u32,
    num_udp: u32,
}

#[derive(Default)]
pub struct StatsMiddlewareProcessor {
    stats: RwLock<Stats>,
}

impl StatsMiddlewareProcessor {
    /// Creates an instance of this processor.
    #[must_use]
    pub fn new() -> Self {
        Default::default()
    }
}

impl std::fmt::Display for StatsMiddlewareProcessor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let stats = self.stats.read().unwrap();
        write!(f, "# Reqs={} [UDP={}, IPv4={}, IPv6={}] Bytes [rx={}, tx={}] Speed [fastest={}μs, slowest={}μs]",
            stats.num_reqs,
            stats.num_udp,
            stats.num_ipv4,
            stats.num_ipv6,
            stats.num_req_bytes,
            stats.num_resp_bytes,
            stats.fastest_req.as_micros(),
            stats.slowest_req.as_micros())?;
        Ok(())
    }
}

impl<RequestOctets, Target> MiddlewareProcessor<RequestOctets, Target>
    for StatsMiddlewareProcessor
where
    RequestOctets: AsRef<[u8]> + Octets,
    Target: Composer + Default,
{
    fn preprocess(
        &self,
        _request: &Request<RequestOctets>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>> {
        ControlFlow::Continue(())
    }

    fn postprocess(
        &self,
        request: &Request<RequestOctets>,
        _response: &mut AdditionalBuilder<StreamTarget<Target>>,
    ) {
        let duration = Instant::now().duration_since(request.received_at());
        let mut stats = self.stats.write().unwrap();

        stats.num_reqs += 1;
        stats.num_req_bytes += request.message().as_slice().len() as u32;
        stats.num_resp_bytes += _response.as_slice().len() as u32;

        if request.transport_ctx().is_udp() {
            stats.num_udp += 1;
        }

        if request.client_addr().is_ipv4() {
            stats.num_ipv4 += 1;
        } else {
            stats.num_ipv6 += 1;
        }

        if duration < stats.fastest_req {
            stats.fastest_req = duration;
        }
        if duration > stats.slowest_req {
            stats.slowest_req = duration;
        }
    }
}

//----------- main() ---------------------------------------------------------

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    eprintln!("Test with commands such as:");
    eprintln!("  dig +short -4 @127.0.0.1 -p 8053 A 1.2.3.4");
    eprintln!("  dig +short -4 @127.0.0.1 +tcp -p 8053 A google.com");
    eprintln!("  dig +short -4 @127.0.0.1 -p 8054 A google.com");
    eprintln!("  dig +short -4 @127.0.0.1 +tcp -p 8080 A google.com");
    eprintln!("  dig +short -6 @::1 +tcp -p 8080 A google.com");
    eprintln!("  dig +short -4 @127.0.0.1 +tcp -p 8081 A google.com");
    eprintln!("  dig +short -4 @127.0.0.1 +tls -p 8443 A google.com");
    eprintln!(
        "  dnsi query --format table --server 127.0.0.1 -p 8053 1.2.3.4 A"
    );
    eprintln!("  dnsi query --format table --server 127.0.0.1 -p 8053 --tcp google.com A"); // Fails, dig version works but slow.
    eprintln!(
        "  dnsi query --format table --server 127.0.0.1 -p 8054 google.com A"
    );
    eprintln!("  dnsi query --format table --server 127.0.0.1 -p 8080 --tcp google.com A");
    eprintln!(
        "  dnsi query --format table --server ::1 -p 8080 --tcp google.com A"
    );
    eprintln!("  dnsi query --format table --server 127.0.0.1 -p 8081 --tcp google.com A");
    eprintln!("  dnsi query --format table --server 127.0.0.1 -p 8443 --tls google.com A");

    /*
    // -----------------------------------------------------------------------
    // Setup logging. You can override the log level by setting environment
    // variable RUST_LOG, e.g. RUST_LOG=trace.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_thread_ids(true)
        .without_time()
        .try_init()
        .ok();
    */

    // Start building the query router plus upstreams.
    let mut qr: QueryRouter<Vec<u8>, Vec<u8>, ReplyMessage> =
        QueryRouter::new();

    // Queries to the root go to 1.1.1.1
    let server_addr =
        SocketAddr::new(IpAddr::from_str("1.1.1.1").unwrap(), 53);
    let udp_connect = UdpConnect::new(server_addr);
    let dgram_conn = client_dgram::Connection::new(udp_connect);
    let conn_service = ClientTransportToSrService::new(dgram_conn);
    qr.add(Name::<Vec<u8>>::from_str(".").unwrap(), conn_service);

    // Queries to .com go to 8.8.8.8
    let server_addr =
        SocketAddr::new(IpAddr::from_str("8.8.8.8").unwrap(), 53);
    let udp_connect = UdpConnect::new(server_addr);
    let dgram_conn = client_dgram::Connection::new(udp_connect);
    let conn_service = ClientTransportToSrService::new(dgram_conn);
    qr.add(Name::<Vec<u8>>::from_str("com").unwrap(), conn_service);

    // Queries to .nl go to 9.9.9.9
    let server_addr =
        SocketAddr::new(IpAddr::from_str("9.9.9.9").unwrap(), 53);
    let udp_connect = UdpConnect::new(server_addr);
    let dgram_conn = client_dgram::Connection::new(udp_connect);
    let conn_service = ClientTransportToSrService::new(dgram_conn);
    qr.add(Name::<Vec<u8>>::from_str("nl").unwrap(), conn_service);

    let srv = SrServiceToService::new(qr);

    // -----------------------------------------------------------------------
    // Wrap `MyService` in an `Arc` so that it can be used by multiple servers
    // at once.
    let svc = Arc::new(srv);

    // -----------------------------------------------------------------------
    // Prepare a modern middleware chain for use by servers defined below.
    // Inject a custom statistics middleware processor (defined above) at the
    // start of the chain so that it can time the request processing time from
    // as early till as late as possible (excluding time spent in the servers
    // that receive the requests and send the responses).
    let mut middleware = MiddlewareBuilder::default();
    let stats = Arc::new(StatsMiddlewareProcessor::new());
    middleware.push_front(stats.clone());
    let middleware = middleware.build();

    // -----------------------------------------------------------------------
    // Run a DNS server on UDP port 8053 on 127.0.0.1. Test it like so:
    //    dig +short -4 @127.0.0.1 -p 8053 A google.com
    let udpsocket = UdpSocket::bind("127.0.0.1:8053").await.unwrap();
    let buf = Arc::new(VecBufSource);
    let mut config = dgram::Config::default();
    config.set_middleware_chain(middleware.clone());
    let srv =
        DgramServer::with_config(udpsocket, buf.clone(), name_to_ip, config);

    let udp_join_handle = tokio::spawn(async move { srv.run().await });

    // -----------------------------------------------------------------------
    // Run a DNS server on TCP port 8053 on 127.0.0.1. Test it like so:
    //    dig +short +keepopen +tcp -4 @127.0.0.1 -p 8053 A google.com
    let v4socket = TcpSocket::new_v4().unwrap();
    v4socket.set_reuseaddr(true).unwrap();
    v4socket.bind("127.0.0.1:8053".parse().unwrap()).unwrap();
    let v4listener = v4socket.listen(1024).unwrap();
    let buf = Arc::new(VecBufSource);
    let mut conn_config = ConnectionConfig::default();
    conn_config.set_middleware_chain(middleware.clone());
    let mut config = stream::Config::default();
    config.set_connection_config(conn_config);
    let srv = StreamServer::with_config(
        v4listener,
        buf.clone(),
        svc.clone(),
        config,
    );
    let srv = srv.with_pre_connect_hook(|stream| {
        // Demonstrate one way without having access to the code that creates
        // the socket initially to enable TCP keep alive,
        eprintln!("TCP connection detected: enabling socket TCP keepalive.");

        let keep_alive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(20))
            .with_interval(Duration::from_secs(20));
        let socket = socket2::SockRef::from(&stream);
        socket.set_tcp_keepalive(&keep_alive).unwrap();

        // Sleep to give us time to run a command like
        // `ss -nte` to see the keep-alive is set. It
        // shows up in the ss output like this:
        //   timer:(keepalive,18sec,0)
        eprintln!("Waiting for 5 seconds so you can run a command like:");
        eprintln!("  ss -nte | grep 8053 | grep keepalive");
        eprintln!("and see `timer:(keepalive,20sec,0) or similar.");
        std::thread::sleep(Duration::from_secs(5));
    });

    let tcp_join_handle = tokio::spawn(async move { srv.run().await });

    #[cfg(target_os = "linux")]
    let udp_mtu_join_handle = {
        // This UDP example sets IP_MTU_DISCOVER via setsockopt(), using the
        // libc crate (as the nix crate doesn't support IP_MTU_DISCOVER at the
        // time of writing). This example is inspired by:
        //
        // - https://www.ietf.org/archive/id/draft-ietf-dnsop-avoid-fragmentation-17.html#name-recommendations-for-udp-res
        // - https://mailarchive.ietf.org/arch/msg/dnsop/Zy3wbhHephubsy2uJesGeDst4F4/
        // - https://man7.org/linux/man-pages/man7/ip.7.html
        //
        // Some other good reading on sending faster via UDP with Rust:
        // - https://devork.be/blog/2023/11/modern-linux-sockets/
        //
        // We could also try the following settings that the Unbound man page
        // mentions:
        //  - SO_RCVBUF      - Unbound advises setting so-rcvbuf to 4m on busy
        //                     servers to prevent short request spikes causing
        //                     packet drops,
        //  - SO_SNDBUF      - Unbound advises setting so-sndbuf to 4m on busy
        //                     servers to avoid resource temporarily
        //                     unavailable errors,
        //  - SO_REUSEPORT   - Unbound advises to turn it off at extreme load
        //                     to distribute queries evenly,
        //  - IP_TRANSPARENT - Allows to bind to non-existent IP addresses
        //                     that are going to exist later on. Unbound uses
        //                     IP_BINDANY on FreeBSD and SO_BINDANY on
        //                     OpenBSD.
        //  - IP_FREEBIND    - Linux only, similar to IP_TRANSPARENT. Allows
        //                     to bind to IP addresses that are nonlocal or do
        //                     not exist, like when the network interface is
        //                     down.
        //  - TCP_MAXSEG     - Value lower than common MSS on Ethernet (1220
        //                     for example) will address path MTU problem.
        //  - A means to control the value of the Differentiated Services
        //    Codepoint (DSCP) in the differentiated services field (DS) of
        //    the  outgoing IP packet headers.
        fn setsockopt(socket: libc::c_int, flag: libc::c_int) -> libc::c_int {
            unsafe {
                libc::setsockopt(
                    socket,
                    libc::IPPROTO_UDP,
                    libc::IP_MTU_DISCOVER,
                    &flag as *const libc::c_int as *const libc::c_void,
                    std::mem::size_of_val(&flag) as libc::socklen_t,
                )
            }
        }

        let udpsocket = UdpSocket::bind("127.0.0.1:8054").await.unwrap();
        let fd = <UdpSocket as std::os::fd::AsRawFd>::as_raw_fd(&udpsocket);
        if setsockopt(fd, libc::IP_PMTUDISC_OMIT) == -1 {
            eprintln!(
                "setsockopt error when setting IP_MTU_DISCOVER to IP_PMTUDISC_OMIT, will retry with IP_PMTUDISC_DONT: {}",
                std::io::Error::last_os_error()
            );

            if setsockopt(fd, libc::IP_PMTUDISC_DONT) == -1 {
                eprintln!(
                    "setsockopt error when setting IP_MTU_DISCOVER to IP_PMTUDISC_DONT: {}",
                    std::io::Error::last_os_error()
                );
            }
        }

        let mut config = dgram::Config::default();
        config.set_middleware_chain(middleware.clone());
        let srv = DgramServer::with_config(
            udpsocket,
            buf.clone(),
            svc.clone(),
            config,
        );

        tokio::spawn(async move { srv.run().await })
    };

    // -----------------------------------------------------------------------
    // Demonstrate manually binding to two separate IPv4 and IPv6 sockets and
    // then listening on both at once using a single server instance. (e.g.
    // for on platforms that don't support binding to IPv4 and IPv6 at once
    // using a single socket).
    let v4socket = TcpSocket::new_v4().unwrap();
    v4socket.set_reuseaddr(true).unwrap();
    v4socket.bind("127.0.0.1:8080".parse().unwrap()).unwrap();
    let v4listener = v4socket.listen(1024).unwrap();

    let v6socket = TcpSocket::new_v6().unwrap();
    v6socket.set_reuseaddr(true).unwrap();
    v6socket.bind("[::1]:8080".parse().unwrap()).unwrap();
    let v6listener = v6socket.listen(1024).unwrap();

    let listener = DoubleListener::new(v4listener, v6listener);
    let mut conn_config = ConnectionConfig::new();
    conn_config.set_middleware_chain(middleware.clone());
    let mut config = stream::Config::new();
    config.set_connection_config(conn_config);
    let srv =
        StreamServer::with_config(listener, buf.clone(), svc.clone(), config);
    let double_tcp_join_handle = tokio::spawn(async move { srv.run().await });

    // -----------------------------------------------------------------------
    // Demonstrate listening with TCP Fast Open enabled (via the tokio-tfo crate).
    // On Linux strace can be used to show that the socket options are indeed
    // set as expected, e.g.:
    //
    //  > strace -e trace=setsockopt cargo run --example serve \
    //      --features serve,tokio-tfo --release
    //     Finished release [optimized] target(s) in 0.12s
    //      Running `target/release/examples/serve`
    //   setsockopt(6, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
    //   setsockopt(7, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
    //   setsockopt(8, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
    //   setsockopt(8, SOL_TCP, TCP_FASTOPEN, [1024], 4) = 0

    let listener = TfoListener::bind("127.0.0.1:8081".parse().unwrap())
        .await
        .unwrap();
    let listener = LocalTfoListener(listener);
    let mut conn_config = ConnectionConfig::new();
    conn_config.set_middleware_chain(middleware.clone());
    let mut config = stream::Config::new();
    config.set_connection_config(conn_config);
    let srv =
        StreamServer::with_config(listener, buf.clone(), svc.clone(), config);
    let tfo_join_handle = tokio::spawn(async move { srv.run().await });

    // -----------------------------------------------------------------------
    // Demonstrate using a simple function instead of a struct as the service
    // Note that this service reduces its connection timeout on each subsequent
    // query handled on the same connection, so try someting like this and you
    // should see later queries getting communication errors:
    //
    //   > dig +short +keepopen +tcp -4 @127.0.0.1 -p 8082 A google.com A \
    //     google.com A google.com A google.com A google.com A google.com \
    //     A google.com
    //   ..
    //   192.0.2.1
    //   192.0.2.1
    //    ..
    //   ;; communications error to 127.0.0.1#8082: end of file
    //
    // This example also demonstrates wrapping the TcpStream inside a
    // BufReader to minimize overhead from system I/O calls.

    let listener = TcpListener::bind("127.0.0.1:8082").await.unwrap();
    let listener = BufferedTcpListener(listener);
    let count = Arc::new(AtomicU8::new(5));

    // Make our service from the `query` function with the help of the
    // `service_fn` function.
    let fn_svc = service_fn(query, count);

    // Show that we don't have to use the same middleware with every server by
    // creating a separate middleware chain for use just by this server, and
    // also show that by creating the individual middleware processors
    // ourselves we can override their default configuration.
    let mut fn_svc_middleware = MiddlewareBuilder::new();
    fn_svc_middleware.push(MandatoryMiddlewareProcessor::new().into());

    #[cfg(feature = "siphasher")]
    {
        let server_secret = "server12secret34".as_bytes().try_into().unwrap();
        fn_svc_middleware
            .push(CookiesMiddlewareProcessor::new(server_secret).into());
    }

    let fn_svc_middleware = fn_svc_middleware.build();

    let mut conn_config = ConnectionConfig::new();
    conn_config.set_middleware_chain(fn_svc_middleware);
    let mut config = stream::Config::new();
    config.set_connection_config(conn_config);
    let srv =
        StreamServer::with_config(listener, buf.clone(), fn_svc, config);
    let fn_join_handle = tokio::spawn(async move { srv.run().await });

    // -----------------------------------------------------------------------
    // Demonstrate using a TLS secured TCP DNS server.

    // Credit: The sample.(pem|rsa) files used here were taken from
    // https://github.com/rustls/hyper-rustls/blob/main/examples/
    let certs = rustls_pemfile::certs(&mut BufReader::new(
        File::open("examples/sample.pem").unwrap(),
    ))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();
    let key = rustls_pemfile::private_key(&mut BufReader::new(
        File::open("examples/sample.rsa").unwrap(),
    ))
    .unwrap()
    .unwrap();

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:8443").await.unwrap();
    let listener = RustlsTcpListener::new(listener, acceptor);

    let mut conn_config = ConnectionConfig::new();
    conn_config.set_middleware_chain(middleware.clone());
    let mut config = stream::Config::new();
    config.set_connection_config(conn_config);
    let srv =
        StreamServer::with_config(listener, buf.clone(), svc.clone(), config);

    let tls_join_handle = tokio::spawn(async move { srv.run().await });

    // -----------------------------------------------------------------------
    // Print statistics periodically
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;
            println!("Statistics report: {stats}");
        }
    });

    // -----------------------------------------------------------------------
    // Keep the services running in the background

    udp_join_handle.await.unwrap();
    tcp_join_handle.await.unwrap();
    #[cfg(target_os = "linux")]
    udp_mtu_join_handle.await.unwrap();
    double_tcp_join_handle.await.unwrap();
    tfo_join_handle.await.unwrap();
    fn_join_handle.await.unwrap();
    tls_join_handle.await.unwrap();
}
