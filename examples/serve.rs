// TODO: Split into separate examples?
use std::{
    fmt::{self, Debug},
    fs::File,
    io::{self, BufReader},
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use domain::{
    base::message_builder::AdditionalBuilder,
    net::server::{
        middleware::{
            builder::MiddlewareBuilder, chain::MiddlewareChain,
            processors::cookies::CookiesMiddlewareProcesor,
        },
        service::ServiceResult,
    },
};
use domain::{
    base::{
        iana::{Class, Rcode},
        wire::Composer,
        Dname, Message, MessageBuilder, StreamTarget,
    },
    net::server::{
        buf::{BufSource, VecBufSource},
        dgram::DgramServer,
        service,
        service::{
            CallResult, Service, ServiceCommand, ServiceError,
            ServiceResultItem, Transaction,
        },
        sock::AsyncAccept,
        stream::StreamServer,
        ContextAwareMessage,
    },
    rdata::A,
};
use futures::{Future, Stream};
use octseq::{FreezeBuilder, Octets};

use rustls_pemfile::{certs, rsa_private_keys};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio_rustls::{
    rustls::{self, Certificate, PrivateKey},
    TlsAcceptor,
};
use tokio_tfo::{TfoListener, TfoStream};

// Helper fn to create a dummy response to send back to the client
fn mk_answer<Target>(
    msg: &ContextAwareMessage<Message<Target>>,
    builder: MessageBuilder<StreamTarget<Target>>,
) -> AdditionalBuilder<StreamTarget<Target>>
where
    Target: Octets + Composer + FreezeBuilder<Octets = Target>,
    <Target as octseq::OctetsBuilder>::AppendError: fmt::Debug,
{
    let mut answer = builder.start_answer(msg, Rcode::NoError).unwrap();
    answer
        .push((
            Dname::root_ref(),
            Class::In,
            86400,
            A::from_octets(192, 0, 2, 1),
        ))
        .unwrap();

    answer.additional()
}

struct UnreachableStream;

impl Stream for UnreachableStream {
    type Item = Result<CallResult<Vec<u8>>, ServiceError<()>>;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        unreachable!()
    }
}

struct MyService;

impl Service<Vec<u8>> for MyService {
    type Error = ();

    type Target = Vec<u8>;

    type Single = std::future::Ready<
        Result<CallResult<Vec<u8>>, ServiceError<Self::Error>>,
    >;

    type Stream = UnreachableStream;

    fn call(
        &self,
        msg: ContextAwareMessage<Message<Vec<u8>>>,
    ) -> Result<
        Transaction<Self::Single, Self::Stream>,
        ServiceError<Self::Error>,
    > {
        let mut middleware = MiddlewareBuilder::<Vec<u8>>::default();
        let server_secret = "server12secret34".as_bytes().try_into().unwrap();
        #[cfg(feature = "siphasher")]
        middleware.push(CookiesMiddlewareProcesor::new(server_secret));
        let middleware = middleware.finish();

        let target = StreamTarget::new_vec();

        let call_result = middleware
            .apply(msg, target, |msg, target| {
                Ok(CallResult::new(mk_answer(msg, target)))
            })
            .map(|(_request, call_result)| call_result)?;

        Ok(Transaction::Single(std::future::ready(Ok(call_result))))
    }
}

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

/// Combine two streams into one by interleaving the output of both as it is produced.
impl AsyncAccept for DoubleListener {
    type Error = io::Error;
    type StreamType = TcpStream;
    type Stream = futures::future::Ready<Result<Self::StreamType, io::Error>>;

    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, SocketAddr), io::Error>> {
        let (x, y) = match self.alt.fetch_xor(true, Ordering::SeqCst) {
            false => (&self.a, &self.b),
            true => (&self.b, &self.a),
        };

        match TcpListener::poll_accept(x, cx).map(|res| {
            res.map(|(stream, addr)| {
                (futures::future::ready(Ok(stream)), addr)
            })
        }) {
            Poll::Ready(res) => Poll::Ready(res),
            Poll::Pending => TcpListener::poll_accept(y, cx).map(|res| {
                res.map(|(stream, addr)| {
                    (futures::future::ready(Ok(stream)), addr)
                })
            }),
        }
    }
}

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
    type Stream = futures::future::Ready<Result<Self::StreamType, io::Error>>;

    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, SocketAddr), io::Error>> {
        TfoListener::poll_accept(self, cx).map(|res| {
            res.map(|(stream, addr)| {
                (futures::future::ready(Ok(stream)), addr)
            })
        })
    }
}

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
    type Stream = futures::future::Ready<Result<Self::StreamType, io::Error>>;

    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, SocketAddr), io::Error>> {
        match TcpListener::poll_accept(self, cx) {
            Poll::Ready(Ok((stream, addr))) => {
                let stream = tokio::io::BufReader::new(stream);
                Poll::Ready(Ok((futures::future::ready(Ok(stream)), addr)))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

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
    type Stream = tokio_rustls::Accept<TcpStream>;

    #[allow(clippy::type_complexity)]
    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, SocketAddr), io::Error>> {
        TcpListener::poll_accept(&self.listener, cx).map(|res| {
            res.map(|(stream, addr)| (self.acceptor.accept(stream), addr))
        })
    }
}

fn query<Target>(
    msg: ContextAwareMessage<Message<Target>>,
    middleware: MiddlewareChain<Target>,
    target: StreamTarget<Target>,
    count: Arc<AtomicU8>,
) -> ServiceResult<
    impl Future<Output = ServiceResultItem<Target, ()>>,
    UnreachableStream,
    (),
>
where
    Target: Composer + Octets + FreezeBuilder<Octets = Target>,
    <Target as octseq::OctetsBuilder>::AppendError: Debug,
{
    let cnt = count
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
            Some(if x > 0 { x - 1 } else { 0 })
        })
        .unwrap();

    // This fn blocks the server until it returns. By returning a future
    // that handles the request we allow the server to execute the future
    // in the background without blocking the server.
    Ok(Transaction::Single(async move {
        eprintln!("Sleeping for 100ms");
        tokio::time::sleep(Duration::from_millis(100)).await;

        middleware
            .apply(msg, target, |msg, target| {
                // TODO: business logic of processing the request
                // and generating an answer.
                let answer = mk_answer(msg, target);

                let idle_timeout = Duration::from_millis((50 * cnt).into());
                let cmd = ServiceCommand::Reconfigure { idle_timeout };
                eprintln!("Setting idle timeout to {idle_timeout:?}");

                let call_result = CallResult::new(answer).with_command(cmd);

                Ok(call_result)
            })
            .map(|(_request, call_result)| call_result)
    }))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    eprintln!("Test with commands such as:");
    eprintln!("  dig +short -4 @127.0.0.1 -p 8053 A google.com");
    eprintln!("  dig +short -4 @127.0.0.1 +tcp -p 8053 A google.com");
    eprintln!("  dig +short -4 @127.0.0.1 -p 8054 A google.com");
    eprintln!("  dig +short -4 @127.0.0.1 +tcp -p 8080 A google.com");
    eprintln!("  dig +short -6 @::1 +tcp -p 8080 A google.com");
    eprintln!("  dig +short -4 @127.0.0.1 +tcp -p 8081 A google.com");
    eprintln!("  dig +short -4 @127.0.0.1 +tls -p 8443 A google.com");

    let svc = Arc::new(MyService);

    // -----------------------------------------------------------------------
    // Run a DNS server on UDP port 8053 on 127.0.0.1. Test it like so:
    //    dig +short +keepopen +tcp -4 @127.0.0.1 -p 8082 A google.com
    let udpsocket = UdpSocket::bind("127.0.0.1:8053").await.unwrap();
    let buf_source = Arc::new(VecBufSource);
    let srv = DgramServer::new(udpsocket, buf_source.clone(), svc.clone());

    let udp_join_handle = tokio::spawn(async move { srv.run().await });

    // -----------------------------------------------------------------------
    // Run a DNS server on TCP port 8053 on 127.0.0.1. Test it like so:
    //    dig +short +keepopen +tcp -4 @127.0.0.1 +tcp -p 8053 A google.com
    let v4socket = TcpSocket::new_v4().unwrap();
    v4socket.set_reuseaddr(true).unwrap();
    v4socket.bind("127.0.0.1:8053".parse().unwrap()).unwrap();
    let v4listener = v4socket.listen(1024).unwrap();
    let buf_source = Arc::new(VecBufSource);
    let srv = StreamServer::new(v4listener, buf_source.clone(), svc.clone());
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
        // time of writing). This example is inspired by
        // https://mailarchive.ietf.org/arch/msg/dnsop/Zy3wbhHephubsy2uJesGeDst4F4/
        let udpsocket = UdpSocket::bind("127.0.0.1:8054").await.unwrap();
        let fd = <UdpSocket as std::os::fd::AsRawFd>::as_raw_fd(&udpsocket);
        let result = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_UDP,
                libc::IP_MTU_DISCOVER,
                &libc::IP_PMTUDISC_OMIT as *const libc::c_int
                    as *const libc::c_void,
                std::mem::size_of_val(&libc::IP_PMTUDISC_OMIT)
                    as libc::socklen_t,
            )
        };

        if result == -1 {
            eprintln!(
                "setsockopt error when setting IP_MTU_DISCOVER: {}",
                std::io::Error::last_os_error()
            );
        }

        let srv =
            DgramServer::new(udpsocket, buf_source.clone(), svc.clone());

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
    let srv = StreamServer::new(listener, buf_source.clone(), svc.clone());
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
    let srv = StreamServer::new(listener, buf_source.clone(), svc.clone());
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

    let mut middleware = MiddlewareBuilder::<Vec<u8>>::default();
    let server_secret = "server12secret34".as_bytes().try_into().unwrap();
    #[cfg(feature = "siphasher")]
    middleware.push(CookiesMiddlewareProcesor::new(server_secret));
    let middleware = middleware.finish();

    let cloned_buf_source = buf_source.clone();
    let target_factory =
        move || StreamTarget::new(cloned_buf_source.create_buf()).unwrap();

    let srv = StreamServer::new(
        listener,
        buf_source.clone(),
        service(query, middleware, target_factory, count).into(),
    );
    let fn_join_handle = tokio::spawn(async move { srv.run().await });

    // -----------------------------------------------------------------------
    // Demonstrate using a TLS secured TCP DNS server.

    fn load_certs(path: &Path) -> io::Result<Vec<Certificate>> {
        certs(&mut BufReader::new(File::open(path)?))
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid cert")
            })
            .map(|mut certs| certs.drain(..).map(Certificate).collect())
    }

    fn load_keys(path: &Path) -> io::Result<Vec<PrivateKey>> {
        rsa_private_keys(&mut BufReader::new(File::open(path)?))
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid key")
            })
            .map(|mut keys| keys.drain(..).map(PrivateKey).collect())
    }

    // https://github.com/rustls/hyper-rustls/blob/main/examples/ has sample
    // certificate and key files that can be used here, like so:
    //
    //   wget -O /tmp/my.crt https://raw.githubusercontent.com/rustls/hyper-rustls/main/examples/sample.pem
    //   wget -O /tmp/my.key https://raw.githubusercontent.com/rustls/hyper-rustls/main/examples/sample.rsa
    let certs = load_certs(Path::new("/tmp/my.crt")).unwrap();
    let mut keys = load_keys(Path::new("/tmp/my.key")).unwrap();

    let config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys.remove(0))
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:8443").await.unwrap();
    let listener = RustlsTcpListener::new(listener, acceptor);
    let srv = StreamServer::new(listener, buf_source.clone(), svc.clone());
    let tls_join_handle = tokio::spawn(async move { srv.run().await });

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
