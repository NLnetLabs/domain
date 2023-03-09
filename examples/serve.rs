// TODO: Split into separate examples?
use std::{
    future::Pending,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use domain::{
    base::{
        iana::{Class, Rcode},
        octets::OctetsBuilder,
        Dname, Message, MessageBuilder, StreamTarget,
    },
    rdata::A,
    serve::{
        buf::BufSource,
        dgram::DgramServer,
        service::{
            CallResult, Service, ServiceCommand, ServiceError, Transaction,
        },
        sock::AsyncAccept,
        stream::StreamServer,
    },
};
use futures::{stream::Once, Future, Stream};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio_tfo::{TfoListener, TfoStream};

// Helper fn to create a dummy response to send back to the client
fn mk_answer(msg: &Message<Vec<u8>>) -> Message<Vec<u8>> {
    let res = MessageBuilder::new_vec();
    let mut answer = res.start_answer(msg, Rcode::NoError).unwrap();
    answer
        .push((
            Dname::root_ref(),
            Class::In,
            86400,
            A::from_octets(192, 0, 2, 1),
        ))
        .unwrap();
    answer.into_message()
}

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

struct NoStream;

impl Stream for NoStream {
    type Item = Result<CallResult<Vec<u8>>, ServiceError<()>>;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        todo!()
    }
}

struct MyService;

impl Service<Vec<u8>> for MyService {
    type Error = ();

    type ResponseOctets = Vec<u8>;

    type Single = VecSingle;

    type Stream = NoStream;

    fn call(
        &self,
        message: Message<Vec<u8>>,
    ) -> Result<
        Transaction<Self::Single, Self::Stream>,
        ServiceError<Self::Error>,
    > {
        let mut target = StreamTarget::new_vec();
        target
            .append_slice(&mk_answer(&message).into_octets())
            .unwrap();
        Ok(Transaction::Single(VecSingle(Some(CallResult::new(
            target,
        )))))
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
    type Addr = SocketAddr;
    type Stream = TcpStream;

    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, Self::Addr), io::Error>> {
        let (x, y) = match self.alt.fetch_xor(true, Ordering::SeqCst) {
            false => (&self.a, &self.b),
            true => (&self.b, &self.a),
        };

        match TcpListener::poll_accept(x, cx) {
            Poll::Ready(res) => Poll::Ready(res),
            Poll::Pending => TcpListener::poll_accept(y, cx),
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
    type Addr = SocketAddr;
    type Stream = TfoStream;

    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, Self::Addr), io::Error>> {
        TfoListener::poll_accept(self, cx)
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
    type Addr = SocketAddr;

    type Stream = tokio::io::BufReader<TcpStream>;

    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, Self::Addr), io::Error>> {
        match TcpListener::poll_accept(self, cx) {
            Poll::Ready(Ok((stream, addr))) => {
                let stream = tokio::io::BufReader::new(stream);
                Poll::Ready(Ok((stream, addr)))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn service(count: Arc<AtomicU8>) -> impl Service<Vec<u8>> {
    #[allow(clippy::type_complexity)]
    fn query(
        count: Arc<AtomicU8>,
        message: Message<Vec<u8>>,
    ) -> Transaction<
        impl Future<Output = Result<CallResult<Vec<u8>>, ServiceError<()>>>,
        Once<Pending<Result<CallResult<Vec<u8>>, ServiceError<()>>>>,
    > {
        let cnt = count
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| {
                Some(if x > 0 { x - 1 } else { 0 })
            })
            .unwrap();

        Transaction::Single(async move {
            let mut target = StreamTarget::new_vec();
            target
                .append_slice(&mk_answer(&message).into_octets())
                .unwrap();
            let idle_timeout = Duration::from_millis(cnt.into());
            let cmd = ServiceCommand::Reconfigure { idle_timeout };
            eprintln!("Setting read timeout to {idle_timeout:?}");
            Ok(CallResult::with_feedback(target, cmd))
        })
    }

    move |msg| Ok(query(count.clone(), msg))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let svc = Arc::new(MyService);

    let udpsocket = UdpSocket::bind("127.0.0.1:8053").await.unwrap();
    let buf_source = Arc::new(VecBufSource);
    let srv = Arc::new(DgramServer::new(
        udpsocket,
        buf_source.clone(),
        svc.clone(),
    ));
    let udp_join_handle = tokio::spawn(srv.run());

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
            std::mem::size_of_val(&libc::IP_PMTUDISC_OMIT) as libc::socklen_t,
        )
    };
    // TODO: result will be 0 for success, -1 for error (with the error code
    // available via Error::last_os_error().raw_os_error())
    eprintln!("setsockopt result = {}", result);
    let srv = Arc::new(DgramServer::new(
        udpsocket,
        buf_source.clone(),
        svc.clone(),
    ));
    let udp_mtu_join_handle = tokio::spawn(srv.run());

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

    let srv =
        Arc::new(StreamServer::new(listener, VecBufSource, svc.clone()));
    let tcp_join_handle = tokio::spawn(srv.run());

    // Demonstrate listening with TCP Fast Open enabled (via the tokio-tfo crate).
    // On Linux strace can be used to show that the socket options are indeed
    // set as expected, e.g.:
    //
    //  > strace -e trace=setsockopt cargo run --example serve --features serve,tokio-tfo --release
    //     Finished release [optimized] target(s) in 0.12s
    //      Running `target/release/examples/serve`
    //   setsockopt(6, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
    //   setsockopt(7, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
    //   setsockopt(8, SOL_SOCKET, SO_REUSEADDR, [1], 4) = 0
    //   setsockopt(8, SOL_TCP, TCP_FASTOPEN, [1024], 4) = 0

    let tfo_listener = TfoListener::bind("127.0.0.1:8081".parse().unwrap())
        .await
        .unwrap();
    let tfo_listener = LocalTfoListener(tfo_listener);
    let tfo_srv =
        Arc::new(StreamServer::new(tfo_listener, VecBufSource, svc));
    let tfo_join_handle = tokio::spawn(tfo_srv.run());

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
    let svc = service(count).into();
    let srv = Arc::new(StreamServer::new(listener, VecBufSource, svc));
    let fn_join_handle = tokio::spawn(srv.run());

    // Keep the services running in the background

    let _ = udp_join_handle.await.unwrap().unwrap();
    let _ = udp_mtu_join_handle.await.unwrap().unwrap();
    let _ = tcp_join_handle.await.unwrap().unwrap();
    let _ = tfo_join_handle.await.unwrap().unwrap();
    let _ = fn_join_handle.await.unwrap().unwrap();
}
