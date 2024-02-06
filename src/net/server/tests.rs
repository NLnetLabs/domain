use core::pin::Pin;
use core::str::FromStr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;
use core::task::Context;
use core::task::Poll;
use std::io;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use futures::Future;
use std::collections::VecDeque;
use std::sync::Arc;
use std::vec::Vec;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::base::Dname;
use crate::base::MessageBuilder;
use crate::base::Rtype;
use crate::base::StaticCompressor;
use crate::base::{
    /*iana::Rcode, octets::OctetsRef,*/ Message,
    /*MessageBuilder,*/ StreamTarget,
};
use crate::net::server::buf::BufSource;
use crate::net::server::service::CallResult;
use crate::net::server::service::Service;
use crate::net::server::service::ServiceCommand;
use crate::net::server::service::ServiceError;
use crate::net::server::service::Transaction;
use crate::net::server::sock::AsyncAccept;
use crate::net::server::stream::StreamServer;
use crate::net::server::Server;

use super::service::ServiceResultItem;
use super::ContextAwareMessage;

/*fn service<RequestOctets: AsRef<[u8]> + Send + Sync + 'static>(
    count: Arc<AtomicU8>,
) -> impl Service<RequestOctets>
where
    for<'a> &'a RequestOctets: OctetsRef,
{
    #[allow(clippy::type_complexity)]
    fn query<RequestOctets: AsRef<[u8]>>(
        count: Arc<AtomicU8>,
        msg: Message<RequestOctets>,
    ) -> Transaction<
        impl Future<Output = Result<StreamTarget<Vec<u8>>, io::Error>>,
        Once<Pending<Result<StreamTarget<Vec<u8>>, io::Error>>>,
    >
    where
        for<'a> &'a RequestOctets: OctetsRef,
    {
        let txn = Transaction::Single(async move {
            let res = MessageBuilder::new_stream_vec();
            let answer = res.start_answer(&msg, Rcode::NoError).unwrap();
            Ok(answer.finish())
        });

        let cnt = count.fetch_add(1, Ordering::Relaxed);
        if cnt >= 50 {
            txn.terminate()
        } else {
            txn
        }
    }

    move |msg| query(count.clone(), msg)
}*/

struct MockStream {
    last_ready: Mutex<Option<Instant>>,
    messages_to_read: Mutex<VecDeque<Vec<u8>>>,
    new_message_every: Duration,
}

impl MockStream {
    fn new(
        messages_to_read: VecDeque<Vec<u8>>,
        new_message_every: Duration,
    ) -> Self {
        Self {
            last_ready: Mutex::new(Option::None),
            messages_to_read: Mutex::new(messages_to_read),
            new_message_every,
        }
    }

    fn _last_ready(&self) -> Option<Instant> {
        *self.last_ready.lock().unwrap()
    }

    fn _messages_remaining(&self) -> usize {
        self.messages_to_read.lock().unwrap().len()
    }
}

impl AsyncRead for MockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut last_ready = self.last_ready.lock().unwrap();

        if last_ready
            .map(|instant| instant.elapsed() > self.new_message_every)
            .unwrap_or(true)
        {
            let mut messages_to_read = self.messages_to_read.lock().unwrap();
            match buf.remaining() {
                2 => {
                    // Initial read: return the number of bytes that will follow
                    if let Some(next_msg) = messages_to_read.front() {
                        let next_msg_len =
                            u16::try_from(next_msg.len()).unwrap();
                        buf.put_slice(&next_msg_len.to_be_bytes());
                        last_ready.replace(Instant::now());
                        return Poll::Ready(Ok(()));
                    } else {
                        // End of stream
                        /*return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::ConnectionAborted,
                            "mock connection disconnect",
                        )));*/
                    }
                }
                _ => {
                    // subsequent read, return the message bytes
                    if let Some(msg) = messages_to_read.pop_front() {
                        buf.put_slice(&msg);
                        return Poll::Ready(Ok(()));
                    }
                }
            }
        }

        let waker = cx.waker().clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            waker.wake();
        });

        Poll::Pending
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct MockListener {
    ready: Arc<AtomicBool>,
    last_accept: Mutex<Option<Instant>>,
    streams_to_read: Mutex<VecDeque<(Duration, VecDeque<Vec<u8>>)>>,
    new_client_every: Duration,
}

impl MockListener {
    fn new(
        streams_to_read: VecDeque<(Duration, VecDeque<Vec<u8>>)>,
        new_client_every: Duration,
    ) -> Self {
        Self {
            ready: Arc::new(AtomicBool::new(false)),
            streams_to_read: Mutex::new(streams_to_read),
            last_accept: Mutex::new(Option::None),
            new_client_every,
        }
    }

    fn get_ready_flag(&self) -> Arc<AtomicBool> {
        self.ready.clone()
    }

    fn _ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    fn _last_accept(&self) -> Option<Instant> {
        *self.last_accept.lock().unwrap()
    }

    fn streams_remaining(&self) -> usize {
        self.streams_to_read.lock().unwrap().len()
    }
}

impl AsyncAccept for MockListener {
    type Error = io::Error;
    type StreamType = MockStream;
    type Stream = futures::future::Ready<Result<Self::StreamType, io::Error>>;

    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, SocketAddr), io::Error>> {
        match self.ready.load(Ordering::Relaxed) {
            true => {
                let mut last_accept = self.last_accept.lock().unwrap();
                if last_accept
                    .map(|instant| instant.elapsed() > self.new_client_every)
                    .unwrap_or(true)
                {
                    let mut streams_to_read =
                        self.streams_to_read.lock().unwrap();
                    if let Some((new_message_every, messages)) =
                        streams_to_read.pop_front()
                    {
                        last_accept.replace(Instant::now());
                        return Poll::Ready(Ok((
                            futures::future::ready(Ok(MockStream::new(
                                messages,
                                new_message_every,
                            ))),
                            SocketAddr::from_str("192.168.0.1:12345")
                                .unwrap(),
                        )));
                    } else {
                        //eprintln!(
                        //    "Accept failing, no more clients to simulate"
                        //);
                    }
                } else {
                    //eprintln!("Accept failing, not time yet for the next client");
                }
            }
            false => {
                //eprintln!("Accept failing, not ready to let clients connect yet");
            }
        }

        let waker = cx.waker().clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            waker.wake();
        });

        Poll::Pending
    }
}

struct MockBufSource;
impl BufSource for MockBufSource {
    type Output = Vec<u8>;

    fn create_buf(&self) -> Self::Output {
        vec![0; 1024]
    }

    fn create_sized(&self, size: usize) -> Self::Output {
        vec![0; size]
    }
}

/*#[tokio::test(flavor = "multi_thread")]
async fn stop_service_fn_test() {
    let srv_join_handle = {
        let sock = MockSock;
        let buf = MockBufSource;
        let count = Arc::new(AtomicU8::new(0));
        let srv =
            Arc::new(StreamServer::new(sock, buf, service(count).into()));
        let handle = tokio::spawn(srv.clone().run());
        tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
        srv.shutdown(); // without this the task never finishes below when .await'd
        handle
    };

    let _ = srv_join_handle.await;

    tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
}*/

struct MySingle;

impl Future for MySingle {
    type Output = Result<CallResult<Vec<u8>>, ServiceError<()>>;

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        let builder = MessageBuilder::new_stream_vec();
        let response = builder.additional();

        let command = ServiceCommand::Reconfigure {
            idle_timeout: Duration::from_millis(5000),
        };

        let call_result = CallResult::new(response).with_command(command);

        Poll::Ready(Ok(call_result))
    }
}

struct MyService;

impl MyService {
    fn new() -> Self {
        Self
    }
}

impl Service<Vec<u8>> for MyService {
    type Error = ();
    type Target = Vec<u8>;
    type Single = MySingle;

    fn call(
        &self,
        _msg: Arc<ContextAwareMessage<Message<Vec<u8>>>>,
        // TODO: pass other requestor address details e.g. IP address, port, etc.
    ) -> Result<
        Transaction<
            ServiceResultItem<Self::Target, Self::Error>,
            Self::Single,
        >,
        ServiceError<Self::Error>,
    > {
        Ok(Transaction::single(MySingle))
        // Err(ServiceError::ShuttingDown)
    }
}

fn mk_query() -> StreamTarget<Vec<u8>> {
    let mut msg = MessageBuilder::from_target(StaticCompressor::new(
        StreamTarget::new_vec(),
    ))
    .unwrap();
    msg.header_mut().set_rd(true);
    msg.header_mut().set_random_id();

    let mut msg = msg.question();
    msg.push((
        Dname::<Vec<u8>>::from_str("example.com.").unwrap(),
        Rtype::A,
    ))
    .unwrap();

    let mut msg = msg.additional();
    msg.opt(|opt| {
        opt.set_udp_payload_size(4096);
        Ok(())
    })
    .unwrap();

    msg.finish().into_target()
}

// By using start_paused = true (from tokio feature "test-util") we cause
// tokio time related types and functions such as Instant and sleep() to
// signal that time has passed when in fact it actually hasn't, allowing a
// time dependent test to run much faster without actual periods of
// waiting to allow time to elapse.
#[tokio::test(flavor = "current_thread", start_paused = true)]
async fn stop_service_test() {
    let (srv_handle, server_status_printer_handle) = {
        let fast_client = (
            Duration::from_millis(100),
            VecDeque::from([mk_query().as_stream_slice().to_vec()]),
        );
        let slow_client = (
            Duration::from_millis(3000),
            VecDeque::from([
                mk_query().as_stream_slice().to_vec(),
                mk_query().as_stream_slice().to_vec(),
            ]),
        );
        let streams_to_read = VecDeque::from([fast_client, slow_client]);
        let new_client_every = Duration::from_millis(2000);
        let listener = MockListener::new(streams_to_read, new_client_every);
        let ready_flag = listener.get_ready_flag();

        let buf = MockBufSource;
        let my_service = Arc::new(MyService::new());
        let srv = Arc::new(StreamServer::new(
            listener,
            buf.into(),
            my_service.clone(),
        ));

        let metrics = srv.metrics();
        let server_status_printer_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                eprintln!(
                    "Server status: #conn={:?}, #req={:?}, #writes={:?}",
                    metrics.num_connections,
                    metrics.num_inflight_requests,
                    metrics.num_pending_writes
                );
            }
        });

        let spawned_srv = srv.clone();
        let srv_handle = tokio::spawn(async move { spawned_srv.run().await });

        eprintln!("Clients sleeping");
        tokio::time::sleep(Duration::from_millis(1000)).await;

        eprintln!("Clients connecting");
        ready_flag.store(true, Ordering::Relaxed);

        // Simulate a wait long enough that all simulated clients had time
        // to connect, communicate and disconnect.
        tokio::time::sleep(Duration::from_millis(15000)).await;

        // Verify that all simulated clients connected.
        assert_eq!(0, srv.source().streams_remaining());

        // Verify that no requests or responses are in progress still in
        // the server.
        assert_eq!(srv.metrics().num_connections(), Some(0));
        assert_eq!(srv.metrics().num_inflight_requests(), 0);
        assert_eq!(srv.metrics().num_pending_writes(), 0);

        eprintln!("Shutting down");
        srv.shutdown().unwrap();
        eprintln!("Shutdown command sent");

        (srv_handle, server_status_printer_handle)
    };

    eprintln!("Waiting for service to shutdown");
    let _ = srv_handle.await;

    // Terminate the task that periodically prints the server status
    server_status_printer_handle.abort();
}
