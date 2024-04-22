use core::future::Future;
use core::pin::Pin;
use core::str::FromStr;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll};
use core::time::Duration;

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::sleep;
use tokio::time::Instant;

use crate::base::MessageBuilder;
use crate::base::Name;
use crate::base::Rtype;
use crate::base::StaticCompressor;
use crate::base::StreamTarget;

use super::buf::BufSource;
use super::message::Request;
use super::service::{
    CallResult, Service, ServiceError, ServiceFeedback, Transaction,
};
use super::sock::AsyncAccept;
use super::stream::StreamServer;

/// Mock I/O which supplies a sequence of mock messages to the server at a
/// defined rate.
struct MockStream {
    /// The instant when poll_read() last returned Poll::Ready.
    last_ready: Mutex<Option<Instant>>,

    /// The messages that the server should read via our mock I/O.
    /// Messages are popped from the front one at a time.
    messages_to_read: Mutex<VecDeque<Vec<u8>>>,

    /// The rate at which messages should be made available to the server.
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
}

impl AsyncRead for MockStream {
    /// Serve mock messages one at a time at a defined rate.
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
            sleep(Duration::from_millis(500)).await;
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

/// Configuration for a mock client defining which messages it should "send",
/// how often, and from which TCP/IP port the messages should appear to come
/// from.
struct MockClientConfig {
    pub new_message_every: Duration,
    pub messages: VecDeque<Vec<u8>>,
    pub client_port: u16,
}

/// A mock TCP connection acceptor with a fixed rate at which (mock) client
/// connections will be accepted.
struct MockListener {
    /// Don't accept connections until we are marked as ready. The caller
    /// acquires a clone of this (because they give away the MockListener
    /// itself) and sets it to true when they want to start accepting
    /// connections from (mock) clients.
    ready: Arc<AtomicBool>,

    /// The instant when poll_accept() last returned Poll::Ready.
    last_accept: Mutex<Option<Instant>>,

    /// The mock client connections to accept.
    streams_to_read: Mutex<VecDeque<MockClientConfig>>,

    /// The rate at which connections should be accepted.
    new_client_every: Duration,
}

impl MockListener {
    fn new(
        streams_to_read: VecDeque<MockClientConfig>,
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
    type Future = std::future::Ready<Result<Self::StreamType, io::Error>>;

    /// Accept mock connections one at a time at a defined rate.
    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Future, SocketAddr), io::Error>> {
        match self.ready.load(Ordering::Relaxed) {
            true => {
                let mut last_accept = self.last_accept.lock().unwrap();
                if last_accept
                    .map(|instant| instant.elapsed() > self.new_client_every)
                    .unwrap_or(true)
                {
                    let mut streams_to_read =
                        self.streams_to_read.lock().unwrap();
                    if let Some(MockClientConfig {
                        new_message_every,
                        messages,
                        client_port,
                    }) = streams_to_read.pop_front()
                    {
                        last_accept.replace(Instant::now());
                        return Poll::Ready(Ok((
                            std::future::ready(Ok(MockStream::new(
                                messages,
                                new_message_every,
                            ))),
                            format!("192.168.0.1:{}", client_port)
                                .parse()
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
            sleep(Duration::from_millis(100)).await;
            waker.wake();
        });

        Poll::Pending
    }
}

/// A mock buffer source, just to show it is possible to define your own.
#[derive(Clone)]
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

/// A mock single result to be returned by a mock service, just to show that
/// it is possible to define your own.
struct MySingle;

impl Future for MySingle {
    type Output = Result<CallResult<Vec<u8>>, ServiceError>;

    fn poll(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        let builder = MessageBuilder::new_stream_vec();
        let response = builder.additional();

        let command = ServiceFeedback::Reconfigure {
            idle_timeout: Some(Duration::from_millis(5000)),
        };

        let call_result = CallResult::new(response).with_feedback(command);

        Poll::Ready(Ok(call_result))
    }
}

/// A mock service that returns MySingle whenever it receives a message.
/// Just to show MySingle in action.
struct MyService;

impl MyService {
    fn new() -> Self {
        Self
    }
}

impl Service<Vec<u8>> for MyService {
    type Target = Vec<u8>;
    type Future = MySingle;

    fn call(
        &self,
        _msg: Request<Vec<u8>>,
    ) -> Result<Transaction<Self::Target, Self::Future>, ServiceError> {
        Ok(Transaction::single(MySingle))
    }
}

/// Create a mock DNS client request.
fn mk_query() -> StreamTarget<Vec<u8>> {
    let mut msg = MessageBuilder::from_target(StaticCompressor::new(
        StreamTarget::new_vec(),
    ))
    .unwrap();
    msg.header_mut().set_rd(true);
    msg.header_mut().set_random_id();

    let mut msg = msg.question();
    msg.push((Name::<Vec<u8>>::from_str("example.com.").unwrap(), Rtype::A))
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
async fn service_test() {
    let (srv_handle, server_status_printer_handle) = {
        let fast_client = MockClientConfig {
            new_message_every: Duration::from_millis(100),
            messages: VecDeque::from([
                mk_query().as_stream_slice().to_vec(),
                mk_query().as_stream_slice().to_vec(),
                mk_query().as_stream_slice().to_vec(),
                mk_query().as_stream_slice().to_vec(),
                mk_query().as_stream_slice().to_vec(),
            ]),
            client_port: 1,
        };
        let slow_client = MockClientConfig {
            new_message_every: Duration::from_millis(3000),
            messages: VecDeque::from([
                mk_query().as_stream_slice().to_vec(),
                mk_query().as_stream_slice().to_vec(),
            ]),
            client_port: 2,
        };
        let num_messages =
            fast_client.messages.len() + slow_client.messages.len();
        let streams_to_read = VecDeque::from([fast_client, slow_client]);
        let new_client_every = Duration::from_millis(2000);
        let listener = MockListener::new(streams_to_read, new_client_every);
        let ready_flag = listener.get_ready_flag();

        let buf = MockBufSource;
        let my_service = Arc::new(MyService::new());
        let srv =
            Arc::new(StreamServer::new(listener, buf, my_service.clone()));

        let metrics = srv.metrics();
        let server_status_printer_handle = tokio::spawn(async move {
            loop {
                sleep(Duration::from_millis(250)).await;
                eprintln!(
                    "Server status: #conn={:?}, #in-flight={}, #pending-writes={}, #msgs-recvd={}, #msgs-sent={}",
                    metrics.num_connections(),
                    metrics.num_inflight_requests(),
                    metrics.num_pending_writes(),
                    metrics.num_received_requests(),
                    metrics.num_sent_responses(),
                );
            }
        });

        let spawned_srv = srv.clone();
        let srv_handle = tokio::spawn(async move { spawned_srv.run().await });

        eprintln!("Clients sleeping");
        sleep(Duration::from_secs(1)).await;

        eprintln!("Clients connecting");
        ready_flag.store(true, Ordering::Relaxed);

        // Simulate a wait long enough that all simulated clients had time
        // to connect, communicate and disconnect.
        sleep(Duration::from_secs(20)).await;

        // Verify that all simulated clients connected.
        assert_eq!(0, srv.source().streams_remaining());

        // Verify that no requests or responses are in progress still in
        // the server.
        assert_eq!(srv.metrics().num_connections(), 0);
        assert_eq!(srv.metrics().num_inflight_requests(), 0);
        assert_eq!(srv.metrics().num_pending_writes(), 0);
        assert_eq!(srv.metrics().num_received_requests(), num_messages);
        assert_eq!(srv.metrics().num_sent_responses(), num_messages);

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
