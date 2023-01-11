//! Networking for a DNS server.
//!
//! DNS servers can be implemented atop various protocols which broadly fall
//! into two categories: connection-less and connection-oriented.
//!
//! Connection-less protocols receive incoming DNS messages independently of
//! each other with no concept of an established connection. Conversely
//! connection-oriented protocols have connection setup and tear down phases
//! used to establish connections between clients and the server and messages
//! are listened for on a per-connection basis.
//!
//! This module offers a consistent interface to the DNS server implementor
//! for receiving and responding to DNS messages, irrespective of the
//! semantics of the underlying transport.
//!
//! The DNS server implementor provides a [Service] implementation which
//! handles received messages and generates responses. The [Service] impl can
//! be used with any of the server implementations offered by this module.

use core::{
    future::poll_fn,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};
use std::io;

use std::sync::Arc;

use futures::{
    future::{select, Either, Future},
    pin_mut,
    stream::Stream,
    StreamExt,
};
use std::boxed::Box;
use std::string::String;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, watch::Receiver},
};

use crate::base::{octets::OctetsBuilder, Message, StreamTarget};

use super::sock::{AsyncAccept, AsyncDgramSock};

//------------ ServiceError --------------------------------------------------

pub enum ServiceError<T> {
    ShuttingDown,
    ServiceSpecificError(T),
    Other(String),
}

//------------ Service -------------------------------------------------------

/// A Service is responsible for generating responses to received DNS messages.
///
/// Responses are encapsulated inside a [Transaction] which is either [Single]
/// (a single response) or [Stream] (a stream of responses, e.g. for a zone
/// transfer).
pub trait Service<RequestOctets: AsRef<[u8]>, ShutdownSignal> {
    type Error;

    type ResponseOctets: OctetsBuilder
        + Send
        + Sync
        + 'static
        + std::convert::AsRef<[u8]>;

    type Single: Future<Output = Result<StreamTarget<Self::ResponseOctets>, io::Error>>
        + Send
        + 'static;

    type Stream: Stream<Item = Result<StreamTarget<Self::ResponseOctets>, io::Error>>
        + Send
        + 'static;

    fn shutdown_signal(&self) -> ShutdownSignal;

    fn poll_ready(
        &self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), ServiceError<Self::Error>>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &self,
        message: Message<RequestOctets>,
    ) -> Transaction<Self::Single, Self::Stream>;
}

/*impl<F, RequestOctets, ResponseOctets, Single, Strm> Service<RequestOctets>
    for F
where
    F: Fn(Message<RequestOctets>) -> Transaction<Single, Strm>,
    RequestOctets: AsRef<[u8]>,
    ResponseOctets:
        OctetsBuilder + Send + Sync + 'static + std::convert::AsRef<[u8]>,
    Single: Future<Output = Result<StreamTarget<ResponseOctets>, io::Error>>
        + Send
        + 'static,
    Strm: Stream<Item = Result<StreamTarget<ResponseOctets>, io::Error>>
        + Send
        + 'static,
{
    type Error = ();
    type ResponseOctets = ResponseOctets;
    type Single = Single;
    type Stream = Strm;

    fn call(
        &self,
        message: Message<RequestOctets>,
    ) -> Transaction<Self::Single, Self::Stream> {
        (*self)(message)
    }
}*/

//------------ Transaction ---------------------------------------------------

/// A server transaction generating the responses for a request.
pub enum Transaction<SingleFut, StreamFut>
where
    SingleFut: Future,
    StreamFut: Stream,
{
    /// The transaction will be concluded with a single response.
    Single(SingleFut),

    /// The transaction will results in stream of multiple responses.
    Stream(StreamFut),

    None,
}

impl<SingleFut, StreamFut> Transaction<SingleFut, StreamFut>
where
    SingleFut: Future,
    StreamFut: Stream,
{
    pub fn is_terminated(&self) -> bool {
        match self {
            Transaction::None => true,
            _ => false,
        }
    }

    pub fn terminate(self) -> Self {
        Self::None
    }
}

//------------ BufSource ----------------------------------------------------

pub trait BufSource {
    type Output: AsRef<[u8]> + AsMut<[u8]>;

    fn create_buf(&self) -> Self::Output;
    fn create_sized(&self, size: usize) -> Self::Output;
}

//------------ ServerMetrics -------------------------------------------------

#[derive(Debug)]
pub struct ServerMetrics {
    num_connections: Option<AtomicUsize>,
    num_inflight_requests: AtomicUsize,
    num_pending_writes: AtomicUsize,
}

impl ServerMetrics {
    pub fn new() -> Self {
        Self {
            num_connections: None,
            num_inflight_requests: AtomicUsize::new(0),
            num_pending_writes: AtomicUsize::new(0),
        }
    }
}

//------------ DgramServer ---------------------------------------------------

pub struct DgramServer<Sock, Buf, Svc> {
    sock: Arc<Sock>,
    buf: Buf,
    service: Svc,
    metrics: Arc<ServerMetrics>,
}

impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource,
    Svc: Service<Buf::Output, Receiver<()>>,
{
    pub fn new(sock: Sock, buf: Buf, service: Svc) -> Self {
        let metrics = Arc::new(ServerMetrics::new());

        DgramServer {
            sock: sock.into(),
            buf,
            service,
            metrics,
        }
    }

    pub async fn run(self) -> Result<(), io::Error> {
        loop {
            let (msg, addr) = self.recv_from().await?;
            let msg = match Message::from_octets(msg) {
                Ok(msg) => msg,
                Err(_) => continue,
            };

            let metrics = self.metrics.clone();
            let sock = self.sock.clone();
            let tran = self.service.call(msg);
            tokio::spawn(async move {
                metrics
                    .num_inflight_requests
                    .fetch_add(1, Ordering::Relaxed);
                match tran {
                    Transaction::Single(fut) => {
                        if let Ok(response) = fut.await {
                            let _ = Self::send_to(
                                &sock,
                                response.as_dgram_slice(),
                                &addr,
                            );
                        }
                    }
                    Transaction::Stream(stream) => {
                        pin_mut!(stream);
                        while let Some(response) = stream.next().await {
                            match response {
                                Ok(response) => {
                                    let _ = Self::send_to(
                                        &sock,
                                        response.as_dgram_slice(),
                                        &addr,
                                    )
                                    .await;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    Transaction::None => unreachable!(),
                }
                metrics
                    .num_inflight_requests
                    .fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    async fn recv_from(
        &self,
    ) -> Result<(Buf::Output, Sock::Addr), io::Error> {
        let mut res = self.buf.create_buf();
        let addr = {
            let mut buf = ReadBuf::new(res.as_mut());
            poll_fn(|ctx| self.sock.poll_recv_from(ctx, &mut buf)).await?
        };
        Ok((res, addr))
    }

    async fn send_to(
        sock: &Sock,
        data: &[u8],
        dest: &Sock::Addr,
    ) -> Result<(), io::Error> {
        let sent = poll_fn(|ctx| sock.poll_send_to(ctx, data, dest)).await?;
        if sent != data.len() {
            Err(io::Error::new(io::ErrorKind::Other, "short send"))
        } else {
            Ok(())
        }
    }
}

//------------ StreamServer --------------------------------------------------

pub struct StreamServer<Sock, Buf, Svc> {
    sock: Sock,
    buf: Arc<Buf>,
    service: Arc<Svc>,
    metrics: Arc<ServerMetrics>,
}

impl<Sock, Buf, Svc> StreamServer<Sock, Buf, Svc>
where
    Sock: AsyncAccept + Send + 'static,
    Sock::Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output, Receiver<()>> + Send + Sync + 'static,
{
    pub fn new(sock: Sock, buf: Buf, service: Arc<Svc>) -> Self {
        let mut metrics = ServerMetrics::new();
        metrics.num_connections.replace(AtomicUsize::new(0));
        let metrics = Arc::new(metrics);

        StreamServer {
            sock,
            buf: buf.into(),
            service,
            metrics,
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<(), io::Error> {
        let mut shutdown_signal = self.service.shutdown_signal();
        let shutdown_fut = shutdown_signal.changed();
        pin_mut!(shutdown_fut);

        loop {
            let accept_fut = Box::pin(self.accept());

            match select(accept_fut, shutdown_fut).await {
                // New TCP client connection received
                Either::Left((Ok((stream, _addr)), moved_shutdown)) => {
                    eprintln!("Accept");
                    let buf = self.buf.clone();
                    let metrics = self.metrics.clone();
                    let service = self.service.clone();

                    tokio::spawn(async move {
                        metrics
                            .num_connections
                            .as_ref()
                            .unwrap()
                            .fetch_add(1, Ordering::Relaxed);
                        let _ =
                            Self::conn(stream, buf, service, metrics.clone())
                                .await;
                        metrics
                            .num_connections
                            .as_ref()
                            .unwrap()
                            .fetch_sub(1, Ordering::Relaxed);
                    });

                    shutdown_fut = moved_shutdown;
                }

                // Failed to listen for new TCP client connections
                Either::Left((Err(_err), _)) => {
                    eprintln!("Accept err");
                    todo!()
                }

                // Received a shutdown signal
                Either::Right((_, _)) => {
                    eprintln!("Accept terminated");
                    return Ok(());
                }
            }

            eprintln!("Accept loop looping");
        }
    }

    async fn accept(&self) -> Result<(Sock::Stream, Sock::Addr), io::Error> {
        poll_fn(|ctx| self.sock.poll_accept(ctx)).await
    }

    async fn conn(
        stream: Sock::Stream,
        buf_source: Arc<Buf>,
        service: Arc<Svc>,
        metrics: Arc<ServerMetrics>,
    ) -> Result<(), io::Error> {
        let (mut read, mut write) = tokio::io::split(stream);
        let (tx, mut rx) =
            mpsc::channel::<StreamTarget<Svc::ResponseOctets>>(10); // XXX Channel length?

        // Sending end: Read messages from the channel and send them.
        let write_metrics = metrics.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                eprintln!("Write");
                if write.write_all(msg.as_stream_slice()).await.is_err() {
                    write_metrics
                        .num_pending_writes
                        .fetch_sub(1, Ordering::Relaxed);
                }
            }
            eprintln!("Writer exiting");
        });

        let mut shutdown_signal = service.shutdown_signal();
        let shutdown_fut = shutdown_signal.changed();

        pin_mut!(shutdown_fut);

        loop {
            eprintln!("Reading stream...");
            let read_fut = read.read_u16();
            pin_mut!(read_fut);

            let size = match select(read_fut, shutdown_fut).await {
                // Shutdown
                Either::Right((_, _)) => {
                    eprintln!("Read 2-octets terminated.");
                    return Ok(());
                }

                // Bytes read
                Either::Left((Ok(size), moved_shutdown_fut)) => {
                    shutdown_fut = moved_shutdown_fut;
                    size as usize
                }

                // Read error
                Either::Left((Err(err), _)) => {
                    eprintln!("Stream error: {err}");
                    return Err(err);
                }
            };

            eprintln!("Read TCP DNS 2-octet header");
            let mut buf = buf_source.create_sized(size);
            if buf.as_ref().len() < size {
                // XXX Maybe do something better here?
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "short buf",
                ));
            }

            let read_fut = read.read_exact(buf.as_mut());
            pin_mut!(read_fut);
            match select(read_fut, shutdown_fut).await {
                // Shutdown
                Either::Right((_, _)) => {
                    eprintln!("Read more octets terminated.");
                    return Ok(());
                }

                // Bytes read
                Either::Left((Ok(_size), moved_shutdown_fut)) => {
                    shutdown_fut = moved_shutdown_fut;
                }

                // Read error
                Either::Left((Err(_err), _)) => todo!(),
            }
            eprintln!("Read message");

            let msg = match Message::from_octets(buf) {
                Ok(msg) => msg,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "short message",
                    ));
                }
            };

            let tran = service.call(msg);
            // This check allows individual connections to be terminated as
            // opposed to service.is_terminated() which indicates that the
            // entire service should be shutdown.
            if tran.is_terminated() {
                eprintln!("Message terminated");
                return Ok(());
            }

            let metrics = metrics.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                metrics
                    .num_inflight_requests
                    .fetch_add(1, Ordering::Relaxed);
                match tran {
                    Transaction::Single(fut) => {
                        if let Ok(response) = fut.await {
                            let _ = tx.send(response).await;
                            metrics
                                .num_pending_writes
                                .store(tx.capacity(), Ordering::Relaxed);
                        }
                    }
                    Transaction::Stream(stream) => {
                        pin_mut!(stream);
                        while let Some(response) = stream.next().await {
                            match response {
                                Ok(response) => {
                                    if tx.send(response).await.is_err() {
                                        metrics.num_pending_writes.store(
                                            tx.capacity(),
                                            Ordering::Relaxed,
                                        );
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    Transaction::None => unreachable!(),
                }
                metrics
                    .num_inflight_requests
                    .fetch_sub(1, Ordering::Relaxed);
            });
            //tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::pin::Pin;
    use core::str::FromStr;
    use core::sync::atomic::AtomicBool;
    use core::task::Context;
    use core::task::Poll;
    use std::io;
    use std::sync::Mutex;
    use std::time::Duration;

    use futures::Future;
    use futures::Stream;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::vec::Vec;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::sync::watch::channel;
    use tokio::sync::watch::Receiver;
    use tokio::sync::watch::Sender;
    use tokio::time::Instant;

    use crate::base::Dname;
    use crate::base::MessageBuilder;
    use crate::base::Rtype;
    use crate::base::StaticCompressor;
    use crate::base::{
        /*iana::Rcode, octets::OctetsRef,*/ Message,
        /*MessageBuilder,*/ StreamTarget,
    };
    use crate::serve::sock::AsyncAccept;

    use super::{BufSource, Service, Transaction};

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

        fn last_ready(&self) -> Option<Instant> {
            self.last_ready.lock().unwrap().clone()
        }

        fn messages_remaining(&self) -> usize {
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
                let mut messages_to_read =
                    self.messages_to_read.lock().unwrap();
                match buf.remaining() {
                    2 => {
                        // Initial read: return the number of bytes that will follow
                        if let Some(next_msg) = messages_to_read.get(0) {
                            let next_msg_len =
                                u16::try_from(next_msg.len()).unwrap();
                            buf.put_slice(&next_msg_len.to_be_bytes());
                            last_ready.replace(Instant::now());
                            return Poll::Ready(Ok(()));
                        } else {
                            // End of stream
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "mock connection disconnect",
                            )));
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

    struct MockSock {
        ready: Arc<AtomicBool>,
        last_accept: Mutex<Option<Instant>>,
        streams_to_read: Mutex<VecDeque<(Duration, VecDeque<Vec<u8>>)>>,
        new_client_every: Duration,
    }

    impl MockSock {
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

        fn ready(&self) -> bool {
            self.ready.load(Ordering::Relaxed)
        }

        fn last_accept(&self) -> Option<Instant> {
            self.last_accept.lock().unwrap().clone()
        }

        fn streams_remaining(&self) -> usize {
            self.streams_to_read.lock().unwrap().len()
        }
    }

    impl AsyncAccept for MockSock {
        type Addr = ();

        type Stream = MockStream;

        fn poll_accept(
            &self,
            cx: &mut Context,
        ) -> Poll<Result<(Self::Stream, Self::Addr), io::Error>> {
            match self.ready.load(Ordering::Relaxed) {
                true => {
                    let mut last_accept = self.last_accept.lock().unwrap();
                    if last_accept
                        .map(|instant| {
                            instant.elapsed() > self.new_client_every
                        })
                        .unwrap_or(true)
                    {
                        let mut streams_to_read =
                            self.streams_to_read.lock().unwrap();
                        if let Some((new_message_every, messages)) =
                            streams_to_read.pop_front()
                        {
                            eprintln!("Accept succeeding");
                            last_accept.replace(Instant::now());
                            return Poll::Ready(Ok((
                                MockStream::new(messages, new_message_every),
                                (),
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
                //eprintln!("Accept waker task sleeping");
                tokio::time::sleep(Duration::from_millis(100)).await;
                //eprintln!("Accept waker task waking up!");
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
        type Output = Result<StreamTarget<Vec<u8>>, io::Error>;

        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Self::Output> {
            Poll::Ready(Ok(StreamTarget::new_vec()))
        }
    }

    struct MyStream;

    impl Stream for MyStream {
        type Item = Result<StreamTarget<Vec<u8>>, io::Error>;

        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            todo!()
        }
    }

    struct MyService {
        shutdown_rx: Receiver<()>,
        shutdown_tx: Sender<()>,
    }

    impl MyService {
        fn new() -> Self {
            let (shutdown_tx, shutdown_rx) = channel(());
            Self {
                shutdown_rx,
                shutdown_tx,
            }
        }

        fn shutdown(&self) {
            let _ = self.shutdown_tx.send(());
        }
    }

    impl Service<Vec<u8>, Receiver<()>> for MyService {
        type Error = ();

        type ResponseOctets = Vec<u8>;

        type Single = MySingle;

        type Stream = MyStream;

        fn shutdown_signal(&self) -> Receiver<()> {
            self.shutdown_rx.clone()
        }

        fn call(
            &self,
            _msg: Message<Vec<u8>>,
        ) -> Transaction<Self::Single, Self::Stream> {
            Transaction::Single(MySingle)
            // if for some reason the request should not be processed and the
            // connection with the client should be terminated, we can return
            // Transaction::None instead.
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
        let (srv_join_handle, dbg_handle) = {
            let fast_client = (
                Duration::from_millis(100),
                VecDeque::from([mk_query().as_stream_slice().to_vec()]),
            );
            let slow_client = (
                Duration::from_millis(3000),
                VecDeque::from([mk_query().as_stream_slice().to_vec()]),
            );
            let streams_to_read = VecDeque::from([fast_client, slow_client]);
            let new_client_every = Duration::from_millis(2000);
            let sock = MockSock::new(streams_to_read, new_client_every);
            let ready_flag = sock.get_ready_flag();

            let buf = MockBufSource;
            let my_service = Arc::new(MyService::new());
            let srv =
                Arc::new(StreamServer::new(sock, buf, my_service.clone()));

            let metrics = srv.metrics.clone();
            let dbg_handle = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    eprintln!(
                        "Server status: #conn={:?}, #req={:?}, #writes={:?}",
                        metrics.num_connections,
                        metrics.num_inflight_requests,
                        metrics.num_pending_writes
                    );
                }
            });

            let handle = tokio::spawn(srv.clone().run());

            eprintln!("Clients sleeping");
            tokio::time::advance(Duration::from_millis(1000)).await;

            eprintln!("Clients connecting");
            ready_flag.store(true, Ordering::Relaxed);

            tokio::time::sleep(Duration::from_millis(5000)).await;
            eprintln!("Shutting down");
            my_service.shutdown();
            eprintln!("Shutdown signal sent");

            (handle, dbg_handle)
        };

        eprintln!("Test waiting");
        let _ = srv_join_handle.await;

        dbg_handle.abort();
    }
}
