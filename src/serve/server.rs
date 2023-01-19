//! Networking for a DNS server.
//!
//! This module provides server implementations for handling exchange of DNS
//! messages in the form of byte sequences at the network layer, for both
//! connection-less! (aka datagram) and connection-oriented (aka stream) based
//! network protocols.
//!
//! Connection-less protocols (e.g. UDP) receive incoming DNS messages
//! independently of each other with no concept of an established connection,
//! while connection-oriented protocols have connection setup and tear down
//! phases used to establish connections (e.g. TCP) between clients and the
//! server, and messages are listened for on a per-connection basis.
//!
//! The provided [`DgramServer`] and [`StreamServer`] types are generic over
//! the low-level socket/stream types used to send and receive via the
//! network, over the allocation strategy for message buffers, and over the
//! [`Service`] responsible for interpreting and constructing request and
//! response byte sequences respectively.
//!
//! The `Server` types offer methods for managing the lifetime and
//! configuration of the server while it is running, e.g. to change the port
//! being listened upon or to adjust the default timeout used for receipt of
//! incoming messages. The [`DgramServer`] and [`StreamServer`] types also
//! collect [`ServerMetrics`] while running to support both diagnostic and
//! policy use cases.
//!
//! A [`Service`] may be used with multiple `Server` impls at the same time,
//! e.g. to offer a shared cache over both TCP and UDP endpoints. `Server`
//! instances can be shutdown independently, or collectively by shutting down
//! the [`Service`] instance that they delegate message handling to.
//!
//! When a [`Service`] is called to handle a request the [`CallResult`] can be
//! either a response byte sequence to write back to the requestor, and/or
//! feedback to the `Server` handling the request/response to alter its
//! behaviour in some way, e.g. to adjust the request timeout for the current
//! connection only (to support the [EDNS(0)] timeout adjustment capability
//! for example), or to disconnect an abusive client. Response byte sequences
//! can be packaged in two ways: [`Transaction::Single`] or
//! [`Transaction::Stream`], the latter being intended to support use cases
//! such as zone transfer which involves sending multiple messages in response
//! to a single request.

// TODO: Add TLS support.
// TODO: Add tracing/logging support? (or metrics only?)
// TODO: Allow the default timeout(s?) to be configured.
// TODO: Use a strategy pattern to extract chosen behaviours? E.g. retry
//       backoff pattern in case of transient network issues? Maybe also the
//       immediate vs delayed write patterns?
// TODO: Look at whether there is unnecessary cloning that can be removed.
// TODO: Replace unwraps with error handling where needed.
// TODO: Improved naming.
// TODO: More/better RustDocs.
// TODO: Split into separate files.
// TODO: Look at whether Ordering::Relaxed is the right ordering type to use
//       where it is currently used.
// TODO: Expose metrics to the caller.
// TODO: Pass client details to the service callback.
// TODO: Use Tokio select! (over N futures) macro instead of select() fn (over
//       just 2 futures)?

use core::{
    future::poll_fn,
    sync::atomic::{AtomicUsize, Ordering},
};
use std::{boxed::Box, io, sync::Mutex, time::Duration};

use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::{
    future::{select, Either, Future},
    pin_mut,
    stream::Stream,
    StreamExt,
};

use std::string::String;
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf,
        ReadHalf, WriteHalf,
    },
    sync::{
        mpsc,
        watch::{self, error::RecvError},
    },
    time::timeout,
};

use crate::base::{octets::OctetsBuilder, Message, StreamTarget};

use super::sock::{AsyncAccept, AsyncDgramSock};

//------------ ServiceError --------------------------------------------------

enum ServerEvent<T, U, V, W> {
    Accept(T, U),
    AcceptError(V),
    Command(ServiceCommand),
    CommandError(W),
}

enum ConnectionEvent<T> {
    /// RFC 7766 6.2.4 "Under normal operation DNS clients typically initiate
    /// connection closing on idle connections; however, DNS servers can close
    /// the connection if the idle timeout set by local policy is exceeded.
    /// Also, connections can be closed by either end under unusual conditions
    /// such as defending against an attack or system failure reboot."
    ///
    /// And: RFC 7766 3 "A DNS server considers an established DNS-over-TCP
    /// session to be idle when it has sent responses to all the queries it
    /// has received on that connection."
    DisconnectWithoutFlush,

    /// RFC 7766 6.2.3 "If a DNS server finds that a DNS client has closed a
    /// TCP session (or if the session has been otherwise interrupted) before
    /// all pending responses have been sent, then the server MUST NOT attempt
    /// to send those responses.  Of course, the DNS server MAY cache those
    /// responses."
    DisconnectWithFlush,

    ReadSucceeded,

    ServiceError(ServiceError<T>),
}

pub enum ServiceError<T> {
    ServiceSpecificError(T),
    ShuttingDown,
    Other(String),
}

//------------ ServiceCommand ------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub enum ServiceCommand {
    CloseConnection,
    Init,
    Reconfigure { idle_timeout: Duration },
    Shutdown,
}

//------------ CallResult ----------------------------------------------------

pub struct CallResult<ResponseOctets> {
    response: Option<StreamTarget<ResponseOctets>>,
    command: Option<ServiceCommand>,
}

/// Directions to a server on how to respond to a request.
///
/// [`CallResult`] supports the following ways to handle a client request:
///
///   - Respond to the client. This is the default case.
///
///   - Respond to the client and adjust the servers handling of requests.
///     This could be required for example to honour a client request EDNS(0)
///     OPT RR that requests that the timeout from server to client be altered.
///
///   - Ignore the client request, e.g. due to policy.
///
///   - Terminate the connection with the client, e.g. due to policy or
///     or because the service is shutting down.
///
/// For reasons of policy it may be necessary to ignore certain client
/// requests without sending a response
impl<ResponseOctets> CallResult<ResponseOctets> {
    pub fn new(response: StreamTarget<ResponseOctets>) -> Self {
        Self {
            response: Some(response),
            command: None,
        }
    }

    pub fn with_feedback(
        response: StreamTarget<ResponseOctets>,
        command: ServiceCommand,
    ) -> Self {
        Self {
            response: Some(response),
            command: Some(command),
        }
    }

    pub fn per_policy(
        command: ServiceCommand,
        response: Option<StreamTarget<ResponseOctets>>,
    ) -> Self {
        Self {
            response,
            command: Some(command),
        }
    }

    pub fn response(&mut self) -> Option<StreamTarget<ResponseOctets>> {
        self.response.take()
    }

    pub fn command(&mut self) -> Option<ServiceCommand> {
        self.command.take()
    }
}

//------------ Service -------------------------------------------------------

/// A Service is responsible for generating responses to received DNS messages.
///
/// Responses are encapsulated inside a [Transaction] which is either [Single]
/// (a single response) or [Stream] (a stream of responses, e.g. for a zone
/// transfer).
pub trait Service<RequestOctets: AsRef<[u8]>> {
    type Error: Send + Sync + 'static;

    type ResponseOctets: OctetsBuilder
        + Send
        + Sync
        + 'static
        + std::convert::AsRef<[u8]>;

    type Single: Future<
            Output = Result<
                CallResult<Self::ResponseOctets>,
                ServiceError<Self::Error>,
            >,
        > + Send
        + 'static;

    type Stream: Stream<
            Item = Result<
                CallResult<Self::ResponseOctets>,
                ServiceError<Self::Error>,
            >,
        > + Send
        + 'static;

    // fn poll_ready(
    //     &self,
    //     _cx: &mut Context<'_>,
    // ) -> Poll<Result<(), ServiceError<Self::Error>>> {
    //     Poll::Ready(Ok(()))
    // }

    fn call(
        &self,
        message: Message<RequestOctets>,
    ) -> Result<
        Transaction<Self::Single, Self::Stream>,
        ServiceError<Self::Error>,
    >;
}

impl<F, SrvErr, ReqOct, RespOct, Sing, Strm> Service<ReqOct> for F
where
    F: Fn(
        Message<ReqOct>,
    ) -> Result<Transaction<Sing, Strm>, ServiceError<SrvErr>>,
    ReqOct: AsRef<[u8]>,
    RespOct:
        OctetsBuilder + Send + Sync + 'static + std::convert::AsRef<[u8]>,
    Sing: Future<Output = Result<CallResult<RespOct>, ServiceError<SrvErr>>>
        + Send
        + 'static,
    Strm: Stream<Item = Result<CallResult<RespOct>, ServiceError<SrvErr>>>
        + Send
        + 'static,
    SrvErr: Send + Sync + 'static,
{
    type Error = SrvErr;
    type ResponseOctets = RespOct;
    type Single = Sing;
    type Stream = Strm;

    fn call(
        &self,
        message: Message<ReqOct>,
    ) -> Result<
        Transaction<Self::Single, Self::Stream>,
        ServiceError<Self::Error>,
    > {
        (*self)(message)
    }
}

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

    pub fn num_connections(&self) -> Option<usize> {
        self.num_connections
            .as_ref()
            .map(|atomic| atomic.load(Ordering::Relaxed))
    }

    pub fn num_inflight_requests(&self) -> usize {
        self.num_inflight_requests.load(Ordering::Relaxed)
    }

    pub fn num_pending_writes(&self) -> usize {
        self.num_pending_writes.load(Ordering::Relaxed)
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
    Svc: Service<Buf::Output>,
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

    pub async fn run(self: Arc<Self>) -> Result<(), io::Error> {
        loop {
            let (msg, addr) = self.recv_from().await?;
            let msg = match Message::from_octets(msg) {
                Ok(msg) => msg,
                Err(_) => continue,
            };

            let metrics = self.metrics.clone();
            let sock = self.sock.clone();
            let txn = self.service.call(msg);
            tokio::spawn(async move {
                metrics
                    .num_inflight_requests
                    .fetch_add(1, Ordering::Relaxed);
                match txn {
                    Ok(Transaction::Single(call_fut)) => {
                        if let Ok(call_result) = call_fut.await {
                            Self::handle_call_result(
                                &sock,
                                &addr,
                                call_result,
                            )
                            .await;
                        }
                    }
                    Ok(Transaction::Stream(stream)) => {
                        pin_mut!(stream);
                        while let Some(response) = stream.next().await {
                            match response {
                                Ok(call_result) => {
                                    Self::handle_call_result(
                                        &sock,
                                        &addr,
                                        call_result,
                                    )
                                    .await;
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    Err(_err) => todo!(),
                }
                metrics
                    .num_inflight_requests
                    .fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    async fn handle_call_result(
        sock: &Sock,
        addr: &Sock::Addr,
        mut call_result: CallResult<Svc::ResponseOctets>,
    ) {
        if let Some(response) = call_result.response() {
            let _ = Self::send_to(sock, response.as_dgram_slice(), addr);
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

pub struct StreamServer<Listener, Buf, Svc> {
    command_rx: watch::Receiver<ServiceCommand>,
    command_tx: Arc<Mutex<watch::Sender<ServiceCommand>>>,
    listener: Arc<Listener>,
    buf: Arc<Buf>,
    service: Arc<Svc>,
    metrics: Arc<ServerMetrics>,
}

struct StreamState<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + 'static,
    Listener::Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    stream_tx: WriteHalf<Listener::Stream>,

    result_q_tx: mpsc::Sender<CallResult<Svc::ResponseOctets>>,

    // RFC 1035 7.1: "Since a resolver must be able to multiplex multiple
    // requests if it is to perform its function efficiently, each pending
    // request is usually represented in some block of state information.
    // This state block will typically contain:
    //
    //   - A timestamp indicating the time the request began.
    //     The timestamp is used to decide whether RRs in the database
    //     can be used or are out of date.  This timestamp uses the
    //     absolute time format previously discussed for RR storage in
    //     zones and caches.  Note that when an RRs TTL indicates a
    //     relative time, the RR must be timely, since it is part of a
    //     zone.  When the RR has an absolute time, it is part of a
    //     cache, and the TTL of the RR is compared against the timestamp
    //     for the start of the request.

    //     Note that using the timestamp is superior to using a current
    //     time, since it allows RRs with TTLs of zero to be entered in
    //     the cache in the usual manner, but still used by the current
    //     request, even after intervals of many seconds due to system
    //     load, query retransmission timeouts, etc."
    //
    // And: RFC 7766 6.2.3: "DNS messages delivered over TCP might arrive in
    // multiple segments.  A DNS server that resets its idle timeout after
    // receiving a single segment might be vulnerable to a "slow-read attack".
    // For this reason, servers SHOULD reset the idle timeout on the receipt
    // of a full DNS message, rather than on receipt of any part of a DNS
    // message."
    last_full_msg_received_at: Option<DateTime<Utc>>,

    // RFC 7766 3: "A DNS server considers an established DNS-over-TCP session
    // to be idle when it has sent responses to all the queries it has
    // received on that connection."
    response_queue_emptied_at: Option<DateTime<Utc>>,

    idle_timeout: chrono::Duration,
}

impl<Listener, Buf, Svc> StreamState<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + 'static,
    Listener::Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    fn new(
        stream_tx: WriteHalf<Listener::Stream>,
        result_q_tx: mpsc::Sender<CallResult<Svc::ResponseOctets>>,
        idle_timeout: chrono::Duration,
    ) -> Self {
        Self {
            stream_tx,
            result_q_tx,
            last_full_msg_received_at: None,
            response_queue_emptied_at: None,
            idle_timeout,
        }
    }

    pub fn idle_time(&self) -> chrono::Duration {
        if let Some(ts) = self.last_full_msg_received_at {
            Utc::now().signed_duration_since(ts)
        } else {
            self.idle_timeout
        }
    }

    fn full_msg_received(&mut self) {
        self.last_full_msg_received_at = Some(Utc::now());
    }

    fn response_queue_emptied(&mut self) {
        self.response_queue_emptied_at = Some(Utc::now());
    }
}

struct ConnectedStream<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + 'static,
    Listener::Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    buf_source: Arc<Buf>,
    metrics: Arc<ServerMetrics>,
    service: Arc<Svc>,
    stream: Option<Listener::Stream>,
}

impl<Listener, Buf, Svc> StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + 'static,
    Listener::Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    pub fn new(listener: Listener, buf: Buf, service: Arc<Svc>) -> Self {
        let (command_tx, command_rx) = watch::channel(ServiceCommand::Init);
        let command_tx = Arc::new(Mutex::new(command_tx));

        let listener = Arc::new(listener);

        let mut metrics = ServerMetrics::new();
        metrics.num_connections.replace(AtomicUsize::new(0));
        let metrics = Arc::new(metrics);

        StreamServer {
            command_tx,
            command_rx,
            listener,
            buf: buf.into(),
            service,
            metrics,
        }
    }

    pub fn listener(&self) -> Arc<Listener> {
        self.listener.clone()
    }

    pub fn shutdown(
        &self,
    ) -> Result<(), watch::error::SendError<ServiceCommand>> {
        eprintln!("Sending shutdown command");
        self.command_tx
            .lock()
            .unwrap()
            .send(ServiceCommand::Shutdown)
    }

    pub async fn run(self: Arc<Self>) -> Result<(), io::Error> {
        let mut command_rx = self.command_rx.clone();

        loop {
            // TODO: Factor the next 5 lines out to a helper fn.
            let command_fut = command_rx.changed();
            let accept_fut = self.accept();

            pin_mut!(command_fut);
            pin_mut!(accept_fut);

            match (
                select(accept_fut, command_fut).await,
                self.command_rx.clone(),
            )
                .into()
            {
                ServerEvent::Accept(stream, _addr) => {
                    let conn = ConnectedStream::<Listener, Buf, Svc>::new(
                        self.service.clone(),
                        self.buf.clone(),
                        self.metrics.clone(),
                        stream,
                    );
                    tokio::spawn(conn.run(self.command_rx.clone()));
                }

                ServerEvent::AcceptError(_err) => {
                    eprintln!("Accept err");
                    todo!()
                }

                ServerEvent::Command(ServiceCommand::Init) => unreachable!(),

                ServerEvent::Command(ServiceCommand::Reconfigure {
                    ..
                }) => { /* TO DO */ }

                ServerEvent::Command(ServiceCommand::CloseConnection {
                    ..
                }) => unreachable!(),

                ServerEvent::Command(ServiceCommand::Shutdown) => {
                    return Ok(());
                }

                ServerEvent::CommandError(err) => {
                    eprintln!("StreamServer receive command error: {err}");
                    todo!();
                }
            }
        }
    }

    async fn accept(
        &self,
    ) -> Result<(Listener::Stream, Listener::Addr), io::Error> {
        poll_fn(|ctx| self.listener.poll_accept(ctx)).await
    }
}

enum ProcessActionResult<T> {
    CommandReceived,
    CallResultReceived(T),
}

type CommandNotification = Result<(), RecvError>;

impl<Listener, Buf, Svc> ConnectedStream<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + 'static,
    Listener::Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    fn new(
        service: Arc<Svc>,
        buf_source: Arc<Buf>,
        metrics: Arc<ServerMetrics>,
        stream: Listener::Stream,
    ) -> Self {
        Self {
            buf_source,
            service,
            metrics,
            stream: Some(stream),
        }
    }

    async fn run(mut self, command_rx: watch::Receiver<ServiceCommand>) {
        self.metrics
            .num_connections
            .as_ref()
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);

        let stream = self.stream.take().unwrap();
        self.run_until_error(command_rx, stream).await;

        self.metrics
            .num_connections
            .as_ref()
            .unwrap()
            .fetch_sub(1, Ordering::Relaxed);
    }

    async fn run_until_error(
        &self,
        mut command_rx: watch::Receiver<ServiceCommand>,
        stream: Listener::Stream,
    ) {
        let (mut stream_rx, stream_tx) = tokio::io::split(stream);
        let (result_q_tx, mut result_q_rx) =
            mpsc::channel::<CallResult<Svc::ResponseOctets>>(10); // TODO: Take from configuration
        let idle_timeout = chrono::Duration::seconds(3); // TODO: Take from configuration

        let mut state =
            StreamState::new(stream_tx, result_q_tx, idle_timeout);

        let mut msg_size_buf = self.buf_source.create_sized(2);

        loop {
            if let Err(err) = self
                .transceive_one_request(
                    &mut command_rx,
                    &mut state,
                    &mut stream_rx,
                    &mut result_q_rx,
                    &mut msg_size_buf,
                )
                .await
            {
                if matches!(err, ConnectionEvent::DisconnectWithFlush) {
                    self.flush_write_queue(&mut state, &mut result_q_rx)
                        .await;
                }
            }
        }
    }

    async fn transceive_one_request(
        &self,
        command_rx: &mut watch::Receiver<ServiceCommand>,
        state: &mut StreamState<Listener, Buf, Svc>,
        stream_rx: &mut ReadHalf<<Listener as AsyncAccept>::Stream>,
        result_q_rx: &mut mpsc::Receiver<CallResult<Svc::ResponseOctets>>,
        msg_size_buf: &mut <Buf as BufSource>::Output,
    ) -> Result<(), ConnectionEvent<Svc::Error>> {
        self.transceive_until(
            command_rx,
            state,
            stream_rx,
            result_q_rx,
            msg_size_buf,
        )
        .await?;

        let msg_len =
            u16::from_be_bytes(msg_size_buf.as_ref().try_into().unwrap());
        let mut msg_buf = self.buf_source.create_sized(msg_len as usize);

        self.transceive_until(
            command_rx,
            state,
            stream_rx,
            result_q_rx,
            &mut msg_buf,
        )
        .await?;

        state.full_msg_received();

        self.process_message(&*state, msg_buf, self.service.clone())
            .await
            .map_err(ConnectionEvent::ServiceError)?;

        Ok(())
    }

    async fn transceive_until(
        &self,
        command_rx: &mut watch::Receiver<ServiceCommand>,
        state: &mut StreamState<Listener, Buf, Svc>,
        stream_rx: &mut ReadHalf<Listener::Stream>,
        result_q_rx: &mut mpsc::Receiver<CallResult<Svc::ResponseOctets>>,
        buf: &mut <Buf as BufSource>::Output,
    ) -> Result<ConnectionEvent<Svc::Error>, ConnectionEvent<Svc::Error>>
    {
        // Note: The MPSC receiver used to receive finished service call
        // results can be read from safely even if the future is cancelled.
        // Thus we don't need to keep the future, we can just call recv()
        // again when we need to.
        //
        // The same is not true of reading an exact number of bytes from the
        // incoming data stream, the future cannot be cancelled safely as any
        // bytes already read will be written to the buffer but we will lose
        // the knowledge of how many bytes have been written to the buffer. So
        // we must keep using the same future until it finally resolves when
        // the read is complete or results in an error.
        'read: loop {
            // Per RFC 7766 3 and 6.2.3 we should reset the idle timer to zero
            // when sending a response or on receipt of a "full DNS message,
            // rather than on receipt of any part of a DNS message", i.e. idle
            // time from the server perspective is time spent without
            // receiving a request or sending a response.
            // TODO: timeout() at a point determined either since last send
            // or override it based on EDNS(0) timeout settings??? RFC 7828
            // section 3 says "This document specifies a new EDNS0 [RFC6891]
            // option, edns-tcp-keepalive, which can be used by DNS clients
            // and servers to signal a willingness to keep an idle TCP session
            // open to conduct future DNS transactions, with the idle timeout
            // being specified by the server. This specification does not
            // distinguish between different types of DNS client and server
            // in the use of this option. [RFC7766] defines an 'idle DNS-over-
            // TCP session' from both the client and server perspective.  The
            // idle timeout described here begins when the idle condition is
            // met per that definition and should be reset when that condition
            // is lifted, i.e., when a client sends a message or when a server
            // receives a message on an idle connection.". As the service
            // may receive requests out of order and at some arbitrary delay
            // caused by the async runtime the service is not best placed to
            // work out when the last request was fully received, except if
            // we give it those timestamps, and even then it isn't able to
            // determine at all when responses are actually written back to
            // the client because that is handled by us, not by the service.
            // So determining the moment at which a connection is idle has
            // to be done by us, but that determination may be influenced by
            // the service by telling us relevant information that it gleaned
            // from the DNS request message details such as EDNS(0) keep alive
            // values.
            let stream_read_fut = timeout(
                state.idle_time().to_std().unwrap(), // unwrap() here should never fail
                stream_rx.read_exact(buf.as_mut()),
            );
            let mut stream_read_fut = Box::pin(stream_read_fut);

            'while_not_read: loop {
                // This outer block ensures the mutable reference on command_rx is
                // dropped so that we can take another one below in order to call
                // command_rx.borrow_and_update().
                {
                    let command_read_fut = command_rx.changed();
                    let result_read_fut = result_q_rx.recv();
                    pin_mut!(command_read_fut);
                    pin_mut!(result_read_fut);

                    let action_read_fut =
                        select(command_read_fut, result_read_fut);

                    match select(action_read_fut, stream_read_fut).await {
                        Either::Left((
                            action,
                            incomplete_stream_read_fut,
                        )) => {
                            let action_res = self.process_action(action)?;
                            stream_read_fut = incomplete_stream_read_fut;

                            match action_res {
                                ProcessActionResult::CommandReceived => {
                                    // handle below to work around double use of &mut ref
                                }
                                ProcessActionResult::CallResultReceived(
                                    call_result,
                                ) => {
                                    self.apply_call_result(
                                        state,
                                        call_result,
                                    )
                                    .await;
                                    continue 'while_not_read;
                                }
                            }
                        }

                        // The stream read succeeded. Return to the caller so that it
                        // can process the bytes written to the buffer.
                        Either::Right((Ok(Ok(_size)), _)) => {
                            return Ok(ConnectionEvent::ReadSucceeded);
                        }

                        // The stream read failed. What kind of failure was it? Was it
                        // transient or permanent? For now assume that the stream can
                        // no longer be read from.
                        // TODO: Determine the various kinds of possible failure and
                        // handle them as appropriate.
                        Either::Right((Ok(Err(err)), _)) => {
                            match err.kind() {
                                io::ErrorKind::UnexpectedEof => {
                                    // The client disconnected. Per RFC 7766
                                    // 6.2.4 pending responses MUST NOT be
                                    // sent to the client.
                                    return Err(
                                        ConnectionEvent::DisconnectWithoutFlush,
                                    );
                                }
                                io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted => {
                                    // These errors might be recoverable, try again
                                    println!(
                                        "Warn: Stream read failed: {err}"
                                    );
                                    continue 'read;
                                }
                                _ => {
                                    // Everything else is either unrecoverable or
                                    // unknown to us at the time of writing and so
                                    // we can't guess how to handle it, so abort.
                                    eprintln!(
                                        "Error: Stream read failed: {err}"
                                    );
                                    return Err(
                                        ConnectionEvent::DisconnectWithoutFlush,
                                    );
                                }
                            }
                        }

                        // The stream read timed out.
                        // TODO: Determine what to do here.
                        // TODO: Per RFC 7766 6.1 "If the server needs to
                        // close a dormant connection to reclaim resources,
                        // it should wait until the connection has been idle
                        // for a period on the order of two minutes.  In
                        // particular, the server should allow the SOA and
                        // AXFR request sequence (which begins a refresh
                        // operation) to be made on a single connection."
                        // TODO: So should an idle determination actually be
                        // made in the service which as that is the layer at
                        // which we interpret DNS messages, rather than here
                        // where DNS message are just opaque byte sequences?
                        Either::Right((Err(_elapsed), _)) => {
                            eprintln!("Stream read timed out");
                            return Err(ConnectionEvent::DisconnectWithFlush);
                        }
                    }
                }

                // Process any command received from the parent server.
                let command = *command_rx.borrow_and_update();
                match command {
                    ServiceCommand::CloseConnection => unreachable!(),
                    ServiceCommand::Init => unreachable!(),
                    ServiceCommand::Reconfigure { idle_timeout } => {
                        eprintln!("Server connection timeout reconfigured to {idle_timeout:?}");
                        state.idle_timeout =
                            chrono::Duration::from_std(idle_timeout).unwrap();
                        // TOOD: Check this unwrap()
                    }
                    ServiceCommand::Shutdown => {
                        return Err(ConnectionEvent::DisconnectWithFlush);
                    }
                }
            }
        }
    }

    fn process_action<T, U, V>(
        &self,
        action: Either<
            (CommandNotification, U),
            (Option<CallResult<Svc::ResponseOctets>>, V),
        >,
    ) -> Result<
        ProcessActionResult<CallResult<Svc::ResponseOctets>>,
        ConnectionEvent<T>,
    > {
        match action {
            // The parent server sent us a command.
            Either::Left((
                Ok(_command_changed),
                _incomplete_call_result_fut,
            )) => Ok(ProcessActionResult::CommandReceived),

            // There was a problem receiving commands from the parent server.
            // This can happen if the command sender is dropped, i.e. the
            // parent server no longer exists but was not cleanly shutdown.
            Either::Left((Err(_err), _incomplete_call_result_fut)) => {
                return Err(ConnectionEvent::DisconnectWithFlush);
            }

            // It is no longer possible to read the results of requests
            // processed by the service because the queue holding those
            // results is empty and can no longer be read from. There is
            // no point continuing to read from the input stream because
            // we will not be able to access the result of processing the
            // request.
            // TODO: Describe when this can occur.
            Either::Right((None, _incomplete_command_changed_fut)) => {
                return Err(ConnectionEvent::DisconnectWithFlush);
            }

            // The service finished processing a request so apply the
            // call result to ourselves and/or the output stream. Then go
            // back to waiting for the stream read to complete or another
            // request to finish being processed.
            Either::Right((
                Some(call_result),
                _incomplete_command_changed_fut,
            )) => Ok(ProcessActionResult::CallResultReceived(call_result)),
        }
    }

    async fn process_message(
        &self,
        state: &StreamState<Listener, Buf, Svc>,
        buf: <Buf as BufSource>::Output,
        service: Arc<Svc>,
    ) -> Result<(), ServiceError<Svc::Error>> {
        use std::string::ToString;

        // TODO: Pass this out as a type rather than a string?
        let msg = Message::from_octets(buf)
            .map_err(|_| ServiceError::Other("short message".to_string()))?;

        let txn =
            service.call(msg /* also send requester address etc */)?;

        let metrics = self.metrics.clone();
        let tx = state.result_q_tx.clone();

        tokio::spawn(async move {
            metrics
                .num_inflight_requests
                .fetch_add(1, Ordering::Relaxed);
            match txn {
                Transaction::Single(call_fut) => {
                    if let Ok(call_result) = call_fut.await {
                        Self::handle_call_result(&tx, call_result, &metrics)
                            .await
                    }
                }

                Transaction::Stream(stream) => {
                    pin_mut!(stream);
                    while let Some(call_result) = stream.next().await {
                        match call_result {
                            Ok(call_result) => {
                                Self::handle_call_result(
                                    &tx,
                                    call_result,
                                    &metrics,
                                )
                                .await;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            metrics
                .num_inflight_requests
                .fetch_sub(1, Ordering::Relaxed);
        });

        Ok(())
    }

    async fn handle_call_result(
        tx: &mpsc::Sender<CallResult<Svc::ResponseOctets>>,
        mut call_result: CallResult<Svc::ResponseOctets>,
        metrics: &Arc<ServerMetrics>,
    ) {
        if let Some(response) = call_result.response() {
            let call_result = if let Some(command) = call_result.command() {
                CallResult::with_feedback(response, command)
            } else {
                CallResult::new(response)
            };

            if let Err(err) = tx.send(call_result).await {
                eprintln!(
                    "StreamServer: Error while queuing response: {err}"
                );
            }
            metrics
                .num_pending_writes
                .store(tx.max_capacity() - tx.capacity(), Ordering::Relaxed);
        }
    }

    async fn flush_write_queue(
        &self,
        state: &mut StreamState<Listener, Buf, Svc>,
        result_q_rx: &mut mpsc::Receiver<CallResult<Svc::ResponseOctets>>,
    ) {
        // Stop accepting new response messages (should we check
        // for in-flight messages that haven't generated a response
        // yet but should be allowed to do so?) so that we can flush
        // the write queue and exit this connection handler.
        result_q_rx.close();
        while let Some(call_result) = result_q_rx.recv().await {
            self.apply_call_result(state, call_result).await;
        }
    }

    async fn apply_call_result(
        &self,
        state: &mut StreamState<Listener, Buf, Svc>,
        mut call_result: CallResult<Svc::ResponseOctets>,
    ) {
        if let Some(msg) = call_result.response() {
            // TODO: spawn this as a task and serialize access to write with a lock?
            if let Err(err) =
                state.stream_tx.write_all(msg.as_stream_slice()).await
            {
                eprintln!("Write error: {err}");
                todo!()
            }
            state.response_queue_emptied();
            self.metrics
                .num_pending_writes
                .fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(cmd) = call_result.command() {
            match cmd {
                ServiceCommand::CloseConnection { .. } => todo!(),
                ServiceCommand::Init => todo!(),
                ServiceCommand::Reconfigure { idle_timeout } => {
                    eprintln!(
                        "Reconfigured connection timeout to {idle_timeout:?}"
                    );
                    state.idle_timeout =
                        chrono::Duration::from_std(idle_timeout).unwrap();
                    // TODO: Check this unwrap()
                }
                ServiceCommand::Shutdown => {
                    state.stream_tx.shutdown().await.unwrap()
                }
            }
        }
    }
}

impl<T, U, V, W, X, Y>
    From<(
        Either<(Result<(T, U), V>, W), (Result<(), X>, Y)>,
        watch::Receiver<ServiceCommand>,
    )> for ServerEvent<T, U, V, X>
{
    fn from(
        (value, mut command_rx): (
            Either<(Result<(T, U), V>, W), (Result<(), X>, Y)>,
            watch::Receiver<ServiceCommand>,
        ),
    ) -> Self {
        match value {
            Either::Left((Ok((stream, addr)), _)) => {
                ServerEvent::Accept(stream, addr)
            }
            Either::Left((Err(err), _)) => ServerEvent::AcceptError(err),
            Either::Right((Ok(()), _)) => {
                let cmd = *command_rx.borrow_and_update();
                ServerEvent::Command(cmd)
            }
            Either::Right((Err(err), _)) => ServerEvent::CommandError(err),
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

        fn _last_ready(&self) -> Option<Instant> {
            self.last_ready.lock().unwrap().clone()
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
            self.last_accept.lock().unwrap().clone()
        }

        fn streams_remaining(&self) -> usize {
            self.streams_to_read.lock().unwrap().len()
        }
    }

    impl AsyncAccept for MockListener {
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
            Poll::Ready(Ok(CallResult::with_feedback(
                StreamTarget::new_vec(),
                ServiceCommand::Reconfigure {
                    idle_timeout: Duration::from_millis(5000),
                },
            )))
        }
    }

    struct MyStream;

    impl Stream for MyStream {
        type Item = Result<CallResult<Vec<u8>>, ServiceError<()>>;

        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            todo!()
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

        type ResponseOctets = Vec<u8>;

        type Single = MySingle;

        type Stream = MyStream;

        fn call(
            &self,
            _msg: Message<Vec<u8>>,
            // TODO: pass other requestor address details e.g. IP address, port, etc.
        ) -> Result<
            Transaction<Self::Single, Self::Stream>,
            ServiceError<Self::Error>,
        > {
            Ok(Transaction::Single(MySingle))
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
            let listener =
                MockListener::new(streams_to_read, new_client_every);
            let ready_flag = listener.get_ready_flag();

            let buf = MockBufSource;
            let my_service = Arc::new(MyService::new());
            let srv = Arc::new(StreamServer::new(
                listener,
                buf,
                my_service.clone(),
            ));

            let metrics = srv.metrics.clone();
            let server_status_printer_handle = tokio::spawn(async move {
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

            let srv_handle = tokio::spawn(srv.clone().run());

            eprintln!("Clients sleeping");
            tokio::time::sleep(Duration::from_millis(1000)).await;

            eprintln!("Clients connecting");
            ready_flag.store(true, Ordering::Relaxed);

            // Simulate a wait long enough that all simulated clients had time
            // to connect, communicate and disconnect.
            tokio::time::sleep(Duration::from_millis(15000)).await;

            // Verify that all simulated clients connected.
            assert_eq!(0, srv.listener().streams_remaining());

            // Verify that no requests or responses are in progress still in
            // the server.
            assert_eq!(srv.metrics.num_connections(), Some(0));
            assert_eq!(srv.metrics.num_inflight_requests(), 0);
            assert_eq!(srv.metrics.num_pending_writes(), 0);

            eprint!("Shutting down");
            srv.shutdown().unwrap();
            eprintln!("Shutdown command sent");

            (srv_handle, server_status_printer_handle)
        };

        eprintln!("Waiting for service to shutdown");
        let _ = srv_handle.await;

        // Terminate the task that periodically prints the server status
        server_status_printer_handle.abort();
    }
}
