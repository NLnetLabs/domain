use super::buf::BufSource;
use super::server::ServerMetrics;
use super::service::{CallResult, Service, Transaction};

use std::{boxed::Box, io, sync::Mutex, time::Duration};
use std::{
    future::poll_fn,
    sync::atomic::{AtomicUsize, Ordering},
};

use std::sync::Arc;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use futures::{
    future::{select, Either},
    pin_mut,
};

use tokio::sync::watch::error::RecvError;
use tokio::{
    io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf,
        WriteHalf,
    },
    sync::{mpsc, watch},
    time::timeout,
};

use crate::base::Message;

use super::{
    service::{ServiceCommand, ServiceError},
    sock::AsyncAccept,
};

//------------ StreamServer --------------------------------------------------

pub struct StreamServer<Listener, Buf, Svc> {
    command_rx: watch::Receiver<ServiceCommand>,
    command_tx: Arc<Mutex<watch::Sender<ServiceCommand>>>,
    listener: Arc<Listener>,
    buf: Arc<Buf>,
    service: Arc<Svc>,
    metrics: Arc<ServerMetrics>,
}

impl<Listener, Buf, Svc> StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    pub fn new(listener: Listener, buf: Arc<Buf>, service: Arc<Svc>) -> Self {
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
            buf,
            service,
            metrics,
        }
    }

    pub fn listener(&self) -> Arc<Listener> {
        self.listener.clone()
    }

    pub fn metrics(&self) -> Arc<ServerMetrics> {
        self.metrics.clone()
    }

    pub fn shutdown(
        &self,
    ) -> Result<(), watch::error::SendError<ServiceCommand>> {
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
                StreamServerEvent::Accept(stream, _addr) => {
                    let conn_command_rx = self.command_rx.clone();
                    let conn_service = self.service.clone();
                    let conn_buf = self.buf.clone();
                    let conn_metrics = self.metrics.clone();
                    let conn_fut = async move {
                        if let Ok(stream) = stream.await {
                            let conn = ConnectedStream::<
                                Listener::StreamType,
                                Buf,
                                Svc,
                            >::new(
                                conn_service,
                                conn_buf,
                                conn_metrics,
                                stream,
                            );
                            conn.run(conn_command_rx).await
                        }
                    };
                    tokio::spawn(conn_fut);
                }

                StreamServerEvent::AcceptError(err) => {
                    eprintln!(
                        "Error while accepting stream connections: {err}"
                    );
                    todo!()
                }

                StreamServerEvent::Command(ServiceCommand::Init) => {
                    unreachable!()
                }

                StreamServerEvent::Command(ServiceCommand::Reconfigure {
                    ..
                }) => { /* TO DO */ }

                StreamServerEvent::Command(
                    ServiceCommand::CloseConnection { .. },
                ) => unreachable!(),

                StreamServerEvent::Command(ServiceCommand::Shutdown) => {
                    return Ok(());
                }

                StreamServerEvent::CommandError(err) => {
                    eprintln!("Error while processing command: {err}");
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

//------------ ConnectedStream -----------------------------------------------

struct ConnectedStream<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    buf_source: Arc<Buf>,
    metrics: Arc<ServerMetrics>,
    service: Arc<Svc>,
    stream: Option<Stream>,
}

impl<Stream, Buf, Svc> ConnectedStream<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    fn new(
        service: Arc<Svc>,
        buf_source: Arc<Buf>,
        metrics: Arc<ServerMetrics>,
        stream: Stream,
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
        stream: Stream,
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
                match err {
                    ConnectionEvent::DisconnectWithoutFlush => {
                        break;
                    }
                    ConnectionEvent::DisconnectWithFlush => {
                        self.flush_write_queue(&mut state, &mut result_q_rx)
                            .await;
                        break;
                    }
                    ConnectionEvent::ReadSucceeded => unreachable!(),
                    ConnectionEvent::ServiceError(err) => {
                        eprintln!("Service error: {}", err);
                    }
                }
            }
        }
    }

    async fn transceive_one_request(
        &self,
        command_rx: &mut watch::Receiver<ServiceCommand>,
        state: &mut StreamState<Stream, Buf, Svc>,
        stream_rx: &mut ReadHalf<Stream>,
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
        state: &mut StreamState<Stream, Buf, Svc>,
        stream_rx: &mut ReadHalf<Stream>,
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
            let stream_read_fut = timeout(
                state.timeout_at_std(),
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
                                    self.write_queued_result(
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
                                    eprintln!(
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
                    ServiceCommand::CloseConnection => {
                        unreachable!()
                    }
                    ServiceCommand::Init => {
                        unreachable!()
                    }
                    ServiceCommand::Reconfigure { idle_timeout } => {
                        // Support RFC 7828 "The edns-tcp-keepalive EDNS0
                        // Option". This cannot be done by the caller as it
                        // requires knowing (a) when the last message was
                        // received and (b) when all pending messages have
                        // been sent, neither of which is known to the caller.
                        // However we also don't want to parse and understand
                        // DNS messages in this layer, it is left to the
                        // caller to process received messages and construct
                        // appropriate responses. If the caller detects an
                        // EDNS0 edns-tcp-keepalive option it can use this
                        // reconfigure mechanism to signal to us that we
                        // should adjust the point at which we will consider
                        // the connectin to be idle and thus potentially
                        // worthy of timing out.
                        eprintln!("Server connection timeout reconfigured to {idle_timeout:?}");
                        if let Ok(timeout) =
                            chrono::Duration::from_std(idle_timeout)
                        {
                            state.idle_timeout = timeout;
                        }
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
        state: &StreamState<Stream, Buf, Svc>,
        buf: <Buf as BufSource>::Output,
        service: Arc<Svc>,
    ) -> Result<(), ServiceError<Svc::Error>> {
        let msg = Message::from_octets(buf)
            .map_err(|_| ServiceError::Other("short message".into()))?;

        let metrics = self.metrics.clone();
        let tx = state.result_q_tx.clone();
        let txn = service.call(msg /* also send client addr */)?;

        tokio::spawn(async move {
            // TODO: Shouldn't this counter be incremented just before
            // service.call() is invoked?
            metrics
                .num_inflight_requests
                .fetch_add(1, Ordering::Relaxed);
            match txn {
                Transaction::Single(call_fut) => {
                    if let Ok(call_result) = call_fut.await {
                        Self::enqueue_call_result(&tx, call_result, &metrics)
                            .await
                    }
                }

                Transaction::Stream(stream) => {
                    pin_mut!(stream);
                    while let Some(call_result) = stream.next().await {
                        match call_result {
                            Ok(call_result) => {
                                Self::enqueue_call_result(
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

    async fn enqueue_call_result(
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
        state: &mut StreamState<Stream, Buf, Svc>,
        result_q_rx: &mut mpsc::Receiver<CallResult<Svc::ResponseOctets>>,
    ) {
        // Stop accepting new response messages (should we check
        // for in-flight messages that haven't generated a response
        // yet but should be allowed to do so?) so that we can flush
        // the write queue and exit this connection handler.
        result_q_rx.close();
        while let Some(call_result) = result_q_rx.recv().await {
            self.write_queued_result(state, call_result).await;
        }
    }

    async fn write_queued_result(
        &self,
        state: &mut StreamState<Stream, Buf, Svc>,
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
            if state.result_q_tx.capacity()
                == state.result_q_tx.max_capacity()
            {
                state.response_queue_emptied();
            }
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

//------------ StreamServerEvent ---------------------------------------------

pub enum StreamServerEvent<Stream, Addr, AcceptErr, CommandErr> {
    Accept(Stream, Addr),
    AcceptError(AcceptErr),
    Command(ServiceCommand),
    CommandError(CommandErr),
}

//------------ ConnectionEvent -----------------------------------------------

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

//------------ StreamState ---------------------------------------------------

pub struct StreamState<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    stream_tx: WriteHalf<Stream>,

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
    //
    idle_timer_reset_at: DateTime<Utc>,

    idle_timeout: chrono::Duration,
}

impl<Stream, Buf, Svc> StreamState<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    fn new(
        stream_tx: WriteHalf<Stream>,
        result_q_tx: mpsc::Sender<CallResult<Svc::ResponseOctets>>,
        idle_timeout: chrono::Duration,
    ) -> Self {
        Self {
            stream_tx,
            result_q_tx,
            idle_timer_reset_at: Utc::now(),
            idle_timeout,
        }
    }

    /// How long from now should this connection be timed out?
    ///
    /// When we (will) have been sat idle for longer than the configured idle
    /// timeout for this connection.
    pub fn timeout_at(&self) -> chrono::Duration {
        self.idle_timeout
            .checked_sub(&self.idle_time())
            .unwrap_or(chrono::Duration::zero())
    }

    pub fn timeout_at_std(&self) -> Duration {
        self.timeout_at().to_std().unwrap_or_default()
    }

    /// How long has this connection been sat idle?
    pub fn idle_time(&self) -> chrono::Duration {
        Utc::now().signed_duration_since(self.idle_timer_reset_at)
    }

    fn reset_idle_timer(&mut self) {
        self.idle_timer_reset_at = Utc::now()
    }

    fn full_msg_received(&mut self) {
        // RFC 7766 6.2.3: "DNS messages delivered over TCP might arrive in
        // multiple segments.  A DNS server that resets its idle timeout after
        // receiving a single segment might be vulnerable to a "slow-read
        // attack". For this reason, servers SHOULD reset the idle timeout on
        // the receipt of a full DNS message, rather than on receipt of any
        // part of a DNS message."
        self.reset_idle_timer()
    }

    fn response_queue_emptied(&mut self) {
        // RFC 7766 3: "A DNS server considers an established DNS-over-TCP
        // session to be idle when it has sent responses to all the queries it
        // has received on that connection."
        self.reset_idle_timer()
    }
}

//------------ From ... for StreamServerEvent --------------------------------

// Used by StreamServer::run() via select(..).await.into() to make the match
// arms more readable.
impl<Stream, Addr, AcceptErr, W, CommandErr, Y>
    From<(
        Either<
            (Result<(Stream, Addr), AcceptErr>, W),
            (Result<(), CommandErr>, Y),
        >,
        watch::Receiver<ServiceCommand>,
    )> for StreamServerEvent<Stream, Addr, AcceptErr, CommandErr>
{
    fn from(
        (value, mut command_rx): (
            Either<
                (Result<(Stream, Addr), AcceptErr>, W),
                (Result<(), CommandErr>, Y),
            >,
            watch::Receiver<ServiceCommand>,
        ),
    ) -> Self {
        match value {
            Either::Left((Ok((stream, addr)), _)) => {
                StreamServerEvent::Accept(stream, addr)
            }
            Either::Left((Err(err), _)) => {
                StreamServerEvent::AcceptError(err)
            }
            Either::Right((Ok(()), _)) => {
                let cmd = *command_rx.borrow_and_update();
                StreamServerEvent::Command(cmd)
            }
            Either::Right((Err(err), _)) => {
                StreamServerEvent::CommandError(err)
            }
        }
    }
}

//------------ ProcessActionResult -------------------------------------------

enum ProcessActionResult<T> {
    CommandReceived,
    CallResultReceived(T),
}

//------------ CommandNotification -------------------------------------------

type CommandNotification = Result<(), RecvError>;
