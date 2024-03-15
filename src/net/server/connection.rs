use core::fmt::{Debug, Display};
use core::ops::{ControlFlow, Deref};
use core::sync::atomic::Ordering;
use core::time::Duration;

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use octseq::Octets;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::Sender;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio::time::{sleep_until, timeout};
use tracing::Level;
use tracing::{debug, enabled, error, trace, warn};

use crate::base::{Message, StreamTarget};
use crate::net::server::buf::BufSource;
use crate::net::server::message::MessageProcessor;
use crate::net::server::message::Request;
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::middleware::chain::MiddlewareChain;
use crate::net::server::service::{
    CallResult, Service, ServiceError, ServiceFeedback,
};
use crate::net::server::util::to_pcap_text;
use crate::utils::config::DefMinMax;

use super::message::{
    MessageDetails, NonUdpTransportContext, TransportSpecificContext,
};
use super::middleware::builder::MiddlewareBuilder;
use super::service::ServerCommand;
use super::stream::Config as ServerConfig;

/// Limit on the amount of time to allow between client requests.
///
/// According to [RFC 7766]:
/// - "A timeout of at least a few seconds is advisable for normal
///   operations".
/// - "Servers MAY use zero timeouts when they are experiencing heavy load or
///    are under attack".
/// - "Servers MAY allow idle connections to remain open for longer periods as
///   resources permit".
///
/// The value has to be between zero and 30 days with a default of 30 seconds.
/// The default and minimum values are the same as those of the Unbound 1.19.2
/// `tcp-idle-timeout` configuration setting. The upper bound is a guess at
/// something reasonable.
///
/// [RFC 7766]: https://datatracker.ietf.org/doc/html/rfc7766#section-6.2.3
//
// Note: Unbound 1.19.2 has another setting, edns-tcp-keepalive-timeout,
// which if set and edns-tcp-keepalive is set to yes, then Unbound has a
// default timeout value of 2 minutes instead of 30 seconds. Internally both
// Unbound options configure the same timeout limit, the tcp-idle-timeout
// setting may exist for backward compatibility. TO DO: Should we increase
// the default timeout value to 2 minutes instead of 30 seconds?
const IDLE_TIMEOUT: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(30),
    Duration::from_millis(200),
    Duration::from_secs(30 * 24 * 60 * 60),
);

/// Limit on the amount of time to wait for writing a response to complete.
///
/// The value has to be between 1 millisecond and 1 hour with a default of 30
/// seconds. These values are guesses at something reasonable. The default is
/// based on the Unbound 1.19.2 default value for its `tcp-idle-timeout`
/// setting.
const RESPONSE_WRITE_TIMEOUT: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(30),
    Duration::from_millis(1),
    Duration::from_secs(60 * 60),
);

/// Limit on the number of DNS responses queued for writing to the client.
///
/// The value has to be between zero and 1,024. The default value is 10. These
/// numbers are just a guess at something reasonable.
///
/// If the limit is hit handling of client requests will block until space
/// becomes available.
const MAX_QUEUED_RESPONSES: DefMinMax<usize> = DefMinMax::new(10, 0, 1024);

//----------- Config ---------------------------------------------------------

/// Configuration for a stream server connection.
pub struct Config<Buf, Svc>
where
    Buf: BufSource,
    Svc: Service<Buf::Output>,
{
    /// Limit on the amount of time to allow between client requests.
    ///
    /// This setting can be overridden on a per connection basis by a
    /// [`Service`] by returning a [`ServerCommand::Reconfigure`] command
    /// with a response message, for example to adjust it per [RFC 7828]
    /// section 3.3.1 "Receivomg queries" which says:
    ///
    ///   A DNS server that receives a query using TCP transport that includes
    ///   the edns-tcp-keepalive option MAY modify the local idle timeout
    ///   associated with that TCP session if resources permit. idle_timeout:
    ///   Duration,
    ///
    /// [RFC 7828]: https://datatracker.ietf.org/doc/html/rfc7828#section-3.3.1
    idle_timeout: Duration,

    /// Limit on the amount of time to wait for writing a response to
    /// complete.
    ///
    /// The value has to be between 1 millisecond and 1 hour with a default of
    /// 30 seconds. These values are guesses at something reasonable. The
    /// default is based on the Unbound 1.19.2 default value for its
    /// `tcp-idle-timeout` setting.
    response_write_timeout: Duration,

    /// Limit on the number of DNS responses queued for wriing to the client.
    max_queued_responses: usize,

    /// The middleware chain used to pre-process requests and post-process
    /// responses.
    middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
}

impl<Buf, Svc> Config<Buf, Svc>
where
    Buf: BufSource,
    Buf::Output: Octets,
    Svc: Service<Buf::Output>,
{
    /// Creates a new, default config.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the limit on the amount of time to allow between client requests.
    ///
    /// According to [RFC 7766]:
    /// - "A timeout of at least a few seconds is advisable for normal
    ///   operations".
    /// - "Servers MAY use zero timeouts when they are experiencing heavy load
    ///    or are under attack".
    /// - "Servers MAY allow idle connections to remain open for longer
    ///   periods as resources permit".
    ///
    /// The value has to be between zero and 30 days with a default of 30
    /// seconds. The default and minimum values are the same as those of the
    /// Unbound 1.19.2 `tcp-idle-timeout` configuration setting. The upper
    /// bound is a guess at something reasonable.
    ///
    /// [RFC 7766]:
    ///     https://datatracker.ietf.org/doc/html/rfc7766#section-6.2.3
    #[allow(dead_code)]
    pub fn set_idle_timeout(&mut self, value: Duration) {
        self.idle_timeout = value;
    }

    /// Set the limit on the amount of time to wait for writing a response to
    /// complete.
    ///
    /// The value has to be between 1 millisecond and 1 hour with a default of
    /// 30 seconds. These values are guesses at something reasonable. The
    /// default is based on the Unbound 1.19.2 default value for its
    /// `tcp-idle-timeout` setting.
    #[allow(dead_code)]
    pub fn set_response_write_timeout(&mut self, value: Duration) {
        self.response_write_timeout = value;
    }

    /// Set the limit on the number of DNS responses queued for writing to the
    /// client.
    ///
    /// The value has to be between zero and 1,024. The default value is 10.
    /// These numbers are just a guess at something reasonable.
    ///
    /// DNS response messages will be discarded if they cannot be queued for
    /// sending because the queue is full.
    #[allow(dead_code)]
    pub fn set_max_queued_responses(&mut self, value: usize) {
        self.max_queued_responses = value;
    }

    /// Set the middleware chain used to pre-process requests and post-process
    /// responses.
    pub fn set_middleware_chain(
        &mut self,
        value: MiddlewareChain<Buf::Output, Svc::Target>,
    ) {
        self.middleware_chain = value;
    }
}

//--- Default

impl<Buf, Svc> Default for Config<Buf, Svc>
where
    Buf: BufSource,
    Buf::Output: Octets,
    Svc: Service<Buf::Output>,
{
    fn default() -> Self {
        Self {
            idle_timeout: IDLE_TIMEOUT.default(),
            response_write_timeout: RESPONSE_WRITE_TIMEOUT.default(),
            max_queued_responses: MAX_QUEUED_RESPONSES.default(),
            middleware_chain: MiddlewareBuilder::default().build(),
        }
    }
}

//--- Clone

impl<Buf, Svc> Clone for Config<Buf, Svc>
where
    Buf: BufSource,
    Buf::Output: Octets,
    Svc: Service<Buf::Output>,
{
    fn clone(&self) -> Self {
        Self {
            idle_timeout: self.idle_timeout,
            response_write_timeout: self.response_write_timeout,
            max_queued_responses: self.max_queued_responses,
            middleware_chain: self.middleware_chain.clone(),
        }
    }
}

//------------ Connection -----------------------------------------------

pub struct Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + Clone + 'static,
    Buf::Output: Send + Sync,
    Svc: Service<Buf::Output> + Send + Sync + Clone + 'static,
{
    active: bool,
    addr: SocketAddr,
    buf_source: Buf,
    config: Config<Buf, Svc>,
    metrics: Arc<ServerMetrics>,
    result_q_rx: mpsc::Receiver<CallResult<Buf::Output, Svc::Target>>,
    service: Svc,
    state: StreamState<Stream, Buf, Svc>,
    stream_rx: Option<ReadHalf<Stream>>,
}

/// Creation
///
impl<Stream, Buf, Svc> Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + Clone + 'static,
    Buf::Output: Octets + Send + Sync,
    Svc: Service<Buf::Output> + Send + Sync + Clone + 'static,
{
    #[must_use]
    #[allow(dead_code)]
    pub fn new(
        service: Svc,
        buf_source: Buf,
        metrics: Arc<ServerMetrics>,
        stream: Stream,
        addr: SocketAddr,
    ) -> Self {
        Self::with_config(
            service,
            buf_source,
            metrics,
            stream,
            addr,
            Config::default(),
        )
    }

    #[must_use]
    pub fn with_config(
        service: Svc,
        buf_source: Buf,
        metrics: Arc<ServerMetrics>,
        stream: Stream,
        addr: SocketAddr,
        config: Config<Buf, Svc>,
    ) -> Self {
        let (stream_rx, stream_tx) = tokio::io::split(stream);
        let (result_q_tx, result_q_rx) =
            mpsc::channel(config.max_queued_responses);
        let state = StreamState::new(stream_tx, result_q_tx);

        // Place the ReadHalf of the stream into an Option so that we can take
        // it out (as we can't clone it and we can't place it into an Arc
        // (even though it is Send and Sync) because AsyncRead::poll_read()
        // takes Pin<&mut Self> which can't be obtained from an Arc without
        // having the only Arc). We want to take it out so that we can use it
        // without taking a reference to self as that conflicts with other
        // uses of self we have to do while running.
        let stream_rx = Some(stream_rx);

        Self {
            active: false,
            addr,
            buf_source,
            config,
            result_q_rx,
            service,
            metrics,
            state,
            stream_rx,
        }
    }
}

/// Control
///
impl<Stream, Buf, Svc> Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    /// Start reading requests and writing responses to the stream.
    ///
    /// # Shutdown behaviour
    ///
    /// When the parent server is shutdown (explicitly or via Drop) the child
    /// connections will also see the [`ServerCommand::Shutdown`] signal and
    /// shutdown and flush any pending writes to the output stream.
    ///
    /// Any requests received after the shutdown signal or requests still
    /// in-flight will be abandoned.
    ///
    /// TODO: What does "abandoned" mean in practice here?
    pub async fn run(
        mut self,
        command_rx: watch::Receiver<ServerCommand<ServerConfig<Buf, Svc>>>,
    ) where
        Svc::Future: Send,
    {
        self.metrics
            .num_connections
            .as_ref()
            .unwrap()
            .fetch_add(1, Ordering::Relaxed);

        // Flag that we have to decrease the metric count on Drop.
        self.active = true;

        self.run_until_error(command_rx).await;
    }
}

//--- Internal details

impl<Stream, Buf, Svc> Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    async fn run_until_error(
        mut self,
        mut command_rx: watch::Receiver<
            ServerCommand<ServerConfig<Buf, Svc>>,
        >,
    ) where
        Svc::Future: Send,
    {
        let stream_rx = self.stream_rx.take().unwrap();
        let mut dns_msg_receiver =
            DnsMessageReceiver::new(self.buf_source.clone(), stream_rx);

        'outer: loop {
            // Create a read future that will survive when other
            // tokio::select! branches resolve before the branch awaiting this
            // future resolves. This ensures that in-progress non-cancel-safe
            // reads do not get cancelled. This works because it
            // avoids creating a new future each time as would happen if we
            // called transceive() in a tokio::select! branch.
            let msg_recv = dns_msg_receiver.recv();
            tokio::pin!(msg_recv);

            'inner: loop {
                let res = tokio::select! {
                    biased;

                    res = command_rx.changed() => {
                        self.process_service_command(res, &mut command_rx)
                    }

                    res = self.result_q_rx.recv() => {
                        self.process_queued_result(res).await
                    }

                    _ = sleep_until(self.state.idle_timeout_deadline(self.config.idle_timeout)) => {
                        self.process_dns_idle_timeout()
                    }

                    res = &mut msg_recv => {
                        let res = self.process_read_result(res).await;
                        if res.is_ok() {
                            // Set up to receive another message
                            break 'inner;
                        } else {
                            res
                        }
                    }
                };

                if let Err(err) = res {
                    match err {
                        ConnectionEvent::DisconnectWithoutFlush => {
                            break 'outer;
                        }
                        ConnectionEvent::DisconnectWithFlush => {
                            self.flush_write_queue().await;
                            break 'outer;
                        }
                        ConnectionEvent::ServiceError(err) => {
                            error!("Service error: {}", err);
                        }
                    }
                }
            }
        }

        trace!("Shutting down the write stream.");
        if let Err(err) = self.state.stream_tx.shutdown().await {
            warn!("Error while shutting down the write stream: {err}");
        }
        trace!("Connection terminated.");

        #[cfg(test)]
        if dns_msg_receiver.cancelled() {
            panic!("Async not-cancel-safe code was cancelled");
        }
    }

    fn process_service_command(
        &mut self,
        res: Result<(), watch::error::RecvError>,
        command_rx: &mut watch::Receiver<
            ServerCommand<ServerConfig<Buf, Svc>>,
        >,
    ) -> Result<(), ConnectionEvent> {
        // If the parent server no longer exists but was not cleanly shutdown
        // then the command channel will be closed and attempting to check for
        // a new command will fail. Advise the caller to break the connection
        // and cleanup if such a problem occurs.
        res.map_err(|_err| ConnectionEvent::DisconnectWithFlush)?;

        // Get the changed command.
        let lock = command_rx.borrow_and_update();
        let command = lock.deref();

        // And process it.
        match command {
            ServerCommand::Init => {
                // The initial "Init" value in the watch channel is never
                // actually seen because changed() is required to return true
                // before we call borrow_and_update() but the initial value in
                // the channel, Init, is not considered a "change". So the
                // only way to end up here would be if we somehow wrongly
                // placed another ServerCommand::Init value into the watch
                // channel after the initial one.
                unreachable!()
            }

            ServerCommand::CloseConnection => {
                // TODO: Should we flush in this case or not?
                return Err(ConnectionEvent::DisconnectWithFlush);
            }

            ServerCommand::Reconfigure(ServerConfig {
                connection_config:
                    Config {
                        idle_timeout,
                        response_write_timeout,
                        max_queued_responses: _, // TO DO: Cannot be changed?
                        middleware_chain: _,     // TO DO
                    },
                .. // Ignore the Server configuration settings
            }) => {
                // Support RFC 7828 "The edns-tcp-keepalive EDNS0 Option".
                // This cannot be done by the caller as it requires knowing
                // (a) when the last message was received and (b) when all
                // pending messages have been sent, neither of which is known
                // to the caller. However we also don't want to parse and
                // understand DNS messages in this layer, it is left to the
                // caller to process received messages and construct
                // appropriate responses. If the caller detects an EDNS0
                // edns-tcp-keepalive option it can use this reconfigure
                // mechanism to signal to us that we should adjust the point
                // at which we will consider the connectin to be idle and thus
                // potentially worthy of timing out.
                debug!("Server connection timeout reconfigured to {idle_timeout:?}");
                self.config.idle_timeout = *idle_timeout;
                self.config.response_write_timeout = *response_write_timeout;

                // TODO: Support dynamic replacement of the middleware chain?
                // E.g. via ArcSwapOption<MiddlewareChain> instead of Option?
            }

            ServerCommand::Shutdown => {
                // The parent server has been shutdown. Close this connection
                // but ensure that we write any pending responses to the
                // stream first.
                //
                // TODO: Should we also wait for any in-flight requests to
                // complete before shutting down? And if so how should we
                // respond to any requests received in the meantime? Should we
                // even stop reading from the stream?
                return Err(ConnectionEvent::DisconnectWithFlush);
            }
        }

        Ok(())
    }

    async fn flush_write_queue(&mut self) {
        debug!("Flushing connection write queue.");
        // Stop accepting new response messages (should we check for in-flight
        // messages that haven't generated a response yet but should be
        // allowed to do so?) so that we can flush the write queue and exit
        // this connection handler.
        trace!("Stop queueing up new results.");
        self.result_q_rx.close();
        trace!("Process already queued results.");
        while let Some(call_result) = self.result_q_rx.recv().await {
            trace!("Processing queued result.");
            if let Err(err) =
                self.process_queued_result(Some(call_result)).await
            {
                warn!("Error while processing queued result: {err}");
            } else {
                trace!("Result processed");
            }
        }
        debug!("Connection write queue flush complete.");
    }

    async fn process_queued_result(
        &mut self,
        call_result: Option<CallResult<Buf::Output, Svc::Target>>,
    ) -> Result<(), ConnectionEvent> {
        // If we failed to read the results of requests processed by the
        // service because the queue holding those results is empty and can no
        // longer be read from, then there is no point continuing to read from
        // the input stream because we will not be able to access the result
        // of processing the request.
        // TODO: Describe when this can occur.
        let Some(call_result) = call_result else {
            return Err(ConnectionEvent::DisconnectWithFlush);
        };

        let (_request, response, feedback) = call_result.into_inner();

        if let Some(feedback) = feedback {
            self.act_on_feedback(feedback).await;
        }

        if let Some(response) = response {
            self.write_result_to_stream(response.finish()).await;
        }

        Ok(())
    }

    async fn write_result_to_stream(
        &mut self,
        msg: StreamTarget<Svc::Target>,
    ) {
        if enabled!(Level::TRACE) {
            let bytes = msg.as_dgram_slice();
            let pcap_text = to_pcap_text(bytes, bytes.len());
            trace!(addr = %self.addr, pcap_text, "Sending response");
        }

        match timeout(
            self.config.response_write_timeout,
            self.state.stream_tx.write_all(msg.as_stream_slice()),
        )
        .await
        {
            Err(_) => {
                error!(
                    "Write timed out (>{:?})",
                    self.config.response_write_timeout
                );
                // TODO: Push it to the back of the queue to retry it?
            }
            Ok(Err(err)) => {
                error!("Write error: {err}");
            }
            Ok(Ok(_)) => {
                self.metrics
                    .num_sent_responses
                    .fetch_add(1, Ordering::Relaxed);
            }
        }

        self.metrics
            .num_pending_writes
            .fetch_sub(1, Ordering::Relaxed);

        if self.state.result_q_tx.capacity()
            == self.state.result_q_tx.max_capacity()
        {
            self.state.response_queue_emptied();
        }
    }

    async fn act_on_feedback(&mut self, cmd: ServiceFeedback) {
        match cmd {
            ServiceFeedback::CloseConnection => {
                self.state.stream_tx.shutdown().await.unwrap()
            }

            ServiceFeedback::Reconfigure { idle_timeout } => {
                debug!("Reconfigured connection timeout to {idle_timeout:?}");
                self.config.idle_timeout = idle_timeout;
            }

            ServiceFeedback::Shutdown => {}
        }
    }

    fn process_dns_idle_timeout(&self) -> Result<(), ConnectionEvent> {
        // DNS idle timeout elapsed, or was it reset?
        if self.state.idle_timeout_expired(self.config.idle_timeout) {
            Err(ConnectionEvent::DisconnectWithoutFlush)
        } else {
            Ok(())
        }
    }

    async fn process_read_result(
        &mut self,
        res: Result<Buf::Output, ConnectionEvent>,
    ) -> Result<(), ConnectionEvent> {
        res.and_then(|msg| {
            let received_at = Instant::now();

            if enabled!(Level::TRACE) {
                let pcap_text = to_pcap_text(&msg, msg.as_ref().len());
                trace!(addr = %self.addr, pcap_text, "Received message");
            }

            self.metrics
                .num_received_requests
                .fetch_add(1, Ordering::Relaxed);

            // Message received, reset the DNS idle timer
            self.state.full_msg_received();

            let msg_details =
                MessageDetails::new(msg, received_at, self.addr);

            // Process the received message
            self.process_request(
                msg_details,
                self.state.result_q_tx.clone(),
                self.config.middleware_chain.clone(),
                &self.service,
                self.metrics.clone(),
            )
            .map_err(ConnectionEvent::ServiceError)
        })
    }
}

//--- Drop

impl<Stream, Buf, Svc> Drop for Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync,
    Buf: BufSource + Send + Sync + Clone,
    Buf::Output: Send + Sync,
    Svc: Service<Buf::Output> + Send + Sync + Clone,
{
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            self.metrics
                .num_connections
                .as_ref()
                .unwrap()
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

//--- MessageProcessor

impl<Stream, Buf, Svc> MessageProcessor<Buf, Svc>
    for Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync,
    Buf: BufSource + Send + Sync + Clone,
    Buf::Output: Octets + Send + Sync,
    Svc: Service<Buf::Output> + Send + Sync + Clone,
{
    type State = Sender<CallResult<Buf::Output, Svc::Target>>;

    fn add_context_to_request(
        &self,
        request: Message<Buf::Output>,
        received_at: Instant,
        addr: SocketAddr,
    ) -> Request<Message<Buf::Output>> {
        let ctx = TransportSpecificContext::NonUdp(NonUdpTransportContext {
            idle_timeout: Some(self.config.idle_timeout),
        });
        Request::new(addr, received_at, request, ctx)
    }

    fn process_call_result(
        call_result: CallResult<Buf::Output, Svc::Target>,
        _addr: SocketAddr,
        tx: Self::State,
        metrics: Arc<ServerMetrics>,
    ) {
        // We can't send in a spawned async task as then we would just
        // accumlate tasks even if the target queue is full. We can't call
        // `tx.blocking_send()` as that would block the Tokio runtime. So
        // instead we try and send and if that fails because the queue is full
        // then we abort.
        match tx.try_send(call_result) {
            Ok(()) => {
                metrics.num_pending_writes.store(
                    tx.max_capacity() - tx.capacity(),
                    Ordering::Relaxed,
                );
            }

            Err(TrySendError::Closed(_msg)) => {
                // TODO: How should we properly communicate this to the operator?
                error!("StreamServer: Unable to queue message for sending: server is shutting down.");
            }

            Err(TrySendError::Full(_msg)) => {
                // TODO: How should we properly communicate this to the operator?
                error!("StreamServer: Unable to queue message for sending: queue is full.");
            }
        }
    }
}

//----------- DnsMessageReceiver ---------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Status {
    New,
    WaitingForMessageHeader,
    WaitingForMessageBody,
    MessageReceived,
}

struct DnsMessageReceiver<Stream, Buf>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
{
    msg_size_buf: [u8; 2],
    buf_source: Buf,
    stream_rx: ReadHalf<Stream>,
    status: Status,
    #[cfg(test)]
    cancelled: bool,
}

impl<Stream, Buf> DnsMessageReceiver<Stream, Buf>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
{
    fn new(buf_source: Buf, stream_rx: ReadHalf<Stream>) -> Self {
        Self {
            msg_size_buf: [0; 2],
            buf_source,
            stream_rx,
            status: Status::New,
            #[cfg(test)]
            cancelled: false,
        }
    }

    #[cfg(test)]
    pub fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// Receive a single DNS message.
    ///
    /// # Cancel safety
    ///
    /// This function is NOT cancel safe.
    pub async fn recv(&mut self) -> Result<Buf::Output, ConnectionEvent> {
        #[cfg(test)]
        if self.status == Status::WaitingForMessageBody {
            self.cancelled = true;
        }

        self.status = Status::WaitingForMessageHeader;
        Self::recv_n_bytes(&mut self.stream_rx, &mut self.msg_size_buf)
            .await?;

        let msg_len = u16::from_be_bytes(self.msg_size_buf) as usize;
        let mut msg_buf = self.buf_source.create_sized(msg_len);

        self.status = Status::WaitingForMessageBody;
        Self::recv_n_bytes(&mut self.stream_rx, &mut msg_buf).await?;

        self.status = Status::MessageReceived;
        Ok(msg_buf)
    }

    /// Receive exactly as many bytes as the given buffer can hold.
    ///
    /// # Cancel safety
    ///
    /// This function is NOT cancel safe.
    async fn recv_n_bytes<T: AsMut<[u8]>>(
        stream_rx: &mut ReadHalf<Stream>,
        buf: &mut T,
    ) -> Result<(), ConnectionEvent> {
        loop {
            match stream_rx.read_exact(buf.as_mut()).await {
                // The stream read succeeded. Return to the caller
                // so that it can process the bytes written to the
                // buffer.
                Ok(_size) => return Ok(()),

                Err(err) => match Self::process_io_error(err) {
                    ControlFlow::Continue(_) => continue,
                    ControlFlow::Break(err) => return Err(err),
                },
            }
        }
    }

    #[must_use]
    fn process_io_error(err: io::Error) -> ControlFlow<ConnectionEvent> {
        match err.kind() {
            io::ErrorKind::UnexpectedEof => {
                // The client disconnected. Per RFC 7766 6.2.4 pending
                // responses MUST NOT be sent to the client.
                error!("I/O error: {}", err);
                ControlFlow::Break(ConnectionEvent::DisconnectWithoutFlush)
            }
            io::ErrorKind::TimedOut | io::ErrorKind::Interrupted => {
                // These errors might be recoverable, try again.
                ControlFlow::Continue(())
            }
            _ => {
                // Everything else is either unrecoverable or unknown to us at
                // the time of writing and so we can't guess how to handle it,
                // so abort.
                error!("I/O error: {}", err);
                ControlFlow::Break(ConnectionEvent::DisconnectWithoutFlush)
            }
        }
    }
}

//------------ ConnectionEvent -----------------------------------------------

enum ConnectionEvent {
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

    ServiceError(ServiceError),
}

//--- Display

impl Display for ConnectionEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConnectionEvent::DisconnectWithoutFlush => {
                write!(f, "Disconnect without flush")
            }
            ConnectionEvent::DisconnectWithFlush => {
                write!(f, "Disconnect with flush")
            }
            ConnectionEvent::ServiceError(err) => {
                write!(f, "Service error: {err}")
            }
        }
    }
}

//------------ StreamState ---------------------------------------------------

pub struct StreamState<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    stream_tx: WriteHalf<Stream>,

    result_q_tx: mpsc::Sender<CallResult<Buf::Output, Svc::Target>>,

    // RFC 7766 section 6.2.3 / RFC 7828 section 3 idle time out tracking
    idle_timer_reset_at: Instant,
}

impl<Stream, Buf, Svc> StreamState<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    #[must_use]
    fn new(
        stream_tx: WriteHalf<Stream>,
        result_q_tx: mpsc::Sender<CallResult<Buf::Output, Svc::Target>>,
    ) -> Self {
        Self {
            stream_tx,
            result_q_tx,
            idle_timer_reset_at: Instant::now(),
        }
    }

    /// How long from now should this connection be timed out?
    ///
    /// When we (will) have been sat idle for longer than the configured idle
    /// timeout for this connection.
    #[must_use]
    pub fn idle_timeout_deadline(&self, timeout: Duration) -> Instant {
        self.idle_timer_reset_at.checked_add(timeout).unwrap()
    }

    #[must_use]
    pub fn idle_timeout_expired(&self, timeout: Duration) -> bool {
        self.idle_timeout_deadline(timeout) <= Instant::now()
    }

    fn reset_idle_timer(&mut self) {
        self.idle_timer_reset_at = Instant::now();
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
