//! Support for stream based connections.
use core::ops::{ControlFlow, Deref};
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use std::fmt::Display;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use futures_util::StreamExt;
use octseq::Octets;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf,
};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio::time::{sleep_until, timeout};
use tracing::Level;
use tracing::{debug, enabled, error, trace, warn};

use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};
use crate::net::server::buf::BufSource;
use crate::net::server::message::Request;
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::service::{Service, ServiceError, ServiceFeedback};
use crate::net::server::util::to_pcap_text;
use crate::utils::config::DefMinMax;

use super::message::{NonUdpTransportContext, TransportSpecificContext};
use super::stream::Config as ServerConfig;
use super::ServerCommand;

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
#[derive(Copy, Debug)]
pub struct Config {
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
}

impl Config {
    /// Creates a new, default config.
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
    /// # Reconfigure
    ///
    /// On [`StreamServer::reconfigure`] the current idle period will NOT be
    /// affected. Subsequent idle periods (after the next message is received
    /// or response is sent, assuming that happens within the current idle
    /// period) will use the new timeout value.
    ///
    /// [RFC 7766]:
    ///     https://datatracker.ietf.org/doc/html/rfc7766#section-6.2.3
    ///
    /// [`StreamServer::reconfigure`]:
    ///     super::stream::StreamServer::reconfigure()
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
    ///
    /// # Reconfigure
    ///
    /// On [`StreamServer::reconfigure`] any responses currently being
    /// written will NOT use the new timeout, it will only apply to responses
    /// that start being sent after the timeout is changed.
    ///
    /// [`StreamServer::reconfigure`]:
    ///     super::stream::StreamServer::reconfigure()
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
    ///
    /// # Reconfigure
    ///
    /// On [`StreamServer::reconfigure`] only new connections created after
    /// this setting is changed will use the new value, existing connections
    /// will continue to use their exisitng queue at its existing size.
    ///
    /// [`StreamServer::reconfigure`]:
    ///     super::stream::StreamServer::reconfigure()
    pub fn set_max_queued_responses(&mut self, value: usize) {
        self.max_queued_responses = value;
    }
}

//--- Default

impl Default for Config {
    fn default() -> Self {
        Self {
            idle_timeout: IDLE_TIMEOUT.default(),
            response_write_timeout: RESPONSE_WRITE_TIMEOUT.default(),
            max_queued_responses: MAX_QUEUED_RESPONSES.default(),
        }
    }
}

//--- Clone

impl Clone for Config {
    fn clone(&self) -> Self {
        *self
    }
}

//------------ Connection -----------------------------------------------

/// A handler for a single stream connection between client and server.
pub struct Connection<Stream, Buf, Svc>
where
    Buf: BufSource,
    Buf::Output: Send + Sync + Unpin,
    Svc: Service<Buf::Output> + Clone,
{
    /// Flag used by the Drop impl to track if the metric count has to be
    /// decreased or not.
    active: bool,

    /// A [`BufSource`] for creating buffers on demand. e.g. to hold response
    /// messages.
    buf: Buf,

    /// User supplied settings that influence our behaviour.
    ///
    /// Note: Some reconfiguration is possible at runtime via
    /// [`ServerCommand::Reconfigure`] and [`ServiceFeedback::Reconfigure`].
    config: Arc<ArcSwap<Config>>,

    /// The address of the connected client.
    addr: SocketAddr,

    /// The incoming connection stream from the client.
    ///
    /// Note: Though this is an Option it should never be None.
    stream_rx: Option<ReadHalf<Stream>>,

    /// The outgoing connection stream to the client.
    stream_tx: WriteHalf<Stream>,

    /// The reader for consuming from the queue of responses waiting to be
    /// written back to the client.
    result_q_rx: mpsc::Receiver<AdditionalBuilder<StreamTarget<Svc::Target>>>,

    /// The writer for pushing ready responses onto the queue waiting
    /// to be written back the client.
    result_q_tx: mpsc::Sender<AdditionalBuilder<StreamTarget<Svc::Target>>>,

    /// A [`Service`] for handling received requests and generating responses.
    service: Svc,

    /// DNS protocol idle time out tracking.
    idle_timer: IdleTimer,

    /// Is a transaction in progress?
    in_transaction: Arc<AtomicBool>,

    /// [`ServerMetrics`] describing the status of the server.
    metrics: Arc<ServerMetrics>,
}

/// Creation
///
impl<Stream, Buf, Svc> Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite,
    Buf: BufSource,
    Buf::Output: Octets + Send + Sync + Unpin,
    Svc: Service<Buf::Output> + Clone,
{
    /// Creates a new handler for an accepted stream connection.
    #[must_use]
    #[allow(dead_code)]
    pub fn new(
        service: Svc,
        buf: Buf,
        metrics: Arc<ServerMetrics>,
        stream: Stream,
        addr: SocketAddr,
    ) -> Self {
        Self::with_config(
            service,
            buf,
            metrics,
            stream,
            addr,
            Config::default(),
        )
    }

    /// Create a new connection handler with a given configuration.
    #[must_use]
    pub fn with_config(
        service: Svc,
        buf: Buf,
        metrics: Arc<ServerMetrics>,
        stream: Stream,
        addr: SocketAddr,
        config: Config,
    ) -> Self {
        let (stream_rx, stream_tx) = tokio::io::split(stream);
        let (result_q_tx, result_q_rx) =
            mpsc::channel(config.max_queued_responses);
        let config = Arc::new(ArcSwap::from_pointee(config));
        let idle_timer = IdleTimer::new();
        let in_transaction = Arc::new(AtomicBool::new(false));

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
            buf,
            config,
            addr,
            stream_rx,
            stream_tx,
            result_q_rx,
            result_q_tx,
            service,
            idle_timer,
            in_transaction,
            metrics,
        }
    }
}

/// Control
///
impl<Stream, Buf, Svc> Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + Clone + 'static,
    Buf::Output: Octets + Send + Sync + Unpin,
    Svc: Service<Buf::Output> + Clone + Send + Sync + 'static,
    Svc::Target: Composer + Send,
    Svc::Stream: Send,
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
    /// in-flight will continue processing and then fail to queue the response
    /// for writing.
    pub async fn run(
        mut self,
        command_rx: watch::Receiver<ServerCommand<ServerConfig>>,
    ) where
        Svc::Future: Send,
    {
        self.metrics.inc_num_connections();

        // Flag that we have to decrease the metric count on Drop.
        self.active = true;

        self.run_until_error(command_rx).await;
    }
}

//--- Internal details

impl<Stream, Buf, Svc> Connection<Stream, Buf, Svc>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + Clone + 'static,
    Buf::Output: Octets + Send + Sync + Unpin,
    Svc: Service<Buf::Output> + Clone + Send + Sync + 'static,
    Svc::Target: Composer + Send,
    Svc::Future: Send,
    Svc::Stream: Send,
{
    /// Connection handler main loop.
    async fn run_until_error(
        mut self,
        mut command_rx: watch::Receiver<ServerCommand<ServerConfig>>,
    ) {
        // SAFETY: This unwrap is safe because we always put a Some value into
        // self.stream_rx in [`Self::with_config`] above (and thus also in
        // [`Self::new`] which calls [`Self::with_config`]).
        let stream_rx = self.stream_rx.take().unwrap();

        let mut dns_msg_receiver =
            DnsMessageReceiver::new(self.buf.clone(), stream_rx);

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
                        self.process_server_command(res, &mut command_rx)
                    }

                    res = self.result_q_rx.recv() => {
                        self.process_queued_result(res).await
                    }

                    _ = sleep_until(self.idle_timer.idle_timeout_deadline(self.config.load().idle_timeout)) => {
                        self.process_dns_idle_timeout(self.config.load().idle_timeout)
                    }

                    res = &mut msg_recv => {
                        let res = self.process_read_request(res).await;
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
        if let Err(err) = self.stream_tx.shutdown().await {
            warn!("Error while shutting down the write stream: {err}");
        }
        trace!("Connection terminated.");

        #[cfg(test)]
        if dns_msg_receiver.cancelled() {
            panic!("Async not-cancel-safe code was cancelled");
        }
    }

    /// Decide what to do with a received [`ServerCommand`].
    fn process_server_command(
        &mut self,
        res: Result<(), watch::error::RecvError>,
        command_rx: &mut watch::Receiver<ServerCommand<ServerConfig>>,
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
                connection_config,
                .. // Ignore the Server specific configuration settings
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
                self.config.store(Arc::new(*connection_config));
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

    /// Stop queueing new responses and process those already in the queue.
    async fn flush_write_queue(&mut self)
    // where
    // Target: Composer,
    {
        debug!("Flushing connection write queue.");
        // Stop accepting new response messages (should we check for in-flight
        // messages that haven't generated a response yet but should be
        // allowed to do so?) so that we can flush the write queue and exit
        // this connection handler.
        trace!("Stop queueing up new results.");
        self.result_q_rx.close();
        trace!("Process already queued results.");
        while let Some(response) = self.result_q_rx.recv().await {
            trace!("Processing queued result.");
            if let Err(err) = self.process_queued_result(Some(response)).await
            {
                warn!("Error while processing queued result: {err}");
            } else {
                trace!("Result processed");
            }
        }
        debug!("Connection write queue flush complete.");
    }

    /// Process a single queued response.
    async fn process_queued_result(
        &mut self,
        response: Option<AdditionalBuilder<StreamTarget<Svc::Target>>>,
    ) -> Result<(), ConnectionEvent>
// where
    //     Target: Composer,
    {
        // If we failed to read the results of requests processed by the
        // service because the queue holding those results is empty and can no
        // longer be read from, then there is no point continuing to read from
        // the input stream because we will not be able to access the result
        // of processing the request. I'm not sure when this could happen,
        // perhaps if we were dropped?
        let Some(response) = response else {
            trace!("Disconnecting due to failed response queue read.");
            return Err(ConnectionEvent::DisconnectWithFlush);
        };

        trace!(
            "Writing queued response with id {} to stream",
            response.header().id()
        );
        self.write_response_to_stream(response.finish()).await;

        Ok(())
    }

    /// Write a response back to the caller over the network stream.
    async fn write_response_to_stream(
        &mut self,
        msg: StreamTarget<Svc::Target>,
    )
    // where
    //     Target: AsRef<[u8]>,
    {
        if enabled!(Level::TRACE) {
            let bytes = msg.as_dgram_slice();
            let pcap_text = to_pcap_text(bytes, bytes.len());
            trace!(addr = %self.addr, pcap_text, "Sending response");
        }

        match timeout(
            self.config.load().response_write_timeout,
            self.stream_tx.write_all(msg.as_stream_slice()),
        )
        .await
        {
            Err(_) => {
                error!(
                    "Write timed out (>{:?})",
                    self.config.load().response_write_timeout
                );
                // TODO: Push it to the back of the queue to retry it?
            }
            Ok(Err(err)) => {
                error!("Write error: {err}");
            }
            Ok(Ok(_)) => {
                self.metrics.inc_num_sent_responses();
            }
        }

        self.metrics.dec_num_pending_writes();

        if self.result_q_tx.capacity() == self.result_q_tx.max_capacity() {
            self.idle_timer.response_queue_emptied();
        }
    }

    /// Implement DNS rules regarding timing out of idle connections.
    ///
    /// Disconnects the current connection of the timer is expired, flushing
    /// pending responses first.
    fn process_dns_idle_timeout(
        &self,
        timeout: Duration,
    ) -> Result<(), ConnectionEvent> {
        // DNS idle timeout elapsed, or was it reset?
        if self.idle_timer.idle_timeout_expired(timeout)
            && !self.in_transaction.load(Ordering::SeqCst)
        {
            trace!("Timing out idle connection");
            Err(ConnectionEvent::DisconnectWithoutFlush)
        } else {
            Ok(())
        }
    }

    /// Process a received request message.
    async fn process_read_request(
        &mut self,
        res: Result<Buf::Output, ConnectionEvent>,
    ) -> Result<(), ConnectionEvent>
    where
        Svc::Stream: Send,
    {
        let in_transaction = self.in_transaction.clone();

        match res {
            Ok(buf) => {
                let received_at = Instant::now();

                if enabled!(Level::TRACE) {
                    let pcap_text = to_pcap_text(&buf, buf.as_ref().len());
                    trace!(addr = %self.addr, pcap_text, "Received message");
                }

                self.metrics.inc_num_received_requests();

                // Message received, reset the DNS idle timer
                self.idle_timer.full_msg_received();

                match Message::from_octets(buf) {
                    Err(err) => {
                        tracing::warn!(
                            "Failed while parsing request message: {err}"
                        );
                        return Err(ConnectionEvent::ServiceError(
                            ServiceError::FormatError,
                        ));
                    }

                    Ok(msg) => {
                        let ctx = NonUdpTransportContext::new(Some(
                            self.config.load().idle_timeout,
                        ));
                        let ctx = TransportSpecificContext::NonUdp(ctx);
                        let request = Request::new(
                            self.addr,
                            received_at,
                            msg,
                            ctx,
                            (),
                        );

                        let svc = self.service.clone();
                        let result_q_tx = self.result_q_tx.clone();
                        let metrics = self.metrics.clone();
                        let config = self.config.clone();

                        trace!(
                            "Spawning task to handle new message with id {}",
                            request.message().header().id()
                        );
                        tokio::spawn(async move {
                            let request_id = request.message().header().id();
                            trace!(
                                "Calling service for request id {request_id}"
                            );
                            let mut stream = svc.call(request).await;

                            trace!("Awaiting service call results for request id {request_id}");
                            while let Some(Ok(call_result)) =
                                stream.next().await
                            {
                                trace!("Processing service call result for request id {request_id}");
                                let (response, feedback) =
                                    call_result.into_inner();

                                if let Some(feedback) = feedback {
                                    match feedback {
                                        ServiceFeedback::Reconfigure {
                                            idle_timeout,
                                        } => {
                                            if let Some(idle_timeout) =
                                                idle_timeout
                                            {
                                                debug!(
                                                    "Reconfigured connection timeout to {idle_timeout:?}"
                                                );
                                                let guard = config.load();
                                                let mut new_config = **guard;
                                                new_config.idle_timeout =
                                                    idle_timeout;
                                                config.store(Arc::new(
                                                    new_config,
                                                ));
                                            }
                                        }

                                        ServiceFeedback::BeginTransaction => {
                                            in_transaction.store(
                                                true,
                                                Ordering::SeqCst,
                                            );
                                        }

                                        ServiceFeedback::EndTransaction => {
                                            in_transaction.store(
                                                false,
                                                Ordering::SeqCst,
                                            );
                                        }
                                    }
                                }

                                if let Some(mut response) = response {
                                    loop {
                                        match result_q_tx.try_send(response) {
                                            Ok(()) => {
                                                let pending_writes =
                                                    result_q_tx
                                                        .max_capacity()
                                                        - result_q_tx
                                                            .capacity();
                                                trace!("Queued message for sending: # pending writes={pending_writes}");
                                                metrics
                                                    .set_num_pending_writes(
                                                        pending_writes,
                                                    );
                                                break;
                                            }

                                            Err(TrySendError::Closed(_)) => {
                                                error!("Unable to queue message for sending: server is shutting down.");
                                                break;
                                            }

                                            Err(TrySendError::Full(
                                                unused_response,
                                            )) => {
                                                if in_transaction.load(Ordering::SeqCst) {
                                                    // Wait until there is space in the message queue.
                                                    tokio::task::yield_now()
                                                        .await;
                                                    response =
                                                        unused_response;
                                                } else {
                                                    error!("Unable to queue message for sending: queue is full.");
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            trace!("Finished processing service call results for request id {request_id}");
                        });
                    }
                }

                Ok(())
            }

            Err(err) => Err(err),
        }
    }
}

//--- Drop

impl<Stream, Buf, Svc> Drop for Connection<Stream, Buf, Svc>
where
    Buf: BufSource,
    Buf::Output: Send + Sync + Unpin,
    Svc: Service<Buf::Output> + Clone,
{
    fn drop(&mut self) {
        if self.active {
            self.active = false;
            self.metrics.dec_num_connections();
        }
    }
}

//----------- DnsMessageReceiver ---------------------------------------------

/// The [`DnsMessageReceiver`] state machine.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Status {
    /// Initial state.
    New,

    /// Waiting to receive a DNS message header.
    WaitingForMessageHeader,

    /// Waiting to receive a DNS message body.
    WaitingForMessageBody,

    /// A full DNS message header and body has been received.
    MessageReceived,
}

/// A cancel safe DNS message receiver.
///
/// If the message is received in bits, e.g. header then body, this receiver
/// ensures that any part of the request already received is not lost if the
/// read operation is cancelled by Tokio and then a new read operation is
/// started.
struct DnsMessageReceiver<Stream, Buf> {
    /// A buffer to record the total expected size of the message currently
    /// being received. DNS TCP streams preceed the DNS message by bytes
    /// indicating the length of the message that follows.
    msg_size_buf: [u8; 2],

    /// A [`BufSource`] for creating buffers on demand. e.g. to hold response
    /// messages.
    buf: Buf,

    /// The incoming connection stream from the client.
    stream_rx: ReadHalf<Stream>,

    /// Our state machine state.
    status: Status,

    #[cfg(test)]
    /// A flag used only during testing that will be set if a read operation
    /// is started but detects that a previous read operation didn't complete,
    /// i.e. the async operation was cancelled.
    cancelled: bool,
}

impl<Stream, Buf> DnsMessageReceiver<Stream, Buf>
where
    Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
{
    /// Creates a new message receiver.
    fn new(buf: Buf, stream_rx: ReadHalf<Stream>) -> Self {
        Self {
            msg_size_buf: [0; 2],
            buf,
            stream_rx,
            status: Status::New,
            #[cfg(test)]
            cancelled: false,
        }
    }

    #[cfg(test)]
    /// Was a read operation using this receiver cancelled at some point?
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
        let mut msg_buf = self.buf.create_sized(msg_len);

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

    /// Handle I/O errors by deciding whether to log them, and whethr to
    /// continue or abort.
    #[must_use]
    fn process_io_error(err: io::Error) -> ControlFlow<ConnectionEvent> {
        match err.kind() {
            io::ErrorKind::UnexpectedEof => {
                // The client disconnected. Per RFC 7766 6.2.4 pending
                // responses MUST NOT be sent to the client.
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

/// An event that occurred while the connection handler was handling the
/// connection.
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

    /// A [`Service`] specific error occurred while the service was processing
    /// a request message.
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

//------------ IdleTimer -----------------------------------------------------

/// RFC 7766 section 6.2.3 / RFC 7828 section 3 idle time out tracking.
pub struct IdleTimer {
    /// The instant when the timer was last reset.
    idle_timer_reset_at: Instant,
}

impl IdleTimer {
    /// Creates a new idle timer.
    ///
    /// Sets the last reset instant to now.
    #[must_use]
    fn new() -> Self {
        Self {
            idle_timer_reset_at: Instant::now(),
        }
    }

    /// How long from now should this connection be timed out?
    ///
    /// When we (will) have been sat idle for longer than the configured idle
    /// timeout for this connection.
    #[must_use]
    pub fn idle_timeout_deadline(&self, timeout: Duration) -> Instant {
        self.idle_timer_reset_at
            .checked_add(timeout)
            .unwrap_or_else(|| {
                warn!("Unable to reset idle timer: value out of bounds");
                Instant::now()
            })
    }

    /// Did the idle timeout expire?
    #[must_use]
    pub fn idle_timeout_expired(&self, timeout: Duration) -> bool {
        self.idle_timeout_deadline(timeout) <= Instant::now()
    }

    /// Reset the idle timer to now.
    fn reset_idle_timer(&mut self) {
        self.idle_timer_reset_at = Instant::now();
    }

    /// Act on the fact that a complete DNS message was received.
    ///
    /// Per RFC 7766 this resets the idle timer.
    fn full_msg_received(&mut self) {
        // RFC 7766 6.2.3: "DNS messages delivered over TCP might arrive in
        // multiple segments.  A DNS server that resets its idle timeout after
        // receiving a single segment might be vulnerable to a "slow-read
        // attack". For this reason, servers SHOULD reset the idle timeout on
        // the receipt of a full DNS message, rather than on receipt of any
        // part of a DNS message."
        self.reset_idle_timer()
    }

    /// Act on the fact that the connection handler caught up with processing
    /// all queued responses.
    ///
    /// Per RFC 7766 this resets the idle timer.
    fn response_queue_emptied(&mut self) {
        // RFC 7766 3: "A DNS server considers an established DNS-over-TCP
        // session to be idle when it has sent responses to all the queries it
        // has received on that connection."
        self.reset_idle_timer()
    }
}
