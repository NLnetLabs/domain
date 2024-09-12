//! Support for datagram based server transports.
//!
//! Wikipedia defines [Datagram] as:
//!
//! > _A datagram is a basic transfer unit associated with a packet-switched
//! > network. Datagrams are typically structured in header and payload
//! > sections. Datagrams provide a connectionless communication service
//! > across a packet-switched network. The delivery, arrival time, and order
//! > of arrival of datagrams need not be guaranteed by the network._
//!
//! [Datagram]: https://en.wikipedia.org/wiki/Datagram
use core::fmt::Debug;
use core::future::poll_fn;
use core::marker::PhantomData;
use core::ops::Deref;
use core::time::Duration;

use std::io;
use std::net::SocketAddr;
use std::string::String;
use std::string::ToString;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use futures::prelude::stream::StreamExt;
use octseq::Octets;
use tokio::io::ReadBuf;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::interval;
use tokio::time::timeout;
use tokio::time::Instant;
use tokio::time::MissedTickBehavior;
use tracing::warn;
use tracing::Level;
use tracing::{enabled, error, trace};

use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};
use crate::net::server::buf::BufSource;
use crate::net::server::error::Error;
use crate::net::server::message::Request;
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::service::{Service, ServiceFeedback};
use crate::net::server::sock::AsyncDgramSock;
use crate::net::server::util::to_pcap_text;
use crate::utils::config::DefMinMax;

use super::buf::VecBufSource;
use super::message::{TransportSpecificContext, UdpTransportContext};
use super::service::ServiceResult;
use super::util::mk_error_response;
use super::ServerCommand;

/// A UDP transport based DNS server transport.
///
/// UDP aka User Datagram Protocol, as implied by the name, is a datagram
/// based protocol. This type defines a type of [`DgramServer`] that expects
/// connections to be received via [`tokio::net::UdpSocket`] and can thus be
/// used to implement a UDP based DNS server.
pub type UdpServer<Svc> = DgramServer<UdpSocket, VecBufSource, Svc>;

/// Limit the time to wait for a complete message to be written to the client.
///
/// The value has to be between 1ms and 60 seconds. The default value is 5
/// seconds.
const WRITE_TIMEOUT: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(5),
    Duration::from_millis(1),
    Duration::from_secs(60),
);

/// Limit suggested for the maximum response size to create.
///
/// The value has to be between 512 and 4,096 per [RFC 6891]. The default
/// value is 1232 per the [2020 DNS Flag Day].
///
/// The [`Service`] and middleware chain (if any) are responsible for
/// enforcing this limit.
///
/// [2020 DNS Flag Day]: http://www.dnsflagday.net/2020/
/// [RFC 6891]: https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.5
const MAX_RESPONSE_SIZE: DefMinMax<u16> = DefMinMax::new(1232, 512, 4096);

//----------- Config ---------------------------------------------------------

/// Configuration for a datagram server.
#[derive(Debug)]
pub struct Config {
    /// Limit suggested to [`Service`] on maximum response size to create.
    max_response_size: Option<u16>,

    /// Limit the time to wait for a complete message to be written to the client.
    write_timeout: Duration,
}

impl Config {
    /// Creates a new, default config.
    pub fn new() -> Self {
        Default::default()
    }

    /// Sets the limit suggested for the maximum response size to create.
    ///
    /// The value has to be between 512 and 4,096 per [RFC 6891]. The default
    /// value is 1232 per the [2020 DNS Flag Day].
    ///
    /// Pass `None` to prevent sending a limit suggestion to the middleware
    /// (if any) and service.
    ///
    /// The [`Service`] and middleware chain (if any) are responsible for
    /// enforcing the suggested limit, or deciding what to do if this is None.
    ///
    /// # Reconfigure
    ///
    /// On [`DgramServer::reconfigure`]` any change to this setting will only
    /// affect requests received after the setting is changed, in progress
    /// requests will be unaffected.
    ///
    /// [2020 DNS Flag Day]: http://www.dnsflagday.net/2020/
    /// [RFC 6891]:
    ///     https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.5
    pub fn set_max_response_size(&mut self, value: Option<u16>) {
        self.max_response_size = value;
    }

    /// Sets the time to wait for a complete message to be written to the
    /// client.
    ///
    /// The value has to be between 1ms and 60 seconds. The default value is 5
    /// seconds.
    ///
    /// # Reconfigure
    ///
    /// On [`DgramServer::reconfigure`]` any change to this setting will only
    /// affect responses sent after the setting is changed, in-flight
    /// responses will be unaffected.
    pub fn set_write_timeout(&mut self, value: Duration) {
        self.write_timeout = value;
    }
}

//--- Default

impl Default for Config {
    fn default() -> Self {
        Self {
            max_response_size: Some(MAX_RESPONSE_SIZE.default()),
            write_timeout: WRITE_TIMEOUT.default(),
        }
    }
}

//--- Clone

impl Clone for Config {
    fn clone(&self) -> Self {
        Self {
            max_response_size: self.max_response_size,
            write_timeout: self.write_timeout,
        }
    }
}

//------------ DgramServer ---------------------------------------------------

/// A [`ServerCommand`] capable of propagating a DgramServer [`Config`] value.
type ServerCommandType = ServerCommand<Config>;

/// A thread safe sender of [`ServerCommand`]s.
type CommandSender = Arc<Mutex<watch::Sender<ServerCommandType>>>;

/// A thread safe receiver of [`ServerCommand`]s.
type CommandReceiver = watch::Receiver<ServerCommandType>;

/// A server for connecting clients via a datagram based network transport to
/// a [`Service`].
///
/// [`DgramServer`] doesn't itself define how messages should be received,
/// message buffers should be allocated, message lengths should be determined
/// or how request messages should be received and responses sent. Instead it
/// is generic over types that provide these abilities.
///
/// By using different implementations of these traits, or even your own
/// implementations, the behaviour of [`DgramServer`] can be tuned as needed.
///
/// The [`DgramServer`] needs a socket to receive incoming messages, a
/// [`BufSource`] to create message buffers on demand, and a [`Service`] to
/// handle received request messages and generate corresponding response
/// messages for [`DgramServer`] to deliver to the client.
///
/// A socket is anything that implements the [`AsyncDgramSock`] trait. This
/// crate provides an implementation for [`tokio::net::UdpSocket`]. When
/// wrapped inside an [`Arc`] the same `UdpSocket` can be [`Arc::clone`]d to
/// multiple instances of [`DgramServer`] potentially increasing throughput.
///
/// # Examples
///
/// The example below shows how to create, run and shutdown a [`DgramServer`]
/// configured to receive requests and write responses via a
/// [`tokio::net::UdpSocket`] using a [`VecBufSource`] for buffer allocation
/// and a [`Service`] to generate responses to requests.
///
/// ```no_run
/// use std::boxed::Box;
/// use std::future::{Future, Ready};
/// use std::pin::Pin;
/// use std::sync::Arc;
///
/// use tokio::net::UdpSocket;
///
/// use domain::base::Message;
/// use domain::net::server::buf::VecBufSource;
/// use domain::net::server::dgram::DgramServer;
/// use domain::net::server::message::Request;
/// use domain::net::server::service::ServiceResult;
/// use domain::net::server::stream::StreamServer;
/// use domain::net::server::util::service_fn;
///
/// fn my_service(msg: Request<Vec<u8>>, _meta: ()) -> ServiceResult<Vec<u8>>
/// {
///     todo!()
/// }
///
/// #[tokio::main]
/// async fn main() {
///     // Create a service impl from the service fn
///     let svc = service_fn(my_service, ());
///
///     // Bind to a local port and listen for incoming UDP messages.
///     let udpsocket = UdpSocket::bind("127.0.0.1:8053").await.unwrap();
///
///     // Create a server that will accept those connections and pass
///     // received messages to your service and in turn pass generated
///     // responses back to the client.
///     let srv = Arc::new(DgramServer::new(udpsocket, VecBufSource, svc));
///
///     // Run the server.
///     let spawned_srv = srv.clone();
///     tokio::spawn(async move { spawned_srv.run().await });
///
///     // ... do something ...
///
///     // Shutdown the server.
///     srv.shutdown().unwrap();
/// }
/// ```
///
/// [`Service`]: super::service::Service
/// [`VecBufSource`]: super::buf::VecBufSource
/// [`tokio::net::TcpListener`]:
///     https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html

pub struct DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync,
    Buf::Output: Octets + Send + Sync + Unpin + 'static,
    Svc: Service<Buf::Output> + Clone + Send + Sync + 'static,
    Svc::Future: Send,
    Svc::Stream: Send,
    Svc::Target: Composer + Default + Send,
{
    /// The configuration of the server.
    config: Arc<ArcSwap<Config>>,

    /// A receiver for receiving [`ServerCommand`]s.
    ///
    /// Used by both the server and spawned connections to react to sent
    /// commands.
    command_rx: CommandReceiver,

    /// A sender for sending [`ServerCommand`]s.
    ///
    /// Used to signal the server to stop, reconfigure, etc.
    command_tx: CommandSender,

    /// The network socket over which client requests will be received
    /// and responses sent.
    sock: Arc<Sock>,

    /// A [`BufSource`] for creating buffers on demand.
    buf: Buf,

    /// [`ServerMetrics`] describing the status of the server.
    metrics: Arc<ServerMetrics>,

    /// Dispatches requests to the service and enqueues responses for sending.
    request_dispatcher: RequestDispatcher<Sock, Buf::Output, Svc>,
}

/// Creation
///
impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync,
    Buf: BufSource + Send + Sync,
    Buf::Output: Octets + Send + Sync + Unpin,
    Svc: Service<Buf::Output> + Clone + Send + Sync + 'static,
    Svc::Future: Send,
    Svc::Stream: Send,
    Svc::Target: Composer + Default + Send,
{
    /// Constructs a new [`DgramServer`] with default configuration.
    ///
    /// See [`Self::with_config`].
    #[must_use]
    pub fn new(sock: Sock, buf: Buf, service: Svc) -> Self {
        Self::with_config(sock, buf, service, Config::default())
    }

    /// Constructs a new [`DgramServer`] with a given configuration.
    ///
    /// Takes:
    /// - A socket which must implement [`AsyncDgramSock`] and is responsible
    ///   receiving new messages and send responses back to the client.
    /// - A [`BufSource`] for creating buffers on demand.
    /// - A [`Service`] for handling received requests and generating
    ///   responses.
    /// - A [`Config`] with settings to control the server behaviour.
    ///
    /// Invoke [`run`] to receive and process incoming messages.
    ///
    /// [`run`]: Self::run()
    #[must_use]
    pub fn with_config(
        sock: Sock,
        buf: Buf,
        service: Svc,
        config: Config,
    ) -> Self {
        let (command_tx, command_rx) = watch::channel(ServerCommand::Init);
        let command_tx = Arc::new(Mutex::new(command_tx));
        let metrics = Arc::new(ServerMetrics::connection_less());
        let config = Arc::new(ArcSwap::from_pointee(config));
        let sock = Arc::new(sock);

        let request_dispatcher = RequestDispatcher::new(
            config.clone(),
            service,
            sock.clone(),
            metrics.clone(),
        );

        DgramServer {
            config,
            command_tx,
            command_rx,
            sock,
            buf,
            metrics,
            request_dispatcher,
        }
    }
}

/// Access
///
impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync,
    Buf: BufSource + Send + Sync,
    Buf::Output: Octets + Send + Sync + Unpin,
    Svc: Service<Buf::Output> + Clone + Send + Sync + 'static,
    Svc::Future: Send,
    Svc::Stream: Send,
    Svc::Target: Composer + Default + Send,
{
    /// Get a reference to the network source being used to receive messages.
    #[must_use]
    pub fn source(&self) -> Arc<Sock> {
        self.sock.clone()
    }

    /// Get a reference to the metrics for this server.
    #[must_use]
    pub fn metrics(&self) -> Arc<ServerMetrics> {
        self.metrics.clone()
    }
}

/// Control
///
impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync,
    Buf::Output: Octets + Send + Sync + Unpin + 'static,
    Svc: Service<Buf::Output> + Clone + Send + Sync + 'static,
    Svc::Future: Send,
    Svc::Stream: Send,
    Svc::Target: Composer + Default + Send,
{
    /// Start the server.
    ///
    /// # Drop behaviour
    ///
    /// When dropped [`shutdown`] will be invoked.
    ///
    /// [`shutdown`]: Self::shutdown
    pub async fn run(&self) {
        if let Err(err) = self.run_until_error().await {
            error!("Server stopped due to error: {err}");
        }
    }

    /// Reconfigure the server while running.
    ///
    ///
    pub fn reconfigure(&self, config: Config) -> Result<(), Error> {
        self.command_tx
            .lock()
            .map_err(|_| Error::CommandCouldNotBeSent)?
            .send(ServerCommand::Reconfigure(config))
            .map_err(|_| Error::CommandCouldNotBeSent)
    }

    /// Stop the server.
    ///
    /// In-flight requests will continue being processed but no new messages
    /// will be accepted. Pending responses will be written as long as the
    /// socket that was given to the server when it was created remains
    /// operational.
    ///
    /// [`Self::is_shutdown`] can be used to dertermine if shutdown is
    /// complete.
    ///
    /// [`Self::await_shutdown`] can be used to wait for shutdown to complete.
    pub fn shutdown(&self) -> Result<(), Error> {
        self.command_tx
            .lock()
            .map_err(|_| Error::CommandCouldNotBeSent)?
            .send(ServerCommand::Shutdown)
            .map_err(|_| Error::CommandCouldNotBeSent)
    }

    /// Check if shutdown has completed.
    ///
    /// Note that until shutdown is fully complete some Tokio background tasks
    /// may remain scheduled or active to process in-flight requests.
    pub fn is_shutdown(&self) -> bool {
        self.metrics.num_inflight_requests() == 0
            && self.metrics.num_pending_writes() == 0
    }

    /// Wait for an in-progress shutdown to complete.
    ///
    /// Returns true if the server shutdown in the given time period, false
    /// otherwise.
    ///
    /// To start the shutdown process first call [`Self::shutdown`] then use
    /// this method to wait for the shutdown process to complete.
    pub async fn await_shutdown(&self, duration: Duration) -> bool {
        timeout(duration, async {
            let mut interval = interval(Duration::from_millis(100));
            interval.set_missed_tick_behavior(MissedTickBehavior::Skip);
            while !self.is_shutdown() {
                interval.tick().await;
            }
        })
        .await
        .is_ok()
    }
}

//--- Internal details

impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync,
    Buf: BufSource + Send + Sync,
    Buf::Output: Octets + Send + Sync + Unpin + 'static,
    Svc: Service<Buf::Output> + Clone + Send + Sync + 'static,
    Svc::Future: Send,
    Svc::Stream: Send,
    Svc::Target: Composer + Default + Send,
{
    /// Receive incoming messages until shutdown or fatal error.
    async fn run_until_error(&self) -> Result<(), String> {
        let mut command_rx = self.command_rx.clone();

        loop {
            tokio::select! {
                // Poll futures in match arm order, not randomly.
                biased;

                // First, prefer obeying `ServerCommand`s over everything
                // else.
                res = command_rx.changed() => {
                    self.process_server_command(res, &mut command_rx)?;
                }

                _ = self.sock.readable() => {
                    let (buf, addr, bytes_read) = match self.recv_from() {
                        Ok(res) => res,
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
                        Err(err) => return Err(format!("Error while receiving message: {err}")),
                    };

                    let received_at = Instant::now();
                    self.metrics.inc_num_received_requests();

                    if enabled!(Level::TRACE) {
                        let pcap_text = to_pcap_text(&buf, bytes_read);
                        trace!(%addr, pcap_text, "Received message");
                    }

                    match Message::from_octets(buf) {
                        Err(err) => {
                            tracing::warn!("Failed while parsing request message: {err}");
                        }

                        Ok(msg) => {
                            let ctx = UdpTransportContext::new(self.config.load().max_response_size);
                            let ctx = TransportSpecificContext::Udp(ctx);
                            let request = Request::new(addr, received_at, msg, ctx, ());

                            trace!(
                                "Spawning task to handle new message with id {}",
                                request.message().header().id()
                            );

                            let mut dispatcher = self.request_dispatcher.clone();
                            tokio::spawn(async move {
                                dispatcher.dispatch(request, addr).await
                            });
                        }
                    }
                }
            }
        }
    }

    /// Decide what to do with a received [`ServerCommand`].
    fn process_server_command(
        &self,
        res: Result<(), watch::error::RecvError>,
        command_rx: &mut CommandReceiver,
    ) -> Result<(), String> {
        // If the parent server no longer exists but was not cleanly shutdown
        // then the command channel will be closed and attempting to check for
        // a new command will fail. Advise the caller to break the connection
        // and cleanup if such a problem occurs.
        res.map_err(|err| format!("Error while receiving command: {err}"))?;

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
                // A datagram server does not have connections so handling the
                // close of a connection which can never happen has no meaning
                // as it cannot occur. However a Service impl cannot know
                // which server will receive the ServerCommand if it is
                // shared between multiple servers and so we should just
                // ignore this if we receive it.
            }

            ServerCommand::Reconfigure(new_config) => {
                self.config.store(Arc::new(new_config.clone()));
            }

            ServerCommand::Shutdown => {
                // Stop receiving new messages.
                return Err("Shutdown command received".to_string());
            }
        }

        Ok(())
    }

    /// Receive a single datagram using the user supplied network socket.
    fn recv_from(
        &self,
    ) -> Result<(Buf::Output, SocketAddr, usize), io::Error> {
        let mut msg = self.buf.create_buf();
        let mut buf = ReadBuf::new(msg.as_mut());
        self.sock
            .try_recv_buf_from(&mut buf)
            .map(|(bytes_read, addr)| (msg, addr, bytes_read))
    }
}

//--- Drop

impl<Sock, Buf, Svc> Drop for DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync,
    Buf::Output: Octets + Send + Sync + Unpin + 'static,
    Svc: Service<Buf::Output> + Clone + Send + Sync + 'static,
    Svc::Future: Send,
    Svc::Stream: Send,
    Svc::Target: Composer + Default + Send,
{
    fn drop(&mut self) {
        // Shutdown the DgramServer. Don't handle the failure case here as
        // I'm not sure if it's safe to log or write to stderr from a Drop
        // impl.
        let _ = self.shutdown();
    }
}
//------------ DispatcherStatus -----------------------------------------------

enum DispatcherStatus {
    Normal,

    InTransaction,

    Aborting,
}

//------------ RequestDispatcher ----------------------------------------------

struct RequestDispatcher<Sock, RequestOctets, Svc>
where
    RequestOctets: Octets + Send + Sync,
    Svc: Service<RequestOctets> + Clone + Send + Sync + 'static,
    Svc::Target: Composer + Default + Send,
{
    /// User supplied settings that influence our behaviour.
    ///
    /// May updated during request and response processing based on received
    /// [`ServiceFeedback`].
    config: Arc<ArcSwap<Config>>,

    /// A [`Service`] for handling received requests and generating responses.
    service: Svc,

    /// The network socket to which responses will be sent.
    sock: Arc<Sock>,

    /// [`ServerMetrics`] describing the status of the server.
    metrics: Arc<ServerMetrics>,

    status: DispatcherStatus,

    _phantom_data: PhantomData<RequestOctets>,
}

impl<Sock, RequestOctets, Svc> RequestDispatcher<Sock, RequestOctets, Svc>
where
    RequestOctets: Octets + Send + Sync,
    Svc: Service<RequestOctets> + Clone + Send + Sync + 'static,
    Svc::Target: Composer + Default + Send,
{
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            service: self.service.clone(),
            sock: self.sock.clone(),
            metrics: self.metrics.clone(),
            status: DispatcherStatus::Normal,
            _phantom_data: PhantomData,
        }
    }
}

impl<Sock, RequestOctets, Svc> RequestDispatcher<Sock, RequestOctets, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    RequestOctets: Octets + Send + Sync,
    Svc: Service<RequestOctets> + Clone + Send + Sync + 'static,
    Svc::Target: Composer + Default + Send,
    Svc::Future: Send,
    Svc::Stream: Send,
{
    fn new(
        config: Arc<ArcSwap<Config>>,
        service: Svc,
        sock: Arc<Sock>,
        metrics: Arc<ServerMetrics>,
    ) -> Self {
        Self {
            config,
            service,
            sock,
            metrics,
            status: DispatcherStatus::Normal,
            _phantom_data: PhantomData,
        }
    }

    async fn dispatch(
        &mut self,
        request: Request<RequestOctets>,
        addr: SocketAddr,
    ) {
        let req_msg = request.message().clone();
        let request_id = request.message().header().id();

        // Dispatch the request to the service for processing.
        trace!("Calling service for request id {request_id}");
        let mut stream = self.service.call(request).await;

        // Handle the resulting stream of responses.
        // TODO: For UDP does it ever make sense to send multiple responses
        // back to the client?
        trace!("Awaiting service call results for request id {request_id}");
        while let Some(item) = stream.next().await {
            trace!(
                "Processing service call result for request id {request_id}"
            );

            let response = self.process_response_stream_item(item, &req_msg);

            if let Some(response) = response {
                self.enqueue_response(addr, response).await;
            }

            if matches!(self.status, DispatcherStatus::Aborting) {
                trace!("Aborting response stream processing for request id {request_id}");
                break;
            }
        }
        trace!("Finished processing service call results for request id {request_id}");
    }

    fn process_response_stream_item(
        &mut self,
        stream_item: ServiceResult<Svc::Target>,
        req_msg: &Message<RequestOctets>,
    ) -> Option<AdditionalBuilder<StreamTarget<Svc::Target>>> {
        match stream_item {
            Ok(call_result) => {
                let (response, feedback) = call_result.into_inner();
                if let Some(feedback) = feedback {
                    self.process_feedback(feedback);
                }
                response
            }

            Err(err) => {
                self.status = DispatcherStatus::Aborting;
                Some(mk_error_response(req_msg, err.rcode().into()))
            }
        }
    }

    fn process_feedback(&mut self, feedback: ServiceFeedback) {
        match feedback {
            ServiceFeedback::Reconfigure {
                idle_timeout: _, // N/A - only applies to connection-oriented transports
            } => {
                // Nothing to do.
            }

            ServiceFeedback::BeginTransaction => {
                self.status = DispatcherStatus::InTransaction
            }

            ServiceFeedback::EndTransaction => {
                self.status = DispatcherStatus::Normal
            }
        }
    }

    async fn enqueue_response(
        &self,
        addr: SocketAddr,
        response: AdditionalBuilder<StreamTarget<Svc::Target>>,
    ) {
        // Convert the DNS response message into bytes.
        let target = response.finish();
        let bytes = target.as_dgram_slice();

        // Logging
        if enabled!(Level::TRACE) {
            let pcap_text = to_pcap_text(bytes, bytes.len());
            trace!(%addr, pcap_text, "Sending response");
        }

        self.metrics.inc_num_pending_writes();

        let write_timeout = self.config.load().write_timeout;

        // Actually write the DNS response message bytes to the UDP
        // socket.
        if let Err(err) =
            Self::send_to(&self.sock, bytes, &addr, write_timeout).await
        {
            warn!(%addr, "Failed to send response: {err}");
        }

        self.metrics.dec_num_pending_writes();
        self.metrics.inc_num_sent_responses();
    }

    /// Send a single datagram using the user supplied network socket.
    async fn send_to(
        sock: &Sock,
        data: &[u8],
        dest: &SocketAddr,
        limit: Duration,
    ) -> Result<(), io::Error> {
        let send_res =
            timeout(limit, poll_fn(|ctx| sock.poll_send_to(ctx, data, dest)))
                .await;

        let Ok(send_res) = send_res else {
            return Err(io::ErrorKind::TimedOut.into());
        };

        let sent = send_res?;

        if sent != data.len() {
            Err(io::Error::new(io::ErrorKind::Other, "short send"))
        } else {
            Ok(())
        }
    }
}
