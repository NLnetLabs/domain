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
use core::ops::Deref;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::string::ToString;
use std::{future::poll_fn, string::String};

use std::{
    io,
    sync::{Arc, Mutex},
};

use octseq::Truncate;
use tokio::net::UdpSocket;
use tokio::time::Instant;
use tokio::{io::ReadBuf, sync::watch};
use tracing::{enabled, error, trace, warn, Level};

use crate::base::Message;
use crate::net::server::buf::BufSource;
use crate::net::server::error::Error;
use crate::net::server::message::MessageProcessor;
use crate::net::server::message::{ContextAwareMessage, MessageDetails};
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::middleware::chain::MiddlewareChain;
use crate::net::server::service::{CallResult, Service, ServiceFeedback};
use crate::net::server::sock::AsyncDgramSock;
use crate::net::server::util::to_pcap_text;
use crate::utils::config::DefMinMax;

use super::buf::VecBufSource;
use super::service::ServerCommand;

/// A UDP transport based DNS server transport.
///
/// UDP aka User Datagram Protocol, as implied by the name, is a datagram
/// based protocol. This type defines a type of [`DgramServer`] that expects
/// connections to be received via [`tokio::net::UdpSocket`] and can thus be
/// used to implement a UDP based DNS server.
pub type UdpServer<Svc> = DgramServer<UdpSocket, VecBufSource, Svc>;

/// Limit suggested for the maximum response size to create.
///
/// The value has to be between 512 and 4,096 per [RFC 6891]. The default
/// value is 1232 per the [2020 DNS Flag Day].
///
/// The [`Service`] and [`MiddlewareChain`] (if any) are response for
/// enforcing this limit.
///
/// [2020 DNS Flag Day]: http://www.dnsflagday.net/2020/
/// [RFC 6891]: https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.5
const MAX_RESPONSE_SIZE: DefMinMax<u16> = DefMinMax::new(1232, 512, 4096);

//----------- Config ---------------------------------------------------------

/// Configuration for a datagram server.
#[derive(Clone, Debug)]
pub struct Config {
    /// Limit suggested to [`Service`] on maximum response size to create.
    max_response_size: Option<u16>,
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
    /// The [`Service`] and [`MiddlewareChain`] (if any) are response for
    /// enforcing the suggested limit, or deciding what to do if this is None.
    ///
    /// [2020 DNS Flag Day]: http://www.dnsflagday.net/2020/
    /// [RFC 6891]:
    ///     https://datatracker.ietf.org/doc/html/rfc6891#section-6.2.5
    pub fn set_max_response_size(&mut self, value: Option<u16>) {
        self.max_response_size = value;
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_response_size: Some(MAX_RESPONSE_SIZE.default()),
        }
    }
}

//------------ DgramServer ---------------------------------------------------

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
/// crate provides an implementation for [`tokio::net::UdpSocket`].
///
/// # Examples
///
/// The example below shows how to create, run and shutdown a [`DgramServer`]
/// configured to receive requests and write responses via a
/// [`tokio::net::UdpSocket`] using a [`VecBufSource`] for buffer allocation
/// and a [`Service`] to generate responses to requests.
///
/// ```
/// use domain::net::server::buf::VecBufSource;
/// use domain::net::server::prelude::*;
/// use domain::net::server::middleware::builder::MiddlewareBuilder;
/// use domain::net::server::dgram::DgramServer;
/// use tokio::net::UdpSocket;
///
/// fn my_service(msg: Arc<ContextAwareMessage<Message<Vec<u8>>>>, _meta: ())
///     -> MkServiceResult<Vec<u8>, Vec<u8>, ()>
/// {
///     todo!()
/// }
///
/// #[tokio::main]
/// async fn main() {
///     // Create a service impl from the service fn
///     let svc = mk_service(my_service, ());
///
///     // Bind to a local port and listen for incoming UDP messages.
///     let udpsocket = UdpSocket::bind("127.0.0.1:8053").await.unwrap();
///
///     // Create the server with default middleware.
///     let middleware = MiddlewareBuilder::default().build();
///
///     // Create a server that will accept those connections and pass
///     // received messages to your service and in turn pass generated
///     // responses back to the client.
///     let srv = Arc::new(DgramServer::new(udpsocket, VecBufSource, svc)
///         .with_middleware(middleware));
///
///     // Run the server.
///     let spawned_srv = srv.clone();
///     let join_handle = tokio::spawn(async move { spawned_srv.run().await });
///
///     // ... do something ...
///
///     // Shutdown the server.
///     srv.shutdown().unwrap();
///
///     // Wait for shutdown to complete.
///     join_handle.await.unwrap();
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
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static + Debug,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    config: Config,
    command_rx: watch::Receiver<ServerCommand<Config>>,
    command_tx: Arc<Mutex<watch::Sender<ServerCommand<Config>>>>,
    sock: Arc<Sock>,
    buf: Buf,
    service: Svc,
    middleware_chain: Option<MiddlewareChain<Buf::Output, Svc::Target>>,
    metrics: Arc<ServerMetrics>,
}

/// Creation
///
impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static + Debug,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    /// Constructs a new [`DgramServer`] with default configuration.
    ///
    /// See [`Self::with_config()`].
    #[must_use]
    pub fn new(sock: Sock, buf: Buf, service: Svc) -> Self {
        Self::with_config(sock, buf, service, Config::default())
    }

    /// Constructs a new [`DgramServer`] with a given configuration.
    ///
    /// Takes:
    /// - A socket which must implement [`AsyncDgramSock`] and is responsible
    /// receiving new messages and send responses back to the client.
    /// - A [`BufSource`] for creating buffers on demand.
    /// - A [`Service`] for handling received requests and generating responses.
    /// - A [`Config`] with settings to control the server behaviour.
    ///
    /// Invoke [`run()`] to receive and process incoming messages.
    ///
    /// [`run()`]: Self::run()
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

        DgramServer {
            config,
            command_tx,
            command_rx,
            sock: sock.into(),
            buf,
            service,
            metrics,
            middleware_chain: None,
        }
    }

    /// Configure the [`DgramServer`] to process messages via a [`MiddlewareChain`].
    #[must_use]
    pub fn with_middleware(
        mut self,
        middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
    ) -> Self {
        self.middleware_chain = Some(middleware_chain);
        self
    }
}

/// Access
///
impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static + Debug,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
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
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static + Debug,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    /// Start the server.
    ///
    /// # Drop behaviour
    ///
    /// When dropped [`shutdown()`] will be invoked.
    ///
    /// [`shutdown()`]: Self::shutdown
    pub async fn run(&self)
    where
        Svc::Single: Send,
    {
        if let Err(err) = self.run_until_error().await {
            error!("DgramServer: {err}");
        }
    }

    /// Stop the server.
    ///
    /// No new messages will be received.
    ///
    /// Tip: Await the [`tokio::task::JoinHandle`] that you received when
    /// spawning a task to run the server to know when shutdown is complete.
    ///
    ///
    /// [`tokio::task::JoinHandle`]:
    ///     https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html
    // TODO: Do we also need a non-graceful terminate immediately function?
    pub fn shutdown(&self) -> Result<(), Error> {
        self.command_tx
            .lock()
            .unwrap()
            .send(ServerCommand::Shutdown)
            .map_err(|_| Error::CommandCouldNotBeSent)
    }
}

//--- Internal details

impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static + Debug,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    /// Receive incoming messages until shutdown or fatal error.
    ///
    // TODO: Use a strongly typed error, not String.
    async fn run_until_error(&self) -> Result<(), String>
    where
        Svc::Single: Send,
    {
        let mut command_rx = self.command_rx.clone();

        loop {
            tokio::select! {
                // Poll futures in match arm order, not randomly.
                biased;

                // First, prefer obeying [`ServiceCommands`] over everything
                // else.
                res = command_rx.changed() => {
                    self.process_service_command(res, &mut command_rx)?;
                }

                recv_res = self.recv_from() => {
                    let (msg, addr, bytes_read) = recv_res
                        .map_err(|err|
                            format!("Error while receiving message: {err}")
                        )?;

                    let received_at = Instant::now();

                    if enabled!(Level::TRACE) {
                        let pcap_text = to_pcap_text(&msg, bytes_read);
                        trace!(%addr, pcap_text, "Received message");
                    }

                    let msg_details = MessageDetails::new(msg, received_at, addr);

                    self.process_request(
                        msg_details, (self.sock.clone(), self.command_tx.clone()),
                        self.middleware_chain.clone(),
                        &self.service,
                        self.metrics.clone()
                    )
                        .map_err(|err|
                            format!("Error while processing message: {err}")
                        )?;
                }
            }
        }
    }

    fn process_service_command(
        &self,
        res: Result<(), watch::error::RecvError>,
        command_rx: &mut watch::Receiver<ServerCommand<Config>>,
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
                // placed another ServiceCommand::Init value into the watch
                // channel after the initial one.
                unreachable!()
            }

            ServerCommand::CloseConnection => {
                // A datagram server does not have connections so handling the
                // close of a connection which can never happen has no meaning
                // as it cannot occur. However a Service impl cannot know
                // which server will receive the ServiceCommand if it is
                // shared between multiple servers and so we should just
                // ignore this if we receive it.
            }

            ServerCommand::Reconfigure(Config {
                max_response_size: _, // TO DO
            }) => {
                // TODO: Support dynamic replacement of the middleware chain?
                // E.g. via ArcSwapOption<MiddlewareChain> instead of Option?
            }

            ServerCommand::Shutdown => {
                // Stop receiving new messages.
                return Err("Shutdown command received".to_string());
            }
        }

        Ok(())
    }

    async fn recv_from(
        &self,
    ) -> Result<(Buf::Output, SocketAddr, usize), io::Error> {
        let mut res = self.buf.create_buf();
        let (addr, bytes_read) = {
            let mut buf = ReadBuf::new(res.as_mut());
            let addr = poll_fn(|ctx| self.sock.poll_recv_from(ctx, &mut buf))
                .await?;
            (addr, buf.filled().len())
        };
        Ok((res, addr, bytes_read))
    }

    async fn send_to(
        sock: &Sock,
        data: &[u8],
        dest: &SocketAddr,
    ) -> Result<(), io::Error> {
        let sent = poll_fn(|ctx| sock.poll_send_to(ctx, data, dest)).await?;
        if sent != data.len() {
            Err(io::Error::new(io::ErrorKind::Other, "short send"))
        } else {
            Ok(())
        }
    }
}

//--- MessageProcessor

impl<Sock, Buf, Svc> MessageProcessor<Buf, Svc>
    for DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static + Debug,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    type State =
        (Arc<Sock>, Arc<Mutex<watch::Sender<ServerCommand<Config>>>>);

    fn add_context_to_request(
        &self,
        request: Message<Buf::Output>,
        received_at: Instant,
        addr: SocketAddr,
    ) -> ContextAwareMessage<Message<Buf::Output>> {
        let mut msg =
            ContextAwareMessage::new(request, addr, received_at, true);
        if let Some(max_response_size) = self.config.max_response_size {
            msg.set_max_response_size_hint(max_response_size);
        }
        msg
    }

    fn process_call_result(
        call_result: CallResult<Buf::Output, Svc::Target>,
        addr: SocketAddr,
        (sock, command_tx): Self::State,
        _metrics: Arc<ServerMetrics>,
    ) {
        tokio::spawn(async move {
            let (request, response, feedback) = call_result.into_inner();

            if let Some(feedback) = feedback {
                match feedback {
                    ServiceFeedback::Reconfigure {
                        idle_timeout: _, // N/A - only applies to connection-oriented transports
                    } => {
                        // Nothing to do.
                    }

                    ServiceFeedback::CloseConnection => {
                        // N/A - only applies to connection-oriented transports
                    }

                    ServiceFeedback::Shutdown => {
                        if let Err(err) = command_tx
                            .lock()
                            .unwrap()
                            .send(ServerCommand::Shutdown)
                        {
                            warn!("Service requested shutdown but shutdown failed: {err}");
                        }
                    }
                }
            }

            // Process the DNS response message, if any.
            if let Some(mut response) = response {
                // Determine if the response needs to be truncated.
                let mut truncate_to = None;

                if let Some(request) = request {
                    if let Some(max_response_size_hint) =
                        request.max_response_size_hint()
                    {
                        let max_response_size_hint: usize =
                            max_response_size_hint.into();
                        let response_len = response.as_slice().len();
                        if response_len > max_response_size_hint {
                            // Truncate per RFC 1035 section 6.2 and RFC 2181 sections 5.1
                            // and 9:
                            //
                            // https://datatracker.ietf.org/doc/html/rfc1035#section-6.2
                            //   "When a response is so long that truncation is required,
                            //    the truncation should start at the end of the response
                            //    and work forward in the datagram.  Thus if there is any
                            //    data for the authority section, the answer section is
                            //    guaranteed to be unique."
                            //
                            // https://datatracker.ietf.org/doc/html/rfc2181#section-5.1
                            //   "A query for a specific (or non-specific) label, class,
                            //    and type, will always return all records in the
                            //    associated RRSet - whether that be one or more RRs.  The
                            //    response must be marked as "truncated" if the entire
                            //    RRSet will not fit in the response."
                            //
                            // https://datatracker.ietf.org/doc/html/rfc2181#section-9 ""
                            //   "Where TC is set, the partial RRSet that would not
                            //    completely fit may be left in the response.  When a DNS
                            //    client receives a reply with TC set, it should ignore
                            //    that response, and query again, using a mechanism, such
                            //    as a TCP connection, that will permit larger replies."

                            // Simplistic approach:
                            trace!("Truncating response from {response_len} bytes to {max_response_size_hint} bytes");
                            truncate_to = Some(max_response_size_hint);
                            response.header_mut().set_tc(true);
                        }
                    }
                }

                // Convert the DNS response message into bytes and apply
                // truncation if needed.
                let mut target = response.finish();
                if let Some(max_response_size) = truncate_to {
                    target.truncate(max_response_size);
                }
                let bytes = target.as_dgram_slice();

                // Logging
                if enabled!(Level::TRACE) {
                    let pcap_text = to_pcap_text(bytes, bytes.len());
                    trace!(%addr, pcap_text, "Sent response");
                }

                // Actually write the DNS response message bytes to the UDP
                // socket.
                let _ = Self::send_to(&sock, bytes, &addr).await;
            }

            // TODO:
            // metrics.num_pending_writes.store(???, Ordering::Relaxed);
        });
    }
}

//--- Drop

impl<Sock, Buf, Svc> Drop for DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static + Debug,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    fn drop(&mut self) {
        // Shutdown the DgramServer. Don't handle the failure case here as
        // I'm not sure if it's safe to log or write to stderr from a Drop
        // impl.
        let _ = self.shutdown();
    }
}
