//! Support for stream based server transports.
//!
//! Wikipedia defines [stream] as:
//!
//! > _A reliable byte stream is a common service paradigm in computer
//! > networking; it refers to a byte stream in which the bytes which emerge
//! > from the communication channel at the recipient are exactly the same,
//! > and in exactly the same order, as they were when the sender inserted
//! > them into the channel._
//! >
//! > _The classic example of a reliable byte stream communication protocol is
//! > the **Transmission Control Protocol**, one of the major building blocks of
//! > the Internet._
//!
//! [stream]: https://en.wikipedia.org/wiki/Reliable_byte_streamuse
use arc_swap::ArcSwap;
use core::future::poll_fn;
use core::ops::Deref;
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use octseq::Octets;
use std::fmt::Debug;
use std::io;
use std::net::SocketAddr;
use std::string::{String, ToString};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{error, trace, trace_span, warn};

use crate::net::server::buf::BufSource;
use crate::net::server::error::Error;
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::service::Service;
use crate::net::server::sock::AsyncAccept;
use crate::utils::config::DefMinMax;

use super::buf::VecBufSource;
use super::connection::{self, Connection};
use super::ServerCommand;
use tokio::io::{AsyncRead, AsyncWrite};

// TODO: Should this crate also provide a TLS listener implementation?

/// A TCP transport based DNS server.
///
/// The TCP aka Transport Control Protocol, as [noted by Wikipedia], is a
/// stream based transport protocol. This type defines a type of
/// [`StreamServer`] that expects connections to be received via
/// [`tokio::net::TcpListener`] and can thus be used to implement a TCP based
/// DNS server.
///
/// [noted by Wikipedia]:
///     https://en.wikipedia.org/wiki/Reliable_byte_streamuse
/// [`tokio::net::TcpListener`]:
///     https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html
pub type TcpServer<Svc> = StreamServer<TcpListener, VecBufSource, Svc>;

/// Limit on the number of concurrent TCP connections that can be handled by
/// the server.
///
/// The value has to be between one and 100,000. The default value is 100. The
/// default value is based on the default value of the NSD 4.8.0 `-n number`
/// configuration setting .
///
/// If the limit is hit, further connections will be accepted but closed
/// immediately.
const MAX_CONCURRENT_TCP_CONNECTIONS: DefMinMax<usize> =
    DefMinMax::new(100, 1, 100000);

//----------- Config ---------------------------------------------------------

/// Configuration for a stream server.
pub struct Config {
    /// Limit on the number of concurrent TCP connections that can be handled
    /// by the server.
    max_concurrent_connections: usize,

    /// Whether to accept new connections or not when at the configured limit.
    accept_connections_at_max: bool,

    /// Connection specific configuration.
    pub(super) connection_config: connection::Config,
}

impl Config {
    /// Creates a new, default config.
    pub fn new() -> Self {
        Default::default()
    }

    /// Set whether to accept new connections or not when at the configured
    /// limit.
    ///
    /// The value has to be true or false. The default value is true.
    ///
    /// See [`Self::set_max_concurrent_connections()`].
    pub fn set_accept_connections_at_max(&mut self, value: bool) {
        self.accept_connections_at_max = value;
    }

    /// Whether to accept new connections or not when at the configured limit.
    pub fn accept_connections_at_max(&self) -> bool {
        self.accept_connections_at_max
    }

    /// Sets the limit on the number of concurrent TCP connections that can be
    /// handled by the server.
    ///
    /// The value has to be between one and 100,000. The default value is 100.
    /// The default value is based on the default value of the NSD 4.8.0 `-n
    /// number` configuration setting .
    ///
    /// If the limit is reached and [`Self::accept_connections_at_max()`] is
    /// true, further connections will be accepted but closed immediately.
    /// Limit on the number of concurrent TCP connections that can be handled
    /// by the server.
    ///
    /// If the limit is reached and [`Self::accept_connections_at_max()`] is
    /// false, no new connections will be accepted unitl the number of
    /// concurrent connections falls below the limit.
    ///
    /// # Reconfigure
    ///
    /// On [`StreamServer::reconfigure`] if there are more connections
    /// currently than the new limit the exceess connections will be allowed
    /// to complete normally, connections will NOT be terminated.
    pub fn set_max_concurrent_connections(&mut self, value: usize) {
        self.max_concurrent_connections = value;
    }

    /// Gets the configured maximum number of concurrent connections.
    pub fn max_concurrent_connections(&self) -> usize {
        self.max_concurrent_connections
    }

    /// Sets the connection specific configuration.
    ///
    /// See [`connection::Config`] for more information.
    pub fn set_connection_config(
        &mut self,
        connection_config: connection::Config,
    ) {
        self.connection_config = connection_config;
    }

    /// Gets the connection specific configuration.
    pub fn connection_config(&self) -> &connection::Config {
        &self.connection_config
    }
}

//--- Default

impl Default for Config {
    fn default() -> Self {
        Self {
            accept_connections_at_max: true,
            max_concurrent_connections: MAX_CONCURRENT_TCP_CONNECTIONS
                .default(),
            connection_config: connection::Config::default(),
        }
    }
}

//--- Clone

impl Clone for Config {
    fn clone(&self) -> Self {
        Self {
            accept_connections_at_max: self.accept_connections_at_max,
            max_concurrent_connections: self.max_concurrent_connections,
            connection_config: self.connection_config,
        }
    }
}

//------------ StreamServer --------------------------------------------------

/// A [`ServerCommand`] capable of propagating a StreamServer [`Config`] value.
type ServerCommandType = ServerCommand<Config>;

/// A thread safe sender of [`ServerCommand`]s.
type CommandSender = Arc<Mutex<watch::Sender<ServerCommandType>>>;

/// A thread safe receiver of [`ServerCommand`]s.
type CommandReceiver = watch::Receiver<ServerCommandType>;

/// A server for connecting clients via stream based network transport to a
/// [`Service`].
///
/// [`StreamServer`] doesn't itself define how connections should be accepted,
/// message buffers should be allocated,
/// or how request messages should be received and responses sent. Instead it
/// is generic over types that provide these abilities.
///
/// By using different implementations of these traits, or even your own
/// implementations, the behaviour of [`StreamServer`] can be tuned as needed.
///
/// The [`StreamServer`] needs a listener to accept incoming connections, a
/// [`BufSource`] to create message buffers on demand, and a [`Service`] to
/// handle received request messages and generate corresponding response
/// messages for [`StreamServer`] to deliver to the client.
///
/// A listener is anything that implements the [`AsyncAccept`] trait. This
/// crate provides an implementation for [`tokio::net::TcpListener`].
///
/// # Examples
///
/// The example below shows how to create, run and shutdown a [`StreamServer`]
/// configured to receive requests and write responses via a
/// [`tokio::net::TcpListener`] using a [`VecBufSource`] for buffer allocation
/// and a [`Service`] to generate responses to requests.
///
/// ```no_run
/// use std::boxed::Box;
/// use std::future::{Future, Ready};
/// use std::pin::Pin;
/// use std::sync::Arc;
///
/// use tokio::net::TcpListener;
///
/// use domain::base::Message;
/// use domain::net::server::buf::VecBufSource;
/// use domain::net::server::message::Request;
/// use domain::net::server::service::{CallResult, ServiceError, ServiceResult};
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
///     // Bind to a local port and listen for incoming TCP connections.
///     let listener = TcpListener::bind("127.0.0.1:8053").await.unwrap();
///
///     // Create a server that will accept those connections and pass
///     // received messages to your service and in turn pass generated
///     // responses back to the client.
///     let srv = Arc::new(StreamServer::new(listener, VecBufSource, svc));
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
pub struct StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync,
    Buf: BufSource + Send + Sync + Clone,
    Buf::Output: Octets + Send + Sync + Unpin,
    Svc: Service<Buf::Output, ()> + Clone,
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

    /// A listener for listening for and accepting incoming stream
    /// connections.
    listener: Arc<Listener>,

    /// A [`BufSource`] for creating buffers on demand.
    buf: Buf,

    /// A [`Service`] for handling received requests and generating responses.
    service: Svc,

    /// An optional pre-connect hook.
    pre_connect_hook: Option<fn(&mut Listener::StreamType)>,

    /// An ascending "ID" number assigned incrementally to newly accepted
    /// connections.
    connection_idx: AtomicUsize,

    /// [`ServerMetrics`] describing the status of the server.
    metrics: Arc<ServerMetrics>,
}

/// # Creation
///
impl<Listener, Buf, Svc> StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync,
    Buf: BufSource + Send + Sync + Clone,
    Buf::Output: Octets + Send + Sync + Unpin,
    Svc: Service<Buf::Output, ()> + Clone,
{
    /// Creates a new [`StreamServer`] instance.
    ///
    /// Takes:
    /// - A listener which must implement [`AsyncAccept`] and is responsible
    ///   awaiting and accepting incoming stream connections.
    /// - A [`BufSource`] for creating buffers on demand.
    /// - A [`Service`] for handling received requests and generating responses.
    #[must_use]
    pub fn new(listener: Listener, buf: Buf, service: Svc) -> Self {
        Self::with_config(listener, buf, service, Config::default())
    }

    /// Creates a new [`StreamServer`] instance with a given configuration.
    #[must_use]
    pub fn with_config(
        listener: Listener,
        buf: Buf,
        service: Svc,
        config: Config,
    ) -> Self {
        let (command_tx, command_rx) = watch::channel(ServerCommand::Init);
        let command_tx = Arc::new(Mutex::new(command_tx));
        let listener = Arc::new(listener);
        let metrics = Arc::new(ServerMetrics::connection_oriented());
        let config = Arc::new(ArcSwap::from_pointee(config));

        StreamServer {
            config,
            command_tx,
            command_rx,
            listener,
            buf,
            service,
            pre_connect_hook: None,
            metrics,
            connection_idx: AtomicUsize::new(0),
        }
    }

    /// Specify a pre-connect hook to be invoked by the given
    /// [`StreamServer`].
    ///
    /// The pre-connect hook can be used to inspect and/or modify the
    /// properties of a newly accepted stream before it is passed to a new
    /// connection handler. This is useful if you do not control the code that
    /// creates the underlying socket and wish to modify the socket options.
    ///
    /// # Examples
    ///
    /// Setting TCP keepalive on the stream:
    ///
    /// ```ignore
    /// let srv = srv.with_pre_connect_hook(|stream| {
    ///     let keep_alive = socket2::TcpKeepalive::new()
    ///         .with_time(Duration::from_secs(20))
    ///         .with_interval(Duration::from_secs(20));
    ///     let socket = socket2::SockRef::from(&stream);
    ///     socket.set_tcp_keepalive(&keep_alive).unwrap();
    /// });
    /// ```
    #[must_use]
    pub fn with_pre_connect_hook(
        mut self,
        pre_connect_hook: fn(&mut Listener::StreamType),
    ) -> Self {
        self.pre_connect_hook = Some(pre_connect_hook);
        self
    }
}

/// # Access
///
impl<Listener, Buf, Svc> StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync,
    Buf: BufSource + Send + Sync + Clone,
    Buf::Output: Octets + Debug + Send + Sync + Unpin,
    Svc: Service<Buf::Output, ()> + Clone,
{
    /// Get a reference to the source for this server.
    #[must_use]
    pub fn source(&self) -> Arc<Listener> {
        self.listener.clone()
    }

    /// Get a reference to the metrics for this server.
    #[must_use]
    pub fn metrics(&self) -> Arc<ServerMetrics> {
        self.metrics.clone()
    }
}

/// # Control
///
impl<Listener, Buf, Svc> StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync,
    Buf: BufSource + Send + Sync + Clone,
    Buf::Output: Octets + Send + Sync + Unpin,
    Svc: Service<Buf::Output, ()> + Clone,
{
    /// Start the server.
    ///
    /// # Drop behaviour
    ///
    /// When dropped [`shutdown`] will be invoked.
    ///
    /// [`shutdown`]: Self::shutdown
    pub async fn run(&self)
    where
        Buf: 'static,
        Buf::Output: 'static,
        Listener::Error: Send,
        Listener::Future: Send + 'static,
        Listener::StreamType: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        if let Err(err) = self.run_until_error().await {
            error!("Server stopped due to error: {err}");
        }
    }

    /// Reconfigure the server while running.
    ///
    /// This command will be received both by the server and by any existing
    /// connections.
    pub fn reconfigure(&self, config: Config) -> Result<(), Error> {
        self.command_tx
            .lock()
            .map_err(|_| Error::CommandCouldNotBeSent)?
            .send(ServerCommand::Reconfigure(config))
            .map_err(|_| Error::CommandCouldNotBeSent)
    }

    /// Stop the server.
    ///
    /// No new connections will be accepted and open connections will be
    /// signalled to shutdown. In-flight requests will continue being
    /// processed but no new messages will be accepted. Pending responses will
    /// be written as long as the client side of connection remains remains
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

impl<Listener, Buf, Svc> StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync,
    Buf: BufSource + Send + Sync + Clone,
    Buf::Output: Octets + Send + Sync + Unpin,
    Svc: Service<Buf::Output, ()> + Clone,
{
    /// Accept stream connections until shutdown or fatal error.
    async fn run_until_error(&self) -> Result<(), String>
    where
        Buf: 'static,
        Buf::Output: 'static,
        Listener::Error: Send,
        Listener::Future: Send + 'static,
        Listener::StreamType: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        let mut command_rx = self.command_rx.clone();

        loop {
            tokio::select! {
                // Poll futures in match arm order, not randomly.
                biased;

                // First, prefer obeying [`ServerCommands`] over everything
                // else.
                res = command_rx.changed() => {
                    self.process_server_command(res, &mut command_rx)?;
                }

                // Next, handle a connection that has been accepted, if any.
                accept_res = self.accept(), if self.accepting_connections() => {
                    match accept_res {
                        Ok((stream, addr)) if !self.at_connection_limit() => {
                            self.spawn_connection_handler(stream, addr);
                        }

                        Ok(_) => {
                            warn!("Connection limit reached: dropping accepted connection");
                        }

                        Err(err) => {
                            error!("Error while accepting TCP connection: {err}");
                        }
                    }
                }
            }
        }
    }

    /// Returns true if the server is at its connection limit.
    ///
    /// See [`Config::max_concurrent_connections`].
    fn at_connection_limit(&self) -> bool {
        let config = ArcSwap::load(&self.config);
        let num_conn = self.metrics.num_connections();
        num_conn >= config.max_concurrent_connections()
    }

    /// Returns true if the server can accept new connections.
    ///
    /// The server will not accept new connections if it is:
    ///   - At the connection limit, AND
    ///   - Configured to stop accepting new connections when at the limit.
    fn accepting_connections(&self) -> bool {
        if self.at_connection_limit() {
            let config = ArcSwap::load(&self.config);
            config.accept_connections_at_max
        } else {
            true
        }
    }

    /// Decide what to do with a received [`ServerCommand`].
    fn process_server_command(
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
            ServerCommand::Reconfigure(new_config) => {
                self.config.store(Arc::new(new_config.clone()));
            }

            ServerCommand::Shutdown => {
                // Stop accepting new connections, terminate the server. Child
                // connections also receeive the command and handle it
                // themselves.
                return Err("Shutdown command received".to_string());
            }

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
                // Individual connections can be closed. The server itself
                // should never receive a CloseConnection command.
                unreachable!()
            }
        }

        Ok(())
    }

    /// Spawn a handler for a newly accepted connection.
    fn spawn_connection_handler(
        &self,
        stream: Listener::Future,
        addr: SocketAddr,
    ) where
        Buf: 'static,
        Buf::Output: Octets + 'static,
        Listener::Error: Send,
        Listener::Future: Send + 'static,
        Listener::StreamType: AsyncRead + AsyncWrite + Send + Sync + 'static,
    {
        // Work around the compiler wanting to move self to the async block by
        // preparing only those pieces of information from self for the new
        // connection handler that it actually needs.
        let config = ArcSwap::load(&self.config);
        let conn_config = config.connection_config;
        let conn_command_rx = self.command_rx.clone();
        let conn_service = self.service.clone();
        let conn_buf = self.buf.clone();
        let conn_metrics = self.metrics.clone();
        let pre_connect_hook = self.pre_connect_hook;
        let new_connection_idx =
            self.connection_idx.fetch_add(1, Ordering::SeqCst);

        trace!("Spawning new connection handler.");
        tokio::spawn(async move {
            let span = trace_span!("stream", conn = new_connection_idx);
            let _guard = span.enter();

            trace!("Accepting connection.");
            if let Ok(mut stream) = stream.await {
                trace!("Connection accepted.");
                // Let the caller inspect and/or modify the accepted stream
                // before passing it to Connection.
                if let Some(hook) = pre_connect_hook {
                    trace!("Running pre-connect hook.");
                    hook(&mut stream);
                }

                let conn = Connection::with_config(
                    conn_service,
                    conn_buf,
                    conn_metrics,
                    stream,
                    addr,
                    conn_config,
                );

                trace!("Starting connection handler.");
                conn.run(conn_command_rx).await;
                trace!("Connection handler terminated.");
            }
        });
    }

    /// Wait for and accept a single stream connection.
    ///
    /// TODO: This may be obsoleted when Rust gains more support for async fns
    /// in traits.
    async fn accept(
        &self,
    ) -> Result<(Listener::Future, SocketAddr), io::Error> {
        poll_fn(|ctx| self.listener.poll_accept(ctx)).await
    }
}

//--- Drop

impl<Listener, Buf, Svc> Drop for StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync,
    Buf: BufSource + Send + Sync + Clone,
    Buf::Output: Octets + Send + Sync + Unpin,
    Svc: Service<Buf::Output, ()> + Clone,
{
    fn drop(&mut self) {
        // Shutdown the StreamServer. Don't handle the failure case here as
        // I'm not sure if it's safe to log or write to stderr from a Drop
        // impl.
        let _ = self.shutdown();
    }
}
