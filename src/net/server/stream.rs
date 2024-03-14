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
use std::io;
use std::net::SocketAddr;
use std::string::{String, ToString};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::{interval, timeout, MissedTickBehavior};
use tracing::{error, trace, trace_span};

use crate::net::server::buf::BufSource;
use crate::net::server::error::Error;
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::middleware::chain::MiddlewareChain;
use crate::net::server::service::Service;
use crate::net::server::sock::AsyncAccept;
use crate::utils::config::DefMinMax;

use super::buf::VecBufSource;
use super::connection::{self, Connection};
use super::service::ServerCommand;

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

/// Configuration for a stream server connection.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// Limit on the number of concurrent TCP connections that can be handled
    /// by the server.
    pub(super) max_concurrent_connections: usize,
    pub(super) connection_config: connection::Config,
}

impl Config {
    /// Creates a new, default config.
    pub fn new() -> Self {
        Default::default()
    }

    /// Set the limit on the number of concurrent TCP connections that can be
    /// handled by the server.
    ///
    /// The value has to be between one and 100,000. The default value is 100.
    /// The default value is based on the default value of the NSD 4.8.0 `-n
    /// number` configuration setting .
    ///
    /// If the limit is hit, further connections will be accepted but closed
    /// immediately.
    pub fn set_max_concurrent_connections(&mut self, value: usize) {
        self.max_concurrent_connections = value;
    }

    pub fn set_connection_config(
        &mut self,
        connection_config: connection::Config,
    ) {
        self.connection_config = connection_config;
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_concurrent_connections: MAX_CONCURRENT_TCP_CONNECTIONS
                .default(),
            connection_config: connection::Config::default(),
        }
    }
}

//------------ StreamServer --------------------------------------------------

/// A server for connecting clients via stream based network transport to a
/// [`Service`].
///
/// [`StreamServer`] doesn't itself define how connections should be accepted,
/// message buffers should be allocated, message lengths should be determined
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
/// ```
/// use domain::net::server::buf::VecBufSource;
/// use domain::net::server::prelude::*;
/// use domain::net::server::middleware::builder::MiddlewareBuilder;
/// use domain::net::server::stream::StreamServer;
/// use tokio::net::TcpListener;
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
///     // Bind to a local port and listen for incoming TCP connections.
///     let listener = TcpListener::bind("127.0.0.1:8053").await.unwrap();
///
///     // Create the server with default middleware.
///     let middleware = MiddlewareBuilder::default().build();
///
///     // Create a server that will accept those connections and pass
///     // received messages to your service and in turn pass generated
///     // responses back to the client.
///     let srv = Arc::new(StreamServer::new(listener, VecBufSource, svc)
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
pub struct StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    /// The configuration of the server.
    config: Arc<ArcSwap<Config>>,

    /// A receiver for receiving [`ServerCommand`]s.
    ///
    /// Used by both the server and spawned connections to react to sent
    /// commands.
    command_rx: watch::Receiver<ServerCommand<Config>>,

    /// A sender for sending [`ServerCommand`]s.
    ///
    /// Used to signal the server to stop, reconfigure, etc.
    command_tx: Arc<Mutex<watch::Sender<ServerCommand<Config>>>>,

    /// A listener for listening for and accepting incoming stream
    /// connections.
    listener: Arc<Listener>,

    /// A [`BufSource`] for creating buffers on demand.
    buf: Buf,

    /// A [`Service`] for handling received requests and generating responses.
    service: Svc,

    /// An optional pre-connect hook.
    pre_connect_hook: Option<fn(&mut Listener::StreamType)>,

    middleware_chain: Option<MiddlewareChain<Buf::Output, Svc::Target>>,

    /// [`ServerMetrics`] describing the status of the server.
    metrics: Arc<ServerMetrics>,

    connection_idx: AtomicUsize,
}

/// # Creation
///
impl<Listener, Buf, Svc> StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    /// Constructs a new [`StreamServer`] instance.
    ///
    /// Takes:
    /// - A listener which must implement [`AsyncAccept`] and is responsible
    /// awaiting and accepting incoming stream connections.
    /// - A [`BufSource`] for creating buffers on demand.
    /// - A [`Service`] for handling received requests and generating responses.
    #[must_use]
    pub fn new(listener: Listener, buf: Buf, service: Svc) -> Self {
        Self::with_config(listener, buf, service, Config::default())
    }

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
            middleware_chain: None,
            metrics,
            connection_idx: AtomicUsize::new(0),
        }
    }

    /// Configure the [`StreamServer`] to process messages via a [`MiddlewareChain`].
    #[must_use]
    pub fn with_middleware(
        mut self,
        middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
    ) -> Self {
        self.middleware_chain = Some(middleware_chain);
        self
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
    Listener: AsyncAccept + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
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
    Listener: AsyncAccept + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
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
            error!("StreamServer: {err}");
        }
    }

    /// Stop the server.
    ///
    /// No new connections will be accepted and open connections will be
    /// signalled to shutdown. In-flight requests will continue being
    /// processed but no new messages will be accepted. Pending responses will
    /// be written as long as the client side of connection remains remains
    /// operational.
    ///
    /// [`Self::is_shutdown()`] can be used to dertermine if shutdown is
    /// complete.
    ///
    /// [`Self::await_shutdown()`] can be used to wait for shutdown to
    /// complete.
    pub fn shutdown(&self) -> Result<(), Error> {
        self.command_tx
            .lock()
            .unwrap()
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
    /// To start the shutdown process first call [`Self::shutdown()`] then use
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
    Listener: AsyncAccept + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    /// Accept stream connections until shutdown or fatal error.
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

                // First, prefer obeying [`ServerCommands`] over everything
                // else.
                res = command_rx.changed() => {
                    self.process_service_command(res, &mut command_rx)?;
                }

                // Next, handle a connection that has been accepted, if any.
                accept_res = self.accept() => {
                    match accept_res {
                        Ok((stream, addr)) => {
                            // SAFETY: This is a connection-oriented server so there
                            // must always be a connection count metric avasilable to
                            // unwrap.
                            let num_conn = self.metrics.num_connections().unwrap();
                            if num_conn < self.config.load().max_concurrent_connections {
                                self.process_new_connection(stream, addr);
                            }
                        }

                        Err(err) => {
                            error!("Error while accepting TCP connection: {err}");
                        }
                    }
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
            ServerCommand::Reconfigure(new_config) => {
                self.config.store(Arc::new(*new_config));
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

    fn process_new_connection(
        &self,
        stream: Listener::Stream,
        addr: SocketAddr,
    ) where
        Svc::Single: Send,
    {
        // Work around the compiler wanting to move self to the async block by
        // preparing only those pieces of information from self for the new
        // connection handler that it actually needs.
        let conn_config = self.config.load().connection_config;
        let conn_command_rx = self.command_rx.clone();
        let conn_service = self.service.clone();
        let conn_middleware_chain = self.middleware_chain.clone();
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
                    conn_middleware_chain,
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
    /// TODO: This may be obsoleted when Rust gains more support for async fns in traits.
    async fn accept(
        &self,
    ) -> Result<(Listener::Stream, SocketAddr), io::Error> {
        poll_fn(|ctx| self.listener.poll_accept(ctx)).await
    }
}

//--- Drop

impl<Listener, Buf, Svc> Drop for StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static + Clone,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static + Clone,
{
    fn drop(&mut self) {
        // Shutdown the StreamServer. Don't handle the failure case here as
        // I'm not sure if it's safe to log or write to stderr from a Drop
        // impl.
        let _ = self.shutdown();
    }
}