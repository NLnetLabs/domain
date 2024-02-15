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
//! [stream]: https://en.wikipedia.org/wiki/Reliable_byte_streamuse std::future::poll_fn;
use core::future::poll_fn;
use std::io;
use std::net::SocketAddr;
use std::string::{String, ToString};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::error;

use crate::net::server::buf::BufSource;
use crate::net::server::error::Error;
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::middleware::chain::MiddlewareChain;
use crate::net::server::service::{Service, ServiceCommand};
use crate::net::server::sock::AsyncAccept;

use super::buf::VecBufSource;
use super::connection::Connection;

// TODO: Should this crate also provide a TLS listener implementation?

/// A TCP transport based DNS server.
pub type TcpServer<Svc> = StreamServer<TcpListener, VecBufSource, Svc>;

//------------ StreamServer --------------------------------------------------

/// A server for connecting clients via stream transport to a [`Service`].
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
/// _Note: This example skips creation of the service and proper error
/// handling. You can learn about creating a service in the [`Service`]
/// documentation._
///
/// ```ignore
/// # use std::sync::Arc;
/// # use domain::base::Message;
/// # use domain::net::server::service::Service;
/// # use domain::net::server::stream::StreamServer;
/// # use domain::net::server::buf::VecBufSource;
/// # use tokio::net::TcpListener;
/// # fn my_service() -> impl Service<Vec<u8>, Message<Vec<u8>>> {
/// #     todo!()
/// # }
/// #
/// # #[tokio::main(flavor = "multi_thread")]
/// # async fn main() {
/// # let my_service = my_service().into();
/// // Bind to a local port and listen for incoming TCP connections.
/// let listener = TcpListener::bind("127.0.0.1:8053").await.unwrap();
///
/// // Create a server that will accept those connections and pass
/// // received messages to your service and in turn pass generated
/// // responses back to the client.
/// let srv = Arc::new(StreamServer::new(listener, VecBufSource, my_service));
///
/// // Run the server.
/// let spawned_srv = srv.clone();
/// let join_handle = tokio::spawn(async move { spawned_srv.run().await });
///
/// // ... do something ...
///
/// // Shutdown the server.
/// srv.shutdown().unwrap();
///
/// // Wait for shutdown to complete.
/// join_handle.await.unwrap();
/// # }
/// ```
///
/// [`Service`]: crate::net::server::traits::service::Service
/// [`VecBufSource`]: crate::net::server::buf::VecBufSource
/// [`tokio::net::TcpListener`]:
///     https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html
pub struct StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    /// A receiver for receiving [`ServiceCommand`]s.
    ///
    /// Used by both the server and spawned connections to react to sent
    /// commands.
    command_rx: watch::Receiver<ServiceCommand>,

    /// A sender for sending [`ServiceCommand`]s.
    ///
    /// Used to signal the server to stop, reconfigure, etc.
    command_tx: Arc<Mutex<watch::Sender<ServiceCommand>>>,

    /// A listener for listening for and accepting incoming stream
    /// connections.
    listener: Arc<Listener>,

    /// A [`BufSource`] for creating buffers on demand.
    buf: Arc<Buf>,

    /// A [`Service`] for handling received requests and generating responses.
    service: Arc<Svc>,

    /// An optional pre-connect hook.
    pre_connect_hook: Option<fn(&mut Listener::StreamType)>,

    middleware_chain: Option<MiddlewareChain<Buf::Output, Svc::Target>>,

    /// [`ServerMetrics`] describing the status of the server.
    metrics: Arc<ServerMetrics>,
}

/// # Creation
///
impl<Listener, Buf, Svc> StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    /// Create a new stream transport server.
    ///
    /// Takes:
    /// - A listener which must implement [`AsyncAccept`] and is responsible
    /// awaiting and accepting incoming stream connections.
    /// - A [`BufSource`] for creating buffers on demand.
    /// - A [`Service`] for handling received requests and generating responses.
    #[must_use]
    pub fn new(listener: Listener, buf: Arc<Buf>, service: Arc<Svc>) -> Self {
        let (command_tx, command_rx) = watch::channel(ServiceCommand::Init);
        let command_tx = Arc::new(Mutex::new(command_tx));
        let listener = Arc::new(listener);
        let metrics = Arc::new(ServerMetrics::connection_oriented());

        StreamServer {
            command_tx,
            command_rx,
            listener,
            buf,
            service,
            pre_connect_hook: None,
            middleware_chain: None,
            metrics,
        }
    }

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
    /// [`Connection`]. This is useful if you do not control the code that
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
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
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
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    /// Start the server.
    ///
    /// # Drop behaviour
    ///
    /// When dropped [`shutdown()`] will be invoked.
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
    /// No new connections will be accepted and in-progress connections will
    /// be signalled to shutdown.
    ///
    /// Tip: Await the [`tokio::task::JoinHandle`] that you received when
    /// spawning a task to run the server to know when shutdown is complete.
    ///
    /// TODO: Do we also need a non-graceful terminate immediately function?
    ///
    /// [`tokio::task::JoinHandle`]:
    ///     https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html
    pub fn shutdown(&self) -> Result<(), Error> {
        self.command_tx
            .lock()
            .unwrap()
            .send(ServiceCommand::Shutdown)
            .map_err(|_| Error::CommandCouldNotBeSent)
    }
}

//--- Internal details

impl<Listener, Buf, Svc> StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    /// Accept stream connections until shutdown or fatal error.
    ///
    /// TODO: Use a strongly typed error, not String.
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

                // Next, handle a connection that has been accepted, if any.
                accept_res = self.accept() => {
                    // TODO: Do we really want to abort here?
                    let (stream, addr) = accept_res
                        .map_err(|err|
                            format!("Error while accepting connection: {err}")
                        )?;

                    self.process_new_connection(stream, addr)?;
                }
            }
        }
    }

    fn process_service_command(
        &self,
        res: Result<(), watch::error::RecvError>,
        command_rx: &mut watch::Receiver<ServiceCommand>,
    ) -> Result<(), String> {
        // If the parent server no longer exists but was not cleanly shutdown
        // then the command channel will be closed and attempting to check for
        // a new command will fail. Advise the caller to break the connection
        // and cleanup if such a problem occurs.
        res.map_err(|err| format!("Error while receiving command: {err}"))?;

        // Get the changed command.
        let command = *command_rx.borrow_and_update();

        // And process it.
        match command {
            ServiceCommand::Reconfigure { .. } => { /* TODO */ }

            ServiceCommand::Shutdown => {
                // Stop accepting new connections, terminate the server. Child
                // connections also receeive the command and handle it
                // themselves.
                return Err("Shutdown command received".to_string());
            }

            ServiceCommand::Init => {
                // The initial "Init" value in the watch channel is never
                // actually seen because the select Into impl only calls
                // watch::Receiver::borrow_and_update() AFTER changed()
                // signals that a new value has been placed in the watch
                // channel. So the only way to end up here would be if we
                // somehow wrongly placed another ServiceCommand::Init value
                // into the watch channel after the initial one.
                unreachable!()
            }

            ServiceCommand::CloseConnection => {
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
    ) -> Result<JoinHandle<()>, String>
    where
        Svc::Single: Send,
    {
        // Work around the compiler wanting to move self to the async block by
        // preparing only those pieces of information from self for the new
        // connection handler that it actually needs.
        let conn_command_rx = self.command_rx.clone();
        let conn_service = self.service.clone();
        let conn_middleware_chain = self.middleware_chain.clone();
        let conn_buf = self.buf.clone();
        let conn_metrics = self.metrics.clone();
        let pre_connect_hook = self.pre_connect_hook;

        let join_handle = tokio::spawn(async move {
            if let Ok(mut stream) = stream.await {
                // Let the caller inspect and/or modify the accepted stream
                // before passing it to Connection.
                if let Some(hook) = pre_connect_hook {
                    hook(&mut stream);
                }

                let conn = Connection::new(
                    conn_service,
                    conn_middleware_chain,
                    conn_buf,
                    conn_metrics,
                    stream,
                    addr,
                );

                conn.run(conn_command_rx).await
            }
        });

        Ok(join_handle)
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
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    fn drop(&mut self) {
        // Shutdown the StreamServer. Don't handle the failure case here as
        // I'm not sure if it's safe to log or write to stderr from a Drop
        // impl.
        let _ = self.shutdown();
    }
}
