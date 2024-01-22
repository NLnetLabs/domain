use super::buf::BufSource;
use super::connection::Connection;
use super::error::Error;
use super::metrics::ServerMetrics;
use super::service::{MsgProvider, Service, ServiceCommand};
use super::sock::AsyncAccept;
use core::marker::PhantomData;
use std::future::poll_fn;
use std::io;
use std::string::String;
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

//------------ StreamServer --------------------------------------------------

/// A server for connecting clients via stream transport to a [`Service`].
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
/// # Advanced Usage
///
/// [`StreamServer`] doesn't itself define how connections should be accepted,
/// message buffers should be allocated, message lengths should be determined
/// or how request messages should be received and responses sent. Instead it
/// is generic over types that provide these abilities. By using different
/// implementations of these traits, or even your own implementations, the
/// behaviour of [`StreamServer`] can be tuned as needed.
///
/// [`Service`]: crate::net::server::service::Service
/// [`VecBufSource`]: crate::net::server::buf::VecBufSource
/// [`tokio::net::TcpListener`]:
///     https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html
pub struct StreamServer<Listener, Buf, Svc, MsgTyp>
where
    Listener: AsyncAccept + Send + 'static,
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

    /// [`ServerMetrics`] describing the status of the server.
    metrics: Arc<ServerMetrics>,

    /// An optional pre-connect hook.
    pre_connect_hook: Option<fn(&mut Listener::StreamType)>,

    _phantom: PhantomData<MsgTyp>,
}

/// # Creation and access
///
impl<Listener, Buf, Svc, MsgTyp> StreamServer<Listener, Buf, Svc, MsgTyp>
where
    Listener: AsyncAccept + Send + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    MsgTyp: MsgProvider<Buf::Output, Msg = MsgTyp> + Send + Sync + 'static,
    Svc: Service<Buf::Output, MsgTyp> + Send + Sync + 'static,
{
    /// Create a new stream transport server.
    ///
    /// Takes:
    /// - A listener which must implement [`AsyncAccept`] and is responsible
    /// awaiting and accepting incoming stream connections.
    /// - A [`BufSource`] for creating buffers on demand.
    /// - A [`Service`] for handling received requests and generating responses.
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
            metrics,
            pre_connect_hook: None,
            _phantom: PhantomData,
        }
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
    /// srv.with_pre_connect_hook(|stream| {
    ///     let keep_alive = socket2::TcpKeepalive::new()
    ///         .with_time(Duration::from_secs(20))
    ///         .with_interval(Duration::from_secs(20));
    ///     let socket = socket2::SockRef::from(&stream);
    ///     socket.set_tcp_keepalive(&keep_alive).unwrap();
    /// });
    /// ```
    pub fn with_pre_connect_hook(
        mut self,
        pre_connect_hook: fn(&mut Listener::StreamType),
    ) -> Self {
        self.pre_connect_hook = Some(pre_connect_hook);
        self
    }
}

impl<Listener, Buf, Svc, MsgTyp> StreamServer<Listener, Buf, Svc, MsgTyp>
where
    Listener: AsyncAccept + Send + 'static,
{
    /// Get a reference to the listener used to accept connections.
    pub fn listener(&self) -> Arc<Listener> {
        self.listener.clone()
    }

    /// Get a reference to the metrics for this server.
    pub fn metrics(&self) -> Arc<ServerMetrics> {
        self.metrics.clone()
    }
}

/// # Control
/// 
impl<Listener, Buf, Svc, MsgTyp> StreamServer<Listener, Buf, Svc, MsgTyp>
where
    Listener: AsyncAccept + Send + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    MsgTyp: MsgProvider<Buf::Output, Msg = MsgTyp> + Send + Sync + 'static,
    Svc: Service<Buf::Output, MsgTyp> + Send + Sync + 'static,
{
    /// Start the server.
    ///
    /// # Drop behaviour
    ///
    /// When dropped [`shutdown()`] will be invoked.
    pub async fn run(&self) {
        if let Err(err) = self.run_until_error().await {
            eprintln!("StreamServer: {err}");
        }
    }
}

impl<Listener, Buf, Svc, MsgTyp> StreamServer<Listener, Buf, Svc, MsgTyp>
where
    Listener: AsyncAccept + Send + 'static,
{
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

impl<Listener, Buf, Svc, MsgTyp> StreamServer<Listener, Buf, Svc, MsgTyp>
where
    Listener: AsyncAccept + Send + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    MsgTyp: MsgProvider<Buf::Output, Msg = MsgTyp> + Send + Sync + 'static,
    Svc: Service<Buf::Output, MsgTyp> + Send + Sync + 'static,
{
    /// Accept stream connections until shutdown or fatal error.
    ///
    /// TODO: Use a strongly typed error, not String.
    async fn run_until_error(&self) -> Result<(), String> {
        let mut command_rx = self.command_rx.clone();

        loop {
            tokio::select! {
                // Poll futures in match arm order, not randomly.
                biased;

                // First, prefer obeying [`ServiceCommands`] over everything
                // else.
                command_res = command_rx.changed() => {
                    command_res.map_err(|err|
                        format!("Error while receiving command: {err}"))?;

                    let cmd = *command_rx.borrow_and_update();

                    match cmd {
                        ServiceCommand::Reconfigure { .. } => { /* TODO */ }

                        ServiceCommand::Shutdown => {
                            // Stop accepting new connections, terminate the
                            // server. Child connections also receive this
                            // signal and handle it themselves.
                            break;
                        }

                        ServiceCommand::Init => {
                            // The initial "Init" value in the watch channel
                            // is never actually seen because the select Into
                            // impl only calls
                            // watch::Receiver::borrow_and_update() AFTER
                            // changed() signals that a new value has been
                            // placed in the watch channel. So the only way to
                            // end up here would be if we somehow wrongly
                            // placed another ServiceCommand::Init value into
                            // the watch channel after the initial one.
                            unreachable!()
                        }

                        ServiceCommand::CloseConnection => {
                            // Individual connections can be closed. The
                            // server itself should never receive a
                            // CloseConnection command.
                            unreachable!()
                        }
                    }
                }

                // Next, handle a connection that has been accepted, if any.
                accept_res = self.accept() => {
                    let (stream, _addr) = accept_res
                        .map_err(|err|
                            format!("Error while accepting connection: {err}")
                        )?;

                        let conn_command_rx = self.command_rx.clone();
                        let conn_service = self.service.clone();
                        let conn_buf = self.buf.clone();
                        let conn_metrics = self.metrics.clone();
                        let pre_connect_hook = self.pre_connect_hook;
                        let conn_fut = async move {
                        if let Ok(mut stream) = stream.await {
                            // Let the caller inspect and/or modify the
                            // accepted stream before passing it to
                            // Connection.
                            if let Some(hook) = pre_connect_hook {
                                hook(&mut stream);
                            }

                            let conn = Connection::new(
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
            }
        }

        Ok(())
    }

    /// Wait for and accept a single stream connection.
    ///
    /// TODO: This may be obsoleted when Rust gains more support for async fns in traits.
    async fn accept(
        &self,
    ) -> Result<(Listener::Stream, Listener::Addr), io::Error> {
        poll_fn(|ctx| self.listener.poll_accept(ctx)).await
    }
}

//--- Drop

impl<Listener, Buf, Svc, MsgTyp> Drop
    for StreamServer<Listener, Buf, Svc, MsgTyp>
where
    Listener: AsyncAccept + Send + 'static,
{
    fn drop(&mut self) {
        // Shutdown the StreamServer. Don't handle the failure case here as
        // I'm not sure if it's safe to log or write to stderr from a Drop
        // impl.
        let _ = self.shutdown();
    }
}
