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
pub struct StreamServer<Listener, Buf, Svc, MsgTyp> {
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

    _phantom: PhantomData<MsgTyp>,
}

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
            _phantom: PhantomData,
        }
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
    /// Start the server.
    pub async fn run(self: Arc<Self>) {
        if let Err(err) = self.run_until_error().await {
            eprintln!("DgramServer: {err}");
        }
    }

    /// Stop the server.
    ///
    /// No new connections will be accepted but in-flight requests will be
    /// allowed to complete and any pending responses, or responses generated
    /// for in-flight requests, will be collected and written back to their
    /// respective client connections before being disconnected.
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
    /// Get a reference to the listener used to accept connections.
    pub fn listener(&self) -> Arc<Listener> {
        self.listener.clone()
    }

    /// Get a reference to the metrics for this server.
    pub fn metrics(&self) -> Arc<ServerMetrics> {
        self.metrics.clone()
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
    async fn run_until_error(&self) -> Result<(), String> {
        let mut command_rx = self.command_rx.clone();

        loop {
            tokio::select! {
                biased;

                command_res = command_rx.changed() => {
                    command_res.map_err(|err|
                        format!("Error while receiving command: {err}"))?;

                    let cmd = *command_rx.borrow_and_update();

                    match cmd {
                        ServiceCommand::Reconfigure { .. } => { /* TODO */ }

                        ServiceCommand::Shutdown => break,

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

                accept_res = self.accept() => {
                    let (stream, _addr) = accept_res
                        .map_err(|err|
                            format!("Error while accepting connection: {err}")
                        )?;

                    let conn_command_rx = self.command_rx.clone();
                    let conn_service = self.service.clone();
                    let conn_buf = self.buf.clone();
                    let conn_metrics = self.metrics.clone();
                    let conn_fut = async move {
                        if let Ok(stream) = stream.await {
                            let conn = Connection::<
                                Listener::StreamType,
                                Buf,
                                Svc,
                                MsgTyp,
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
            }
        }

        Ok(())
    }

    /// Wait for and accept a single stream connection.
    async fn accept(
        &self,
    ) -> Result<(Listener::Stream, Listener::Addr), io::Error> {
        poll_fn(|ctx| self.listener.poll_accept(ctx)).await
    }
}
