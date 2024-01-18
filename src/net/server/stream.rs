use super::buf::BufSource;
use super::connection::Connection;
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

pub struct StreamServer<Listener, Buf, Svc, MsgTyp> {
    command_rx: watch::Receiver<ServiceCommand>,
    command_tx: Arc<Mutex<watch::Sender<ServiceCommand>>>,
    listener: Arc<Listener>,
    buf: Arc<Buf>,
    service: Arc<Svc>,
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

    pub async fn run(self: Arc<Self>) {
        if let Err(err) = self.run_until_error().await {
            eprintln!("DgramServer: {err}");
        }
    }

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

    async fn accept(
        &self,
    ) -> Result<(Listener::Stream, Listener::Addr), io::Error> {
        poll_fn(|ctx| self.listener.poll_accept(ctx)).await
    }
}
