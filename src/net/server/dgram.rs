use std::net::SocketAddr;
use std::{future::poll_fn, string::String};

use std::{
    io,
    sync::{Arc, Mutex},
};

use super::error::Error;
use super::middleware::chain::MiddlewareChain;
use super::{
    buf::BufSource,
    metrics::ServerMetrics,
    service::{CallResult, Service, ServiceCommand},
    sock::AsyncDgramSock,
};
use super::{MessageProcessor, Server};

use tokio::{io::ReadBuf, sync::watch};

//------------ DgramServer ---------------------------------------------------

/// A server for connecting clients via datagram transport to a [`Service`].
pub struct DgramServer<Sock, Buf, Svc>
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    command_rx: watch::Receiver<ServiceCommand>,
    command_tx: Arc<Mutex<watch::Sender<ServiceCommand>>>,
    sock: Arc<Sock>,
    buf: Arc<Buf>,
    service: Arc<Svc>,
    middleware_chain: Option<MiddlewareChain<Buf::Output, Svc::Target>>,
    metrics: Arc<ServerMetrics>,
}

impl<Sock, Buf, Svc> Server<Sock, Buf, Svc> for DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    #[must_use]
    fn new(sock: Sock, buf: Arc<Buf>, service: Arc<Svc>) -> Self {
        let (command_tx, command_rx) = watch::channel(ServiceCommand::Init);
        let command_tx = Arc::new(Mutex::new(command_tx));
        let metrics = Arc::new(ServerMetrics::connection_less());

        DgramServer {
            command_tx,
            command_rx,
            sock: sock.into(),
            buf,
            service,
            metrics,
            middleware_chain: None,
        }
    }

    #[must_use]
    fn with_middleware(
        mut self,
        middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
    ) -> Self {
        self.middleware_chain = Some(middleware_chain);
        self
    }

    /// Get a reference to the source.
    #[must_use]
    fn source(&self) -> Arc<Sock> {
        self.sock.clone()
    }

    /// Get a reference to the metrics for this server.
    #[must_use]
    fn metrics(&self) -> Arc<ServerMetrics> {
        self.metrics.clone()
    }

    async fn run(&self)
    where
        Svc::Single: Send,
    {
        if let Err(err) = self.run_until_error().await {
            eprintln!("DgramServer: {err}");
        }
    }

    fn shutdown(&self) -> Result<(), Error> {
        self.command_tx
            .lock()
            .unwrap()
            .send(ServiceCommand::Shutdown)
            .map_err(|_| Error::CommandCouldNotBeSent)
    }
}

impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    async fn run_until_error(&self) -> Result<(), String>
    where
        Svc::Single: Send,
    {
        let mut command_rx = self.command_rx.clone();

        loop {
            tokio::select! {
                biased;

                command_res = command_rx.changed() => {
                    command_res.map_err(|err| format!("Error while receiving command: {err}"))?;

                    let cmd = *command_rx.borrow_and_update();

                    match cmd {
                        ServiceCommand::Reconfigure { .. } => {
                            /* TODO */

                            // TODO: Support dynamic replacement of the
                            // middleware chain? E.g. via
                            // ArcSwapOption<MiddlewareChain> instead of
                            // Option?
                        }

                        ServiceCommand::Shutdown => break,

                        ServiceCommand::Init => {
                            // The initial "Init" value in the watch channel is never
                            // actually seen because the select Into impl only calls
                            // watch::Receiver::borrow_and_update() AFTER changed()
                            // signals that a new value has been placed in the watch
                            // channel. So the only way to end up here would be if
                            // we somehow wrongly placed another ServiceCommand::Init
                            // value into the watch channel after the initial one.
                            unreachable!()
                        }

                        ServiceCommand::CloseConnection => {
                            // A datagram server does not have connections so handling
                            // the close of a connection which can never happen has no
                            // meaning as it cannot occur.
                            unreachable!()
                        }
                    }
                }

                recv_res = self.recv_from() => {
                    let (msg, addr) = recv_res
                        .map_err(|err|
                            format!("Error while receiving message: {err}")
                        )?;

                    <Self as MessageProcessor<Buf, Svc>>::process_message(
                        msg, addr, self.sock.clone(),
                        self.middleware_chain.clone(),
                        &self.service,
                        self.metrics.clone()
                    ).await
                        .map_err(|err|
                            format!("Error while processing message: {err}")
                        )?;
                }
            }
        }

        Ok(())
    }

    async fn recv_from(
        &self,
    ) -> Result<(Buf::Output, SocketAddr), io::Error> {
        let mut res = self.buf.create_buf();
        let addr = {
            let mut buf = ReadBuf::new(res.as_mut());
            poll_fn(|ctx| self.sock.poll_recv_from(ctx, &mut buf)).await?
        };
        Ok((res, addr))
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

impl<Sock, Buf, Svc> MessageProcessor<Buf, Svc>
    for DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    type State = Arc<Sock>;

    async fn handle_finalized_response(
        CallResult { response, .. }: CallResult<Svc::Target>,
        addr: SocketAddr,
        sock: &Self::State,
        _metrics: &Arc<ServerMetrics>,
    ) {
        let _ =
            Self::send_to(sock, response.finish().as_dgram_slice(), &addr)
                .await;

        // TODO:
        // metrics.num_pending_writes.store(???, Ordering::Relaxed);
    }
}
