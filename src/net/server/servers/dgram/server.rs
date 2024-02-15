use std::fmt::Debug;
use std::net::SocketAddr;
use std::{future::poll_fn, string::String};

use std::{
    io,
    sync::{Arc, Mutex},
};

use tokio::task::JoinHandle;
use tokio::{io::ReadBuf, sync::watch};
use tracing::{enabled, error, trace, Level};

use crate::base::Message;
use crate::net::server::buf::BufSource;
use crate::net::server::error::Error;
use crate::net::server::message::ContextAwareMessage;
use crate::net::server::message::MessageProcessor;
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::middleware::chain::MiddlewareChain;
use crate::net::server::service::{CallResult, Service, ServiceCommand};
use crate::net::server::sock::AsyncDgramSock;
use crate::net::server::util::to_pcap_text;

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

/// Creation
///
impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    #[must_use]
    pub fn new(sock: Sock, buf: Arc<Buf>, service: Arc<Svc>) -> Self {
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
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    /// Get a reference to the source.
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
    pub async fn run(&self)
    where
        Svc::Single: Send,
    {
        if let Err(err) = self.run_until_error().await {
            error!("DgramServer: {err}");
        }
    }

    pub fn shutdown(&self) -> Result<(), Error> {
        self.command_tx
            .lock()
            .unwrap()
            .send(ServiceCommand::Shutdown)
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
                    let (msg, addr, bytes_read) = recv_res
                        .map_err(|err|
                            format!("Error while receiving message: {err}")
                        )?;

                    if enabled!(Level::TRACE) {
                        let pcap_text = to_pcap_text(&msg, bytes_read);
                        trace!(%addr, pcap_text, "Received message");
                    }

                    self.process_request(
                        msg, addr, self.sock.clone(),
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
    type State = Arc<Sock>;

    fn add_context_to_request(
        &self,
        request: Message<Buf::Output>,
        addr: SocketAddr,
    ) -> ContextAwareMessage<Message<Buf::Output>> {
        ContextAwareMessage::new(request, false, addr)
    }

    fn handle_finalized_response(
        CallResult { response, .. }: CallResult<Svc::Target>,
        addr: SocketAddr,
        sock: Self::State,
        _metrics: Arc<ServerMetrics>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let target = response.finish();
            let bytes = target.as_dgram_slice();

            if enabled!(Level::TRACE) {
                let pcap_text = to_pcap_text(bytes, bytes.len());
                trace!(%addr, pcap_text, "Sent response");
            }

            let _ = Self::send_to(&sock, bytes, &addr).await;

            // TODO:
            // metrics.num_pending_writes.store(???, Ordering::Relaxed);
        })
    }
}
