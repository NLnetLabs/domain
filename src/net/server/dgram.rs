use core::ops::ControlFlow;
use std::net::SocketAddr;
use std::{future::poll_fn, string::String, sync::atomic::Ordering};

use std::{
    io,
    sync::{Arc, Mutex},
};

use crate::base::Message;

use super::middleware::chain::MiddlewareChain;
use super::service::{ServiceResultItem, Transaction};
use super::ContextAwareMessage;
use super::{
    buf::BufSource,
    metrics::ServerMetrics,
    service::{CallResult, Service, ServiceCommand, ServiceError},
    sock::AsyncDgramSock,
};

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

    pub fn shutdown(
        &self,
    ) -> Result<(), watch::error::SendError<ServiceCommand>> {
        self.command_tx
            .lock()
            .unwrap()
            .send(ServiceCommand::Shutdown)
    }

    pub async fn run(&self)
    where
        Svc::Single: Send,
    {
        if let Err(err) = self.run_until_error().await {
            eprintln!("DgramServer: {err}");
        }
    }

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
                        ServiceCommand::Reconfigure { .. } => { /* TODO */ }

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

                    self.process_message(msg, addr)
                        .map_err(|err|
                            format!("Error while processing message: {err}")
                        )?;
                }
            }
        }

        Ok(())
    }

    fn process_message(
        &self,
        buf: <Buf as BufSource>::Output,
        addr: SocketAddr,
    ) -> Result<(), ServiceError<Svc::Error>>
    where
        Svc::Single: Send,
    {
        let msg = Message::<Buf::Output>::from_octets(buf)
            .map_err(|_| ServiceError::Other("short message".into()))?;

        let msg = ContextAwareMessage::new(msg, false, addr);

        let (msg, txn, last_processor_idx) = self.preprocess_request(msg)?;

        self.postprocess_response(msg, txn, last_processor_idx);

        Ok(())
    }

    // TODO: Deduplicate with Connection.
    #[allow(clippy::type_complexity)]
    fn preprocess_request(
        &self,
        mut msg: ContextAwareMessage<Message<Buf::Output>>,
    ) -> Result<
        (
            Arc<ContextAwareMessage<Message<Buf::Output>>>,
            Transaction<
                ServiceResultItem<Svc::Target, Svc::Error>,
                Svc::Single,
            >,
            Option<usize>,
        ),
        ServiceError<Svc::Error>,
    >
    where
        Svc::Single: Send,
    {
        match &self.middleware_chain {
            Some(middleware_chain) => {
                let res = middleware_chain
                    .preprocess::<Svc::Error, Svc::Single>(
                        &mut msg,
                    );
                let out_msg = Arc::new(msg);
                match res {
                    ControlFlow::Continue(()) => {
                        let txn = self.service.call(out_msg.clone())?;
                        Ok((out_msg, txn, None))
                    }
                    ControlFlow::Break((txn, last_processor_idx)) => {
                        Ok((out_msg, txn, Some(last_processor_idx)))
                    }
                }
            }

            None => {
                let out_msg = Arc::new(msg);
                let txn = self.service.call(out_msg.clone())?;
                Ok((out_msg, txn, None))
            }
        }
    }

    #[allow(clippy::type_complexity)]
    fn postprocess_response(
        &self,
        msg: Arc<ContextAwareMessage<Message<Buf::Output>>>,
        mut txn: Transaction<
            ServiceResultItem<Svc::Target, Svc::Error>,
            Svc::Single,
        >,
        last_processor_id: Option<usize>,
    ) where
        Svc::Single: Send,
    {
        let metrics = self.metrics.clone();
        let sock = self.sock.clone();
        let middleware_chain = self.middleware_chain.clone();
        let msg = Arc::new(msg);

        tokio::spawn(async move {
            // TODO: Shouldn't this counter be incremented just before
            // service.call() is invoked?
            metrics
                .num_inflight_requests
                .fetch_add(1, Ordering::Relaxed);
            while let Some(Ok(mut call_result)) = txn.next().await {
                if let Some(middleware_chain) = &middleware_chain {
                    middleware_chain.postprocess(
                        &msg,
                        &mut call_result.response,
                        last_processor_id,
                    );
                }
                Self::handle_call_result(
                    &sock,
                    &msg.client_addr(),
                    call_result,
                )
                .await;
            }
            metrics
                .num_inflight_requests
                .fetch_sub(1, Ordering::Relaxed);
        });
    }

    async fn handle_call_result(
        sock: &Sock,
        addr: &SocketAddr,
        CallResult { response, .. }: CallResult<Svc::Target>,
    ) {
        let _ = Self::send_to(sock, response.finish().as_dgram_slice(), addr)
            .await;
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
