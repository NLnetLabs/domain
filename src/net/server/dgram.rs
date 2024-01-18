use core::marker::PhantomData;
use std::{future::poll_fn, string::String, sync::atomic::Ordering};

use std::{
    io,
    sync::{Arc, Mutex},
};

use super::{
    buf::BufSource,
    metrics::ServerMetrics,
    service::{
        CallResult, MsgProvider, Service, ServiceCommand, ServiceError,
        Transaction,
    },
    sock::AsyncDgramSock,
};

use futures::{pin_mut, StreamExt};
use tokio::{io::ReadBuf, sync::watch};

//------------ DgramServer ---------------------------------------------------

/// A server for connecting clients via datagram transport to a [`Service`].
pub struct DgramServer<Sock, Buf, Svc, MsgTyp> {
    command_rx: watch::Receiver<ServiceCommand>,
    command_tx: Arc<Mutex<watch::Sender<ServiceCommand>>>,
    sock: Arc<Sock>,
    buf: Arc<Buf>,
    service: Arc<Svc>,
    metrics: Arc<ServerMetrics>,
    _phantom: std::marker::PhantomData<MsgTyp>,
}

impl<Sock, Buf, Svc, MsgTyp> DgramServer<Sock, Buf, Svc, MsgTyp>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource,
    MsgTyp: MsgProvider<Buf::Output, Msg = MsgTyp>,
    Svc: Service<Buf::Output, MsgTyp>,
{
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
            _phantom: PhantomData,
        }
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
        addr: <Sock as AsyncDgramSock>::Addr,
    ) -> Result<(), ServiceError<Svc::Error>> {
        let msg = MsgTyp::from_octets(buf)
            .map_err(|_| ServiceError::Other("short message".into()))?;

        let metrics = self.metrics.clone();
        let sock = self.sock.clone();
        let txn = self.service.call(msg /* also send client addr */)?;

        tokio::spawn(async move {
            metrics
                .num_inflight_requests
                .fetch_add(1, Ordering::Relaxed);
            match txn {
                Transaction::Single(call_fut) => {
                    if let Ok(call_result) = call_fut.await {
                        Self::handle_call_result(&sock, &addr, call_result)
                            .await;
                    }
                }

                Transaction::Stream(stream) => {
                    pin_mut!(stream);
                    while let Some(response) = stream.next().await {
                        match response {
                            Ok(call_result) => {
                                Self::handle_call_result(
                                    &sock,
                                    &addr,
                                    call_result,
                                )
                                .await;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            metrics
                .num_inflight_requests
                .fetch_sub(1, Ordering::Relaxed);
        });

        Ok(())
    }

    async fn handle_call_result(
        sock: &Sock,
        addr: &Sock::Addr,
        mut call_result: CallResult<Svc::ResponseOctets>,
    ) {
        if let Some(response) = call_result.response() {
            let _ =
                Self::send_to(sock, response.as_dgram_slice(), addr).await;
        }
    }

    async fn recv_from(
        &self,
    ) -> Result<(Buf::Output, Sock::Addr), io::Error> {
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
        dest: &Sock::Addr,
    ) -> Result<(), io::Error> {
        let sent = poll_fn(|ctx| sock.poll_send_to(ctx, data, dest)).await?;
        if sent != data.len() {
            Err(io::Error::new(io::ErrorKind::Other, "short send"))
        } else {
            Ok(())
        }
    }
}
