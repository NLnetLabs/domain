use std::{future::poll_fn, sync::atomic::Ordering};

use std::{
    io,
    sync::{Arc, Mutex},
};

use crate::base::Message;

use super::{
    buf::BufSource,
    server::ServerMetrics,
    service::{
        CallResult, Service, ServiceCommand, ServiceError, Transaction,
    },
    sock::AsyncDgramSock,
};

use futures::future::Either;
use futures::{future::select, pin_mut, StreamExt};
use tokio::{io::ReadBuf, sync::watch};

//------------ DgramServer ---------------------------------------------------

pub struct DgramServer<Sock, Buf, Svc> {
    command_rx: watch::Receiver<ServiceCommand>,
    command_tx: Arc<Mutex<watch::Sender<ServiceCommand>>>,
    sock: Arc<Sock>,
    buf: Arc<Buf>,
    service: Arc<Svc>,
    metrics: Arc<ServerMetrics>,
}

impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource,
    Svc: Service<Buf::Output>,
{
    pub fn new(sock: Sock, buf: Arc<Buf>, service: Arc<Svc>) -> Self {
        let (command_tx, command_rx) = watch::channel(ServiceCommand::Init);
        let command_tx = Arc::new(Mutex::new(command_tx));
        let metrics = Arc::new(ServerMetrics::new());

        DgramServer {
            command_tx,
            command_rx,
            sock: sock.into(),
            buf,
            service,
            metrics,
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

    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let mut command_rx = self.command_rx.clone();

        loop {
            let command_fut = command_rx.changed();
            let recv_fut = self.recv_from(); // TODO: time out this read

            pin_mut!(command_fut);
            pin_mut!(recv_fut);

            match (
                select(recv_fut, command_fut).await,
                self.command_rx.clone(), // this is crazy
            )
                .into()
            {
                DgramServerEvent::Recv(msg, addr) => {
                    if let Err(_err) =
                        self.as_ref().process_message(msg, addr)
                    {
                        eprintln!("DgramServer process message error");
                    }
                }
                DgramServerEvent::RecvError(err) => {
                    eprintln!("DgramServer receive message error: {err}");
                    todo!();
                }
                DgramServerEvent::Command(ServiceCommand::Init) => {
                    unreachable!()
                }
                DgramServerEvent::Command(ServiceCommand::Reconfigure {
                    ..
                }) => { /* TODO */ }
                DgramServerEvent::Command(
                    ServiceCommand::CloseConnection,
                ) => {
                    unreachable!()
                }
                DgramServerEvent::Command(ServiceCommand::Shutdown) => {
                    return Ok(());
                }
                DgramServerEvent::CommandError(err) => {
                    eprintln!("DgramServer receive command error: {err}");
                    todo!();
                }
            }
        }
    }

    fn process_message(
        &self,
        buf: <Buf as BufSource>::Output,
        addr: <Sock as AsyncDgramSock>::Addr,
    ) -> Result<(), ServiceError<Svc::Error>> {
        let msg = Message::from_octets(buf)
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

//------------ DgramServerEvent ----------------------------------------------

pub enum DgramServerEvent<Msg, Addr, RecvErr, CommandErr> {
    Recv(Msg, Addr),
    RecvError(RecvErr),
    Command(ServiceCommand),
    CommandError(CommandErr),
}

//------------ From ... for DgramServerEvent ---------------------------------

// Used by DgramServer::run() via select(..).await.into() to make the match
// arms more readable.
impl<Msg, Addr, RecvErr, W, CommandErr, Y>
    From<(
        Either<
            (Result<(Msg, Addr), RecvErr>, W),
            (Result<(), CommandErr>, Y),
        >,
        watch::Receiver<ServiceCommand>,
    )> for DgramServerEvent<Msg, Addr, RecvErr, CommandErr>
{
    fn from(
        (value, mut command_rx): (
            Either<
                (Result<(Msg, Addr), RecvErr>, W),
                (Result<(), CommandErr>, Y),
            >,
            watch::Receiver<ServiceCommand>,
        ),
    ) -> Self {
        match value {
            Either::Left((Ok((msg, addr)), _)) => {
                DgramServerEvent::Recv(msg, addr)
            }
            Either::Left((Err(err), _)) => DgramServerEvent::RecvError(err),
            Either::Right((Ok(()), _)) => {
                let cmd = *command_rx.borrow_and_update();
                DgramServerEvent::Command(cmd)
            }
            Either::Right((Err(err), _)) => {
                DgramServerEvent::CommandError(err)
            }
        }
    }
}
