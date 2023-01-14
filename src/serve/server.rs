//! Networking for a DNS server.
//!
//! DNS servers can be implemented atop various protocols which broadly fall
//! into two categories: connection-less and connection-oriented.
//!
//! Connection-less protocols receive incoming DNS messages independently of
//! each other with no concept of an established connection. Conversely
//! connection-oriented protocols have connection setup and tear down phases
//! used to establish connections between clients and the server and messages
//! are listened for on a per-connection basis.
//!
//! This module offers a consistent interface to the DNS server implementor
//! for receiving and responding to DNS messages, irrespective of the
//! semantics of the underlying transport.
//!
//! The DNS server implementor provides a [Service] implementation which
//! handles received messages and generates responses. The [Service] impl can
//! be used with any of the server implementations offered by this module.

use core::{
    future::poll_fn,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};
use std::{io, sync::Mutex, time::Duration};

use std::sync::Arc;

use futures::{
    future::{select, Either, Future},
    pin_mut,
    stream::Stream,
    StreamExt,
};

use std::string::String;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{
        mpsc,
        watch::{self, error::RecvError},
    },
    time::{error::Elapsed, timeout},
};

use crate::base::{octets::OctetsBuilder, Message, StreamTarget};

use super::sock::{AsyncAccept, AsyncDgramSock};

//------------ ServiceError --------------------------------------------------

pub enum ServerEvent<T, U, V, W> {
    Accept(T, U),
    AcceptError(V),
    Command(ServiceCommand),
    CommandError(W),
}

pub enum ConnectionEvent<T, U> {
    CallCompleted(CallResult<T>),
    ConnectionClosed,
    ReadSucceeded(U),
    ReadTimedOut,
}

pub enum ServiceError<T> {
    ServiceSpecificError(T),
    ShuttingDown,
    Other(String),
}

impl<T> From<RecvError> for ServiceError<T> {
    fn from(err: RecvError) -> Self {
        ServiceError::Other(format!("RecvError: {err}"))
    }
}

//------------ ServiceCommand ------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub enum ServiceCommand {
    CloseConnection,
    Init,
    Reconfigure { read_timeout: Duration },
    Shutdown,
}

//------------ CallResult ----------------------------------------------------

pub struct CallResult<ResponseOctets> {
    response: Option<StreamTarget<ResponseOctets>>,
    command: Option<ServiceCommand>,
}

/// Directions to a server on how to respond to a request.
///
/// [`CallResult`] supports the following ways to handle a client request:
///
///   - Respond to the client. This is the default case.
///
///   - Respond to the client and adjust the servers handling of requests.
///     This could be required for example to honour a client request EDNS(0)
///     OPT RR that requests that the timeout from server to client be altered.
///
///   - Ignore the client request, e.g. due to policy.
///
///   - Terminate the connection with the client, e.g. due to policy or
///     or because the service is shutting down.
///
/// For reasons of policy it may be necessary to ignore certain client
/// requests without sending a response
impl<ResponseOctets> CallResult<ResponseOctets> {
    pub fn new(response: StreamTarget<ResponseOctets>) -> Self {
        Self {
            response: Some(response),
            command: None,
        }
    }

    pub fn with_feedback(
        response: StreamTarget<ResponseOctets>,
        command: ServiceCommand,
    ) -> Self {
        Self {
            response: Some(response),
            command: Some(command),
        }
    }

    pub fn per_policy(
        command: ServiceCommand,
        response: Option<StreamTarget<ResponseOctets>>,
    ) -> Self {
        Self {
            response,
            command: Some(command),
        }
    }

    pub fn response(&mut self) -> Option<StreamTarget<ResponseOctets>> {
        self.response.take()
    }

    pub fn command(&mut self) -> Option<ServiceCommand> {
        self.command.take()
    }
}

//------------ Service -------------------------------------------------------

/// A Service is responsible for generating responses to received DNS messages.
///
/// Responses are encapsulated inside a [Transaction] which is either [Single]
/// (a single response) or [Stream] (a stream of responses, e.g. for a zone
/// transfer).
pub trait Service<RequestOctets: AsRef<[u8]>> {
    type Error: Send + Sync + 'static;

    type ResponseOctets: OctetsBuilder
        + Send
        + Sync
        + 'static
        + std::convert::AsRef<[u8]>;

    type Single: Future<
            Output = Result<
                CallResult<Self::ResponseOctets>,
                ServiceError<Self::Error>,
            >,
        > + Send
        + 'static;

    type Stream: Stream<
            Item = Result<
                CallResult<Self::ResponseOctets>,
                ServiceError<Self::Error>,
            >,
        > + Send
        + 'static;

    fn poll_ready(
        &self,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<(), ServiceError<Self::Error>>> {
        Poll::Ready(Ok(()))
    }

    fn call(
        &self,
        message: Message<RequestOctets>,
    ) -> Result<
        Transaction<Self::Single, Self::Stream>,
        ServiceError<Self::Error>,
    >;
}

/*impl<F, RequestOctets, ResponseOctets, Single, Strm> Service<RequestOctets>
    for F
where
    F: Fn(Message<RequestOctets>) -> Transaction<Single, Strm>,
    RequestOctets: AsRef<[u8]>,
    ResponseOctets:
        OctetsBuilder + Send + Sync + 'static + std::convert::AsRef<[u8]>,
    Single: Future<Output = Result<StreamTarget<ResponseOctets>, io::Error>>
        + Send
        + 'static,
    Strm: Stream<Item = Result<StreamTarget<ResponseOctets>, io::Error>>
        + Send
        + 'static,
{
    type Error = ();
    type ResponseOctets = ResponseOctets;
    type Single = Single;
    type Stream = Strm;

    fn call(
        &self,
        message: Message<RequestOctets>,
    ) -> Transaction<Self::Single, Self::Stream> {
        (*self)(message)
    }
}*/

//------------ Transaction ---------------------------------------------------

/// A server transaction generating the responses for a request.
pub enum Transaction<SingleFut, StreamFut>
where
    SingleFut: Future,
    StreamFut: Stream,
{
    /// The transaction will be concluded with a single response.
    Single(SingleFut),

    /// The transaction will results in stream of multiple responses.
    Stream(StreamFut),
}

//------------ BufSource ----------------------------------------------------

pub trait BufSource {
    type Output: AsRef<[u8]> + AsMut<[u8]>;

    fn create_buf(&self) -> Self::Output;
    fn create_sized(&self, size: usize) -> Self::Output;
}

//------------ ServerMetrics -------------------------------------------------

#[derive(Debug)]
pub struct ServerMetrics {
    num_connections: Option<AtomicUsize>,
    num_inflight_requests: AtomicUsize,
    num_pending_writes: AtomicUsize,
}

impl ServerMetrics {
    pub fn new() -> Self {
        Self {
            num_connections: None,
            num_inflight_requests: AtomicUsize::new(0),
            num_pending_writes: AtomicUsize::new(0),
        }
    }

    pub fn num_connections(&self) -> Option<usize> {
        self.num_connections
            .as_ref()
            .map(|atomic| atomic.load(Ordering::Relaxed))
    }

    pub fn num_inflight_requests(&self) -> usize {
        self.num_inflight_requests.load(Ordering::Relaxed)
    }

    pub fn num_pending_writes(&self) -> usize {
        self.num_pending_writes.load(Ordering::Relaxed)
    }
}

//------------ DgramServer ---------------------------------------------------

pub struct DgramServer<Sock, Buf, Svc> {
    sock: Arc<Sock>,
    buf: Buf,
    service: Svc,
    metrics: Arc<ServerMetrics>,
}

impl<Sock, Buf, Svc> DgramServer<Sock, Buf, Svc>
where
    Sock: AsyncDgramSock + Send + Sync + 'static,
    Buf: BufSource,
    Svc: Service<Buf::Output>,
{
    pub fn new(sock: Sock, buf: Buf, service: Svc) -> Self {
        let metrics = Arc::new(ServerMetrics::new());

        DgramServer {
            sock: sock.into(),
            buf,
            service,
            metrics,
        }
    }

    pub async fn run(self) -> Result<(), io::Error> {
        loop {
            let (msg, addr) = self.recv_from().await?;
            let msg = match Message::from_octets(msg) {
                Ok(msg) => msg,
                Err(_) => continue,
            };

            let metrics = self.metrics.clone();
            let sock = self.sock.clone();
            let txn = self.service.call(msg);
            tokio::spawn(async move {
                metrics
                    .num_inflight_requests
                    .fetch_add(1, Ordering::Relaxed);
                match txn {
                    Ok(Transaction::Single(call_fut)) => {
                        if let Ok(call_result) = call_fut.await {
                            Self::handle_call_result(
                                &sock,
                                &addr,
                                call_result,
                            )
                            .await;
                        }
                    }
                    Ok(Transaction::Stream(stream)) => {
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
                    Err(_err) => todo!(),
                }
                metrics
                    .num_inflight_requests
                    .fetch_sub(1, Ordering::Relaxed);
            });
        }
    }

    async fn handle_call_result(
        sock: &Sock,
        addr: &Sock::Addr,
        mut call_result: CallResult<Svc::ResponseOctets>,
    ) {
        if let Some(response) = call_result.response() {
            let _ = Self::send_to(sock, response.as_dgram_slice(), addr);
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

//------------ StreamServer --------------------------------------------------

pub struct StreamServer<Listener, Buf, Svc> {
    command_rx: watch::Receiver<ServiceCommand>,
    command_tx: Arc<Mutex<watch::Sender<ServiceCommand>>>,
    listener: Arc<Listener>,
    buf: Arc<Buf>,
    service: Arc<Svc>,
    metrics: Arc<ServerMetrics>,
}

impl<Listener, Buf, Svc> StreamServer<Listener, Buf, Svc>
where
    Listener: AsyncAccept + Send + 'static,
    Listener::Stream: AsyncRead + AsyncWrite + Send + Sync + 'static,
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    pub fn new(listener: Listener, buf: Buf, service: Arc<Svc>) -> Self {
        let (command_tx, command_rx) = watch::channel(ServiceCommand::Init);
        let command_tx = Arc::new(Mutex::new(command_tx));

        let listener = Arc::new(listener);

        let mut metrics = ServerMetrics::new();
        metrics.num_connections.replace(AtomicUsize::new(0));
        let metrics = Arc::new(metrics);

        StreamServer {
            command_tx,
            command_rx,
            listener,
            buf: buf.into(),
            service,
            metrics,
        }
    }

    pub fn listener(&self) -> Arc<Listener> {
        self.listener.clone()
    }

    pub fn shutdown(
        &self,
    ) -> Result<(), watch::error::SendError<ServiceCommand>> {
        self.command_tx
            .lock()
            .unwrap()
            .send(ServiceCommand::Shutdown)
    }

    pub async fn run(self: Arc<Self>) -> Result<(), io::Error> {
        let mut command_rx = self.command_rx.clone();

        loop {
            let command_fut = command_rx.changed();
            let accept_fut = self.accept();

            pin_mut!(command_fut);
            pin_mut!(accept_fut);

            match (
                select(accept_fut, command_fut).await,
                self.command_rx.clone(),
            )
                .into()
            {
                ServerEvent::Accept(stream, _addr) => {
                    let buf = self.buf.clone();
                    let metrics = self.metrics.clone();
                    let service = self.service.clone();

                    tokio::spawn(async move {
                        metrics
                            .num_connections
                            .as_ref()
                            .unwrap()
                            .fetch_add(1, Ordering::Relaxed);
                        let _ =
                            Self::conn(stream, buf, service, metrics.clone())
                                .await;
                        metrics
                            .num_connections
                            .as_ref()
                            .unwrap()
                            .fetch_sub(1, Ordering::Relaxed);
                    });
                }

                ServerEvent::AcceptError(_err) => {
                    eprintln!("Accept err");
                    todo!()
                }

                ServerEvent::Command(ServiceCommand::Init) => unreachable!(),

                ServerEvent::Command(ServiceCommand::Reconfigure {
                    ..
                }) => { /* TO DO */ }

                ServerEvent::Command(ServiceCommand::CloseConnection {
                    ..
                }) => { /* N/A */ }

                ServerEvent::Command(ServiceCommand::Shutdown) => {
                    return Ok(())
                }

                ServerEvent::CommandError(err) => {
                    eprintln!("StreamServer receive command error: {err}");
                    todo!();
                }
            }
        }
    }

    async fn accept(
        &self,
    ) -> Result<(Listener::Stream, Listener::Addr), io::Error> {
        poll_fn(|ctx| self.listener.poll_accept(ctx)).await
    }

    async fn conn(
        stream: Listener::Stream,
        buf_source: Arc<Buf>,
        service: Arc<Svc>,
        metrics: Arc<ServerMetrics>,
    ) -> Result<(), io::Error> {
        let (mut stream_rx, mut write) = tokio::io::split(stream);
        let (call_res_q_tx, mut call_res_q_rx) =
            mpsc::channel::<CallResult<Svc::ResponseOctets>>(10); // XXX Channel length?
        let mut max_read = Duration::from_millis(10000);
        let mut size_buf = buf_source.create_sized(2);

        loop {
            let mut msg_buf = None;

            let mut evt = Self::read_stream(
                max_read,
                &mut stream_rx,
                &mut size_buf,
                &mut call_res_q_rx,
            )
            .await;

            if let ConnectionEvent::ReadSucceeded(size) = evt {
                // Read the actual message bytes
                let mut buf = buf_source.create_sized(size);
                if buf.as_ref().len() < size {
                    // XXX Maybe do something better here?
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "short buf",
                    ));
                }

                evt = Self::read_stream(
                    max_read,
                    &mut stream_rx,
                    &mut buf,
                    &mut call_res_q_rx,
                )
                .await;
                msg_buf = Some(buf);
            };

            match evt {
                ConnectionEvent::ConnectionClosed => {
                    Self::flush_write_queue(
                        &mut call_res_q_rx,
                        &mut write,
                        &metrics,
                        &mut max_read,
                    )
                    .await;
                    return Ok(());
                }
                ConnectionEvent::ReadSucceeded(_size) => {}
                ConnectionEvent::ReadTimedOut => continue,
                ConnectionEvent::CallCompleted(res) => {
                    Self::apply_call_result(
                        res,
                        &mut write,
                        &metrics,
                        &mut max_read,
                    )
                    .await;
                    continue;
                }
            }

            let msg =
                Message::from_octets(msg_buf.unwrap()).map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "short message")
                })?;

            match service.call(msg /* also send requester address etc */) {
                Ok(txn) => {
                    let metrics = metrics.clone();
                    let tx = call_res_q_tx.clone();
                    tokio::spawn(async move {
                        metrics
                            .num_inflight_requests
                            .fetch_add(1, Ordering::Relaxed);
                        match txn {
                            Transaction::Single(call_fut) => {
                                if let Ok(call_result) = call_fut.await {
                                    Self::handle_call_result(
                                        &tx,
                                        call_result,
                                        &metrics,
                                    )
                                    .await
                                }
                            }
                            Transaction::Stream(stream) => {
                                pin_mut!(stream);
                                while let Some(call_result) =
                                    stream.next().await
                                {
                                    match call_result {
                                        Ok(call_result) => {
                                            Self::handle_call_result(
                                                &tx,
                                                call_result,
                                                &metrics,
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
                }
                Err(ServiceError::ShuttingDown) => return Ok(()),
                Err(ServiceError::ServiceSpecificError(_err)) => todo!(),
                Err(ServiceError::Other(_err)) => todo!(),
            }
        }
    }

    async fn handle_call_result(
        tx: &mpsc::Sender<CallResult<Svc::ResponseOctets>>,
        mut call_result: CallResult<Svc::ResponseOctets>,
        metrics: &Arc<ServerMetrics>,
    ) {
        if let Some(response) = call_result.response() {
            let call_result = if let Some(command) = call_result.command() {
                CallResult::with_feedback(response, command)
            } else {
                CallResult::new(response)
            };

            if let Err(err) = tx.send(call_result).await {
                eprintln!(
                    "StreamServer: Error while queuing response: {err}"
                );
            }
            metrics
                .num_pending_writes
                .store(tx.max_capacity() - tx.capacity(), Ordering::Relaxed);
        }
    }

    async fn apply_call_result(
        mut call_result: CallResult<
            <Svc as Service<<Buf as BufSource>::Output>>::ResponseOctets,
        >,
        write: &mut tokio::io::WriteHalf<<Listener as AsyncAccept>::Stream>,
        metrics: &Arc<ServerMetrics>,
        max_read: &mut Duration,
    ) {
        if let Some(msg) = call_result.response() {
            // TODO: spawn this as a task and serialize access to write with a lock?
            if let Err(err) = write.write_all(msg.as_stream_slice()).await {
                eprintln!("Write error: {err}")
            }
            metrics.num_pending_writes.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(cmd) = call_result.command() {
            match cmd {
                ServiceCommand::CloseConnection { .. } => todo!(),
                ServiceCommand::Init => todo!(),
                ServiceCommand::Reconfigure { read_timeout } => {
                    *max_read = read_timeout
                }
                ServiceCommand::Shutdown => write.shutdown().await.unwrap(),
            }
        }
    }

    async fn flush_write_queue(
        rx: &mut mpsc::Receiver<
            CallResult<
                <Svc as Service<<Buf as BufSource>::Output>>::ResponseOctets,
            >,
        >,
        write: &mut tokio::io::WriteHalf<<Listener as AsyncAccept>::Stream>,
        metrics: &Arc<ServerMetrics>,
        max_read: &mut Duration,
    ) {
        // Stop accepting new response messages (should we check
        // for in-flight messages that haven't generated a response
        // yet but should be allowed to do so?) so that we can flush
        // the write queue and exit this connection handler.
        rx.close();
        while let Some(res) = rx.recv().await {
            Self::apply_call_result(res, write, metrics, max_read).await;
        }
    }

    async fn read_stream(
        max_read: Duration,
        stream_rx: &mut tokio::io::ReadHalf<
            <Listener as AsyncAccept>::Stream,
        >,
        size_buf: &mut <Buf as BufSource>::Output,
        call_res_q_rx: &mut mpsc::Receiver<
            CallResult<
                <Svc as Service<<Buf as BufSource>::Output>>::ResponseOctets,
            >,
        >,
    ) -> ConnectionEvent<
        <Svc as Service<<Buf as BufSource>::Output>>::ResponseOctets,
        usize,
    > {
        let b = timeout(max_read, stream_rx.read_exact(size_buf.as_mut()));
        let a = call_res_q_rx.recv();
        pin_mut!(b);
        pin_mut!(a);
        select(a, b).await.into()
    }
}

impl<T, U, V, W, X, Y>
    From<(
        Either<(Result<(T, U), V>, W), (Result<(), X>, Y)>,
        watch::Receiver<ServiceCommand>,
    )> for ServerEvent<T, U, V, X>
{
    fn from(
        (value, mut command_rx): (
            Either<(Result<(T, U), V>, W), (Result<(), X>, Y)>,
            watch::Receiver<ServiceCommand>,
        ),
    ) -> Self {
        match value {
            Either::Left((Ok((stream, addr)), _)) => {
                ServerEvent::Accept(stream, addr)
            }
            Either::Left((Err(err), _)) => ServerEvent::AcceptError(err),
            Either::Right((Ok(()), _)) => {
                let cmd = *command_rx.borrow_and_update();
                ServerEvent::Command(cmd)
            }
            Either::Right((Err(err), _)) => ServerEvent::CommandError(err),
        }
    }
}

impl<T, U, V, W, X>
    From<
        Either<
            (Option<CallResult<T>>, U),
            (Result<Result<V, W>, Elapsed>, X),
        >,
    > for ConnectionEvent<T, V>
where
    W: std::fmt::Display,
{
    fn from(
        select_res: Either<
            (Option<CallResult<T>>, U),
            (Result<Result<V, W>, Elapsed>, X),
        >,
    ) -> Self {
        match select_res {
            Either::Left((Some(call_result), _)) => {
                ConnectionEvent::CallCompleted(call_result)
            }

            // The write queue is empty and the receiver has been
            // closed so no new responses can be queued, i.e. we
            // have finished.
            Either::Left((None, _)) => ConnectionEvent::ConnectionClosed,

            // The read succeeded, pass the value read onwards to
            // where we read that many bytes of actual message
            Either::Right((Ok(Ok(size)), _)) => {
                ConnectionEvent::ReadSucceeded(size)
            }

            // The read failed, did the client close the connection?
            // We will clean up and exit this connection handler.
            Either::Right((Ok(Err(_err)), _)) => {
                ConnectionEvent::ConnectionClosed
            }

            // The read timed out, try again
            Either::Right((Err(_err), _)) => ConnectionEvent::ReadTimedOut,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::pin::Pin;
    use core::str::FromStr;
    use core::sync::atomic::AtomicBool;
    use core::task::Context;
    use core::task::Poll;
    use std::io;
    use std::sync::Mutex;
    use std::time::Duration;

    use futures::Future;
    use futures::Stream;
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::vec::Vec;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio::time::Instant;

    use crate::base::Dname;
    use crate::base::MessageBuilder;
    use crate::base::Rtype;
    use crate::base::StaticCompressor;
    use crate::base::{
        /*iana::Rcode, octets::OctetsRef,*/ Message,
        /*MessageBuilder,*/ StreamTarget,
    };
    use crate::serve::sock::AsyncAccept;

    use super::{BufSource, Service, Transaction};

    /*fn service<RequestOctets: AsRef<[u8]> + Send + Sync + 'static>(
        count: Arc<AtomicU8>,
    ) -> impl Service<RequestOctets>
    where
        for<'a> &'a RequestOctets: OctetsRef,
    {
        #[allow(clippy::type_complexity)]
        fn query<RequestOctets: AsRef<[u8]>>(
            count: Arc<AtomicU8>,
            msg: Message<RequestOctets>,
        ) -> Transaction<
            impl Future<Output = Result<StreamTarget<Vec<u8>>, io::Error>>,
            Once<Pending<Result<StreamTarget<Vec<u8>>, io::Error>>>,
        >
        where
            for<'a> &'a RequestOctets: OctetsRef,
        {
            let txn = Transaction::Single(async move {
                let res = MessageBuilder::new_stream_vec();
                let answer = res.start_answer(&msg, Rcode::NoError).unwrap();
                Ok(answer.finish())
            });

            let cnt = count.fetch_add(1, Ordering::Relaxed);
            if cnt >= 50 {
                txn.terminate()
            } else {
                txn
            }
        }

        move |msg| query(count.clone(), msg)
    }*/

    struct MockStream {
        last_ready: Mutex<Option<Instant>>,
        messages_to_read: Mutex<VecDeque<Vec<u8>>>,
        new_message_every: Duration,
    }

    impl MockStream {
        fn new(
            messages_to_read: VecDeque<Vec<u8>>,
            new_message_every: Duration,
        ) -> Self {
            Self {
                last_ready: Mutex::new(Option::None),
                messages_to_read: Mutex::new(messages_to_read),
                new_message_every,
            }
        }

        fn _last_ready(&self) -> Option<Instant> {
            self.last_ready.lock().unwrap().clone()
        }

        fn _messages_remaining(&self) -> usize {
            self.messages_to_read.lock().unwrap().len()
        }
    }

    impl AsyncRead for MockStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut last_ready = self.last_ready.lock().unwrap();

            if last_ready
                .map(|instant| instant.elapsed() > self.new_message_every)
                .unwrap_or(true)
            {
                let mut messages_to_read =
                    self.messages_to_read.lock().unwrap();
                match buf.remaining() {
                    2 => {
                        // Initial read: return the number of bytes that will follow
                        if let Some(next_msg) = messages_to_read.get(0) {
                            let next_msg_len =
                                u16::try_from(next_msg.len()).unwrap();
                            buf.put_slice(&next_msg_len.to_be_bytes());
                            last_ready.replace(Instant::now());
                            return Poll::Ready(Ok(()));
                        } else {
                            // End of stream
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "mock connection disconnect",
                            )));
                        }
                    }
                    _ => {
                        // subsequent read, return the message bytes
                        if let Some(msg) = messages_to_read.pop_front() {
                            buf.put_slice(&msg);
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
            }

            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(500)).await;
                waker.wake();
            });

            Poll::Pending
        }
    }

    impl AsyncWrite for MockStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct MockListener {
        ready: Arc<AtomicBool>,
        last_accept: Mutex<Option<Instant>>,
        streams_to_read: Mutex<VecDeque<(Duration, VecDeque<Vec<u8>>)>>,
        new_client_every: Duration,
    }

    impl MockListener {
        fn new(
            streams_to_read: VecDeque<(Duration, VecDeque<Vec<u8>>)>,
            new_client_every: Duration,
        ) -> Self {
            Self {
                ready: Arc::new(AtomicBool::new(false)),
                streams_to_read: Mutex::new(streams_to_read),
                last_accept: Mutex::new(Option::None),
                new_client_every,
            }
        }

        fn get_ready_flag(&self) -> Arc<AtomicBool> {
            self.ready.clone()
        }

        fn _ready(&self) -> bool {
            self.ready.load(Ordering::Relaxed)
        }

        fn _last_accept(&self) -> Option<Instant> {
            self.last_accept.lock().unwrap().clone()
        }

        fn streams_remaining(&self) -> usize {
            self.streams_to_read.lock().unwrap().len()
        }
    }

    impl AsyncAccept for MockListener {
        type Addr = ();

        type Stream = MockStream;

        fn poll_accept(
            &self,
            cx: &mut Context,
        ) -> Poll<Result<(Self::Stream, Self::Addr), io::Error>> {
            match self.ready.load(Ordering::Relaxed) {
                true => {
                    let mut last_accept = self.last_accept.lock().unwrap();
                    if last_accept
                        .map(|instant| {
                            instant.elapsed() > self.new_client_every
                        })
                        .unwrap_or(true)
                    {
                        let mut streams_to_read =
                            self.streams_to_read.lock().unwrap();
                        if let Some((new_message_every, messages)) =
                            streams_to_read.pop_front()
                        {
                            last_accept.replace(Instant::now());
                            return Poll::Ready(Ok((
                                MockStream::new(messages, new_message_every),
                                (),
                            )));
                        } else {
                            //eprintln!(
                            //    "Accept failing, no more clients to simulate"
                            //);
                        }
                    } else {
                        //eprintln!("Accept failing, not time yet for the next client");
                    }
                }
                false => {
                    //eprintln!("Accept failing, not ready to let clients connect yet");
                }
            }

            let waker = cx.waker().clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                waker.wake();
            });

            Poll::Pending
        }
    }

    struct MockBufSource;
    impl BufSource for MockBufSource {
        type Output = Vec<u8>;

        fn create_buf(&self) -> Self::Output {
            vec![0; 1024]
        }

        fn create_sized(&self, size: usize) -> Self::Output {
            vec![0; size]
        }
    }

    /*#[tokio::test(flavor = "multi_thread")]
    async fn stop_service_fn_test() {
        let srv_join_handle = {
            let sock = MockSock;
            let buf = MockBufSource;
            let count = Arc::new(AtomicU8::new(0));
            let srv =
                Arc::new(StreamServer::new(sock, buf, service(count).into()));
            let handle = tokio::spawn(srv.clone().run());
            tokio::time::sleep(std::time::Duration::from_millis(2000)).await;
            srv.shutdown(); // without this the task never finishes below when .await'd
            handle
        };

        let _ = srv_join_handle.await;

        tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
    }*/

    struct MySingle;

    impl Future for MySingle {
        type Output = Result<CallResult<Vec<u8>>, ServiceError<()>>;

        fn poll(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Self::Output> {
            Poll::Ready(Ok(CallResult::with_feedback(
                StreamTarget::new_vec(),
                ServiceCommand::Reconfigure {
                    read_timeout: Duration::from_millis(5000),
                },
            )))
        }
    }

    struct MyStream;

    impl Stream for MyStream {
        type Item = Result<CallResult<Vec<u8>>, ServiceError<()>>;

        fn poll_next(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Self::Item>> {
            todo!()
        }
    }

    struct MyService;

    impl MyService {
        fn new() -> Self {
            Self
        }
    }

    impl Service<Vec<u8>> for MyService {
        type Error = ();

        type ResponseOctets = Vec<u8>;

        type Single = MySingle;

        type Stream = MyStream;

        fn call(
            &self,
            _msg: Message<Vec<u8>>,
            // TODO: pass other requestor address details e.g. IP address, port, etc.
        ) -> Result<
            Transaction<Self::Single, Self::Stream>,
            ServiceError<Self::Error>,
        > {
            Ok(Transaction::Single(MySingle))
            // if for some reason the request should not be processed and the
            // connection with the client should be terminated, we can return
            // Transaction::None instead.
        }
    }

    fn mk_query() -> StreamTarget<Vec<u8>> {
        let mut msg = MessageBuilder::from_target(StaticCompressor::new(
            StreamTarget::new_vec(),
        ))
        .unwrap();
        msg.header_mut().set_rd(true);
        msg.header_mut().set_random_id();

        let mut msg = msg.question();
        msg.push((
            Dname::<Vec<u8>>::from_str("example.com.").unwrap(),
            Rtype::A,
        ))
        .unwrap();

        let mut msg = msg.additional();
        msg.opt(|opt| {
            opt.set_udp_payload_size(4096);
            Ok(())
        })
        .unwrap();

        msg.finish().into_target()
    }

    // By using start_paused = true (from tokio feature "test-util") we cause
    // tokio time related types and functions such as Instant and sleep() to
    // signal that time has passed when in fact it actually hasn't, allowing a
    // time dependent test to run much faster without actual periods of
    // waiting to allow time to elapse.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn stop_service_test() {
        let (srv_handle, server_status_printer_handle) = {
            let fast_client = (
                Duration::from_millis(100),
                VecDeque::from([mk_query().as_stream_slice().to_vec()]),
            );
            let slow_client = (
                Duration::from_millis(3000),
                VecDeque::from([
                    mk_query().as_stream_slice().to_vec(),
                    mk_query().as_stream_slice().to_vec(),
                ]),
            );
            let streams_to_read = VecDeque::from([fast_client, slow_client]);
            let new_client_every = Duration::from_millis(2000);
            let listener =
                MockListener::new(streams_to_read, new_client_every);
            let ready_flag = listener.get_ready_flag();

            let buf = MockBufSource;
            let my_service = Arc::new(MyService::new());
            let srv = Arc::new(StreamServer::new(
                listener,
                buf,
                my_service.clone(),
            ));

            let metrics = srv.metrics.clone();
            let server_status_printer_handle = tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    eprintln!(
                        "Server status: #conn={:?}, #req={:?}, #writes={:?}",
                        metrics.num_connections,
                        metrics.num_inflight_requests,
                        metrics.num_pending_writes
                    );
                }
            });

            let srv_handle = tokio::spawn(srv.clone().run());

            eprintln!("Clients sleeping");
            tokio::time::sleep(Duration::from_millis(1000)).await;

            eprintln!("Clients connecting");
            ready_flag.store(true, Ordering::Relaxed);

            // Simulate a wait long enough that all simulated clients had time
            // to connect, communicate and disconnect.
            tokio::time::sleep(Duration::from_millis(15000)).await;

            // Verify that all simulated clients connected.
            assert_eq!(0, srv.listener().streams_remaining());

            // Verify that no requests or responses are in progress still in
            // the server.
            assert_eq!(srv.metrics.num_connections(), Some(0));
            assert_eq!(srv.metrics.num_inflight_requests(), 0);
            assert_eq!(srv.metrics.num_pending_writes(), 0);

            eprint!("Shutting down");
            srv.shutdown().unwrap();
            eprintln!("Shutdown command sent");

            (srv_handle, server_status_printer_handle)
        };

        eprintln!("Waiting for service to shutdown");
        let _ = srv_handle.await;

        // Terminate the task that periodically prints the server status
        server_status_printer_handle.abort();
    }
}
