//! A client transport using a stream socket.

// RFC 7766 describes DNS over TCP
// RFC 7828 describes the edns-tcp-keepalive option

use super::request::{
    ComposeRequest, ComposeRequestMulti, Error, GetResponse,
    GetResponseMulti, SendRequest, SendRequestMulti,
};
use crate::base::iana::{Rcode, Rtype};
use crate::base::message::Message;
use crate::base::message_builder::StreamTarget;
use crate::base::opt::{AllOptData, OptRecord, TcpKeepalive};
use crate::base::{ParsedName, Serial};
use crate::rdata::AllRecordData;
use crate::utils::config::DefMinMax;
use bytes::{Bytes, BytesMut};
use core::cmp;
use octseq::Octets;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec::Vec;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use tracing::trace;

//------------ Configuration Constants ----------------------------------------

/// Default response timeout.
///
/// Note: nsd has 120 seconds, unbound has 3 seconds.
const RESPONSE_TIMEOUT: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(19),
    Duration::from_millis(1),
    Duration::from_secs(600),
);

/// Default idle timeout.
///
/// Note that RFC 7766, Secton 6.2.3 says: "DNS clients SHOULD close the
/// TCP connection of an idle session, unless an idle timeout has been
/// established using some other signalling mechanism, for example,
/// [edns-tcp-keepalive]."
/// However, RFC 7858, Section 3.4 says: "In order to amortize TCP and TLS
/// connection setup costs, clients and servers SHOULD NOT immediately close
/// a connection after each response.  Instead, clients and servers SHOULD
/// reuse existing connections for subsequent queries as long as they have
/// sufficient resources.".
/// We set the default to 10 seconds, which is that same as what stubby
/// uses. Minimum zero to allow idle timeout to be disabled. Assume that
/// one hour is more than enough as maximum.
const IDLE_TIMEOUT: DefMinMax<Duration> = DefMinMax::new(
    Duration::from_secs(10),
    Duration::ZERO,
    Duration::from_secs(3600),
);

/// Capacity of the channel that transports `ChanReq`s.
const DEF_CHAN_CAP: usize = 8;

/// Capacity of a private channel dispatching responses.
const READ_REPLY_CHAN_CAP: usize = 8;

//------------ Config ---------------------------------------------------------

/// Configuration for a stream transport connection.
#[derive(Clone, Debug)]
pub struct Config {
    /// Response timeout currently in effect.
    response_timeout: Duration,

    /// Single response timeout.
    single_response_timeout: Duration,

    /// Streaming response timeout.
    streaming_response_timeout: Duration,

    /// Default idle timeout.
    ///
    /// This value is used if the other side does not send a TcpKeepalive
    /// option.
    idle_timeout: Duration,
}

impl Config {
    /// Creates a new, default config.
    pub fn new() -> Self {
        Default::default()
    }

    /// Returns the response timeout.
    ///
    /// This is the amount of time to wait on a non-idle connection for a
    /// response to an outstanding request.
    pub fn response_timeout(&self) -> Duration {
        self.response_timeout
    }

    /// Sets the response timeout.
    ///
    /// For requests where ComposeRequest::is_streaming() returns true see
    /// set_streaming_response_timeout() instead.
    ///
    /// Excessive values are quietly trimmed.
    //
    //  XXX Maybe that’s wrong and we should rather return an error?
    pub fn set_response_timeout(&mut self, timeout: Duration) {
        self.response_timeout = RESPONSE_TIMEOUT.limit(timeout);
        self.streaming_response_timeout = self.response_timeout;
    }

    /// Returns the streaming response timeout.
    pub fn streaming_response_timeout(&self) -> Duration {
        self.streaming_response_timeout
    }

    /// Sets the streaming response timeout.
    ///
    /// Only used for requests where ComposeRequest::is_streaming() returns
    /// true as it is typically desirable that such response streams be
    /// allowed to complete even if the individual responses arrive very
    /// slowly.
    ///
    /// Excessive values are quietly trimmed.
    pub fn set_streaming_response_timeout(&mut self, timeout: Duration) {
        self.streaming_response_timeout = RESPONSE_TIMEOUT.limit(timeout);
    }

    /// Returns the initial idle timeout, if set.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Sets the initial idle timeout.
    ///
    /// By default the stream is immediately closed if there are no pending
    /// requests or responses.
    ///
    /// Set this to allow requests to be sent in sequence with delays between
    /// such as a SOA query followed by AXFR for more efficient use of the
    /// stream per RFC 9103.
    ///
    /// Note: May be overridden by an RFC 7828 edns-tcp-keepalive timeout
    /// received from a server.
    ///
    /// Excessive values are quietly trimmed.
    pub fn set_idle_timeout(&mut self, timeout: Duration) {
        self.idle_timeout = IDLE_TIMEOUT.limit(timeout)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            response_timeout: RESPONSE_TIMEOUT.default(),
            single_response_timeout: RESPONSE_TIMEOUT.default(),
            streaming_response_timeout: RESPONSE_TIMEOUT.default(),
            idle_timeout: IDLE_TIMEOUT.default(),
        }
    }
}

//------------ Connection -----------------------------------------------------

/// A connection to a single stream transport.
#[derive(Debug)]
pub struct Connection<Req, ReqMulti> {
    /// The sender half of the request channel.
    sender: mpsc::Sender<ChanReq<Req, ReqMulti>>,
}

impl<Req, ReqMulti> Connection<Req, ReqMulti> {
    /// Creates a new stream transport with default configuration.
    ///
    /// Returns a connection and a future that drives the transport using
    /// the provided stream. This future needs to be run while any queries
    /// are active. This is most easly achieved by spawning it into a runtime.
    /// It terminates when the last connection is dropped.
    pub fn new<Stream>(
        stream: Stream,
    ) -> (Self, Transport<Stream, Req, ReqMulti>) {
        Self::with_config(stream, Default::default())
    }

    /// Creates a new stream transport with the given configuration.
    ///
    /// Returns a connection and a future that drives the transport using
    /// the provided stream. This future needs to be run while any queries
    /// are active. This is most easly achieved by spawning it into a runtime.
    /// It terminates when the last connection is dropped.
    pub fn with_config<Stream>(
        stream: Stream,
        config: Config,
    ) -> (Self, Transport<Stream, Req, ReqMulti>) {
        let (sender, transport) = Transport::new(stream, config);
        (Self { sender }, transport)
    }
}

impl<Req, ReqMulti> Connection<Req, ReqMulti>
where
    Req: ComposeRequest + 'static,
    ReqMulti: ComposeRequestMulti + 'static,
{
    /// Start a DNS request.
    ///
    /// This function takes a precomposed message as a parameter and
    /// returns a [`Message`] object wrapped in a [`Result`].
    async fn handle_request_impl(
        self,
        msg: Req,
    ) -> Result<Message<Bytes>, Error> {
        let (sender, receiver) = oneshot::channel();
        let sender = ReplySender::Single(Some(sender));
        let msg = ReqSingleMulti::Single(msg);
        let req = ChanReq { sender, msg };
        self.sender.send(req).await.map_err(|_| {
            // Send error. The receiver is gone, this means that the
            // connection is closed.
            Error::ConnectionClosed
        })?;
        receiver.await.map_err(|_| Error::StreamReceiveError)?
    }

    /// Start a streaming request.
    async fn handle_streaming_request_impl(
        self,
        msg: ReqMulti,
        sender: mpsc::Sender<Result<Option<Message<Bytes>>, Error>>,
    ) -> Result<(), Error> {
        let reply_sender = ReplySender::Stream(sender);
        let msg = ReqSingleMulti::Multi(msg);
        let req = ChanReq {
            sender: reply_sender,
            msg,
        };
        self.sender.send(req).await.map_err(|_| {
            // Send error. The receiver is gone, this means that the
            // connection is closed.
            Error::ConnectionClosed
        })?;
        Ok(())
    }

    /// Returns a request handler for a request.
    pub fn get_request(&self, request_msg: Req) -> Request {
        Request {
            fut: Box::pin(self.clone().handle_request_impl(request_msg)),
        }
    }

    /// Return a multiple-response request handler for a request.
    fn get_streaming_request(&self, request_msg: ReqMulti) -> RequestMulti {
        let (sender, receiver) = mpsc::channel(DEF_CHAN_CAP);
        RequestMulti {
            stream: receiver,
            fut: Some(Box::pin(
                self.clone()
                    .handle_streaming_request_impl(request_msg, sender),
            )),
        }
    }
}

impl<Req, ReqMulti> Clone for Connection<Req, ReqMulti> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<Req, ReqMulti> SendRequest<Req> for Connection<Req, ReqMulti>
where
    Req: ComposeRequest + 'static,
    ReqMulti: ComposeRequestMulti + Debug + Send + Sync + 'static,
{
    fn send_request(
        &self,
        request_msg: Req,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(self.get_request(request_msg))
    }
}

impl<Req, ReqMulti> SendRequestMulti<ReqMulti> for Connection<Req, ReqMulti>
where
    Req: ComposeRequest + Debug + Send + Sync + 'static,
    ReqMulti: ComposeRequestMulti + 'static,
{
    fn send_request(
        &self,
        request_msg: ReqMulti,
    ) -> Box<dyn GetResponseMulti + Send + Sync> {
        Box::new(self.get_streaming_request(request_msg))
    }
}

//------------ Request -------------------------------------------------------

/// An active request.
pub struct Request {
    /// The underlying future.
    fut: Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + Sync>,
    >,
}

impl Request {
    /// Async function that waits for the future stored in Request to complete.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        (&mut self.fut).await
    }
}

impl GetResponse for Request {
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Message<Bytes>, Error>>
                + Send
                + Sync
                + '_,
        >,
    > {
        Box::pin(self.get_response_impl())
    }
}

impl Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("fut", &format_args!("_"))
            .finish()
    }
}

//------------ RequestMulti --------------------------------------------------

/// An active request.
pub struct RequestMulti {
    /// Receiver for a stream of responses.
    stream: mpsc::Receiver<Result<Option<Message<Bytes>>, Error>>,

    /// The underlying future.
    #[allow(clippy::type_complexity)]
    fut: Option<
        Pin<Box<dyn Future<Output = Result<(), Error>> + Send + Sync>>,
    >,
}

impl RequestMulti {
    /// Async function that waits for the future stored in Request to complete.
    async fn get_response_impl(
        &mut self,
    ) -> Result<Option<Message<Bytes>>, Error> {
        if self.fut.is_some() {
            let fut = self.fut.take().expect("Some expected");
            fut.await?;
        }

        // Fetch from the stream
        self.stream
            .recv()
            .await
            .ok_or(Error::ConnectionClosed)
            .map_err(|_| Error::ConnectionClosed)?
    }
}

impl GetResponseMulti for RequestMulti {
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Option<Message<Bytes>>, Error>>
                + Send
                + Sync
                + '_,
        >,
    > {
        let fut = self.get_response_impl();
        Box::pin(fut)
    }
}

impl Debug for RequestMulti {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("fut", &format_args!("_"))
            .finish()
    }
}

//------------ Transport -----------------------------------------------------

/// The underlying machinery of a stream transport.
#[derive(Debug)]
pub struct Transport<Stream, Req, ReqMulti> {
    /// The stream socket towards the remote end.
    stream: Stream,

    /// Transport configuration.
    config: Config,

    /// The receiver half of request channel.
    receiver: mpsc::Receiver<ChanReq<Req, ReqMulti>>,
}

/// This is the type of sender in [ChanReq].
#[derive(Debug)]
enum ReplySender {
    /// Return channel for a single response.
    Single(Option<oneshot::Sender<ChanResp>>),

    /// Return channel for a stream of responses.
    Stream(mpsc::Sender<Result<Option<Message<Bytes>>, Error>>),
}

impl ReplySender {
    /// Send a response.
    async fn send(&mut self, resp: ChanResp) -> Result<(), ()> {
        match self {
            ReplySender::Single(sender) => match sender.take() {
                Some(sender) => sender.send(resp).map_err(|_| ()),
                None => Err(()),
            },
            ReplySender::Stream(sender) => {
                sender.send(resp.map(Some)).await.map_err(|_| ())
            }
        }
    }

    /// Send EOF on a response stream.
    async fn send_eof(&mut self) -> Result<(), ()> {
        match self {
            ReplySender::Single(_) => {
                panic!("cannot send EOF for Single");
            }
            ReplySender::Stream(sender) => {
                sender.send(Ok(None)).await.map_err(|_| ())
            }
        }
    }

    /// Report whether in stream mode or not.
    fn is_stream(&self) -> bool {
        matches!(self, Self::Stream(_))
    }
}

#[derive(Debug)]
/// Enum that can either store a request for a single response or one for
/// multiple responses.
enum ReqSingleMulti<Req, ReqMulti> {
    /// Single response request.
    Single(Req),
    /// Multi-response request.
    Multi(ReqMulti),
}

/// A message from a [`Request`] to start a new request.
#[derive(Debug)]
struct ChanReq<Req, ReqMulti> {
    /// DNS request message
    msg: ReqSingleMulti<Req, ReqMulti>,

    /// Sender to send result back to [`Request`]
    sender: ReplySender,
}

/// A message back to [`Request`] returning a response.
type ChanResp = Result<Message<Bytes>, Error>;

/// Internal datastructure of [Transport::run] to keep track of
/// the status of the connection.
// The types Status and ConnState are only used in Transport
struct Status {
    /// State of the connection.
    state: ConnState,

    /// Do we need to include edns-tcp-keepalive in an outogoing request.
    ///
    /// Typically this is true at the start of the connection and gets
    /// cleared when we successfully managed to include the option in a
    /// request.
    send_keepalive: bool,

    /// Time we are allow to keep the connection open when idle.
    ///
    /// Initially we set the idle timeout to the default in config. A received
    /// edns-tcp-keepalive option may change that.
    idle_timeout: Duration,
}

/// Status of the connection. Used in [`Status`].
enum ConnState {
    /// The connection is in this state from the start and when at least
    /// one active DNS request is present.
    ///
    /// The instant contains the time of the first request or the
    /// most recent response that was received.
    Active(Option<Instant>),

    /// This state represent a connection that went idle and has an
    /// idle timeout.
    ///
    /// The instant contains the time the connection went idle.
    Idle(Instant),

    /// This state represent an idle connection where either there was no
    /// idle timeout or the idle timer expired.
    IdleTimeout,

    /// A read error occurred.
    ReadError(Error),

    /// It took too long to receive a response.
    ReadTimeout,

    /// A write error occurred.
    WriteError(Error),
}

//--- Display
impl std::fmt::Display for ConnState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ConnState::Active(instant) => f.write_fmt(format_args!(
                "Active (since {}s ago)",
                instant
                    .map(|v| Instant::now().duration_since(v).as_secs())
                    .unwrap_or_default()
            )),
            ConnState::Idle(instant) => f.write_fmt(format_args!(
                "Idle (since {}s ago)",
                Instant::now().duration_since(*instant).as_secs()
            )),
            ConnState::IdleTimeout => f.write_str("IdleTimeout"),
            ConnState::ReadError(err) => {
                f.write_fmt(format_args!("ReadError: {err}"))
            }
            ConnState::ReadTimeout => f.write_str("ReadTimeout"),
            ConnState::WriteError(err) => {
                f.write_fmt(format_args!("WriteError: {err}"))
            }
        }
    }
}

#[derive(Debug)]
/// State of an AXFR or IXFR responses stream for detecting the end of the
/// stream.
enum XFRState {
    /// Start of AXFR.
    AXFRInit,
    /// After the first SOA record has been encountered.
    AXFRFirstSoa(Serial),
    /// Start of IXFR.
    IXFRInit,
    /// After the first SOA record has been encountered.
    IXFRFirstSoa(Serial),
    /// After the first SOA record in a diff section has been encountered.
    IXFRFirstDiffSoa(Serial),
    /// After the second SOA record in a diff section has been encountered.
    IXFRSecondDiffSoa(Serial),
    /// End of the stream has been found.
    Done,
    /// An error has occured.
    Error,
}

impl<Stream, Req, ReqMulti> Transport<Stream, Req, ReqMulti> {
    /// Creates a new transport.
    fn new(
        stream: Stream,
        config: Config,
    ) -> (mpsc::Sender<ChanReq<Req, ReqMulti>>, Self) {
        let (sender, receiver) = mpsc::channel(DEF_CHAN_CAP);
        (
            sender,
            Self {
                config,
                stream,
                receiver,
            },
        )
    }
}

impl<Stream, Req, ReqMulti> Transport<Stream, Req, ReqMulti>
where
    Stream: AsyncRead + AsyncWrite,
    Req: ComposeRequest,
    ReqMulti: ComposeRequestMulti,
{
    /// Run the transport machinery.
    pub async fn run(mut self) {
        let (reply_sender, mut reply_receiver) =
            mpsc::channel::<Message<Bytes>>(READ_REPLY_CHAN_CAP);

        let (read_stream, mut write_stream) = tokio::io::split(self.stream);

        let reader_fut = Self::reader(read_stream, reply_sender);
        tokio::pin!(reader_fut);

        let mut status = Status {
            state: ConnState::Active(None),
            idle_timeout: self.config.idle_timeout,
            send_keepalive: true,
        };
        let mut query_vec =
            Queries::<(ChanReq<Req, ReqMulti>, Option<XFRState>)>::new();

        let mut reqmsg: Option<Vec<u8>> = None;
        let mut reqmsg_offset = 0;

        loop {
            let opt_timeout = match status.state {
                ConnState::Active(opt_instant) => {
                    if let Some(instant) = opt_instant {
                        let elapsed = instant.elapsed();
                        if elapsed > self.config.response_timeout {
                            Self::error(
                                Error::StreamReadTimeout,
                                &mut query_vec,
                            );
                            status.state = ConnState::ReadTimeout;
                            break;
                        }
                        Some(self.config.response_timeout - elapsed)
                    } else {
                        None
                    }
                }
                ConnState::Idle(instant) => {
                    let elapsed = instant.elapsed();
                    if elapsed >= status.idle_timeout {
                        // Move to IdleTimeout and end
                        // the loop
                        status.state = ConnState::IdleTimeout;
                        break;
                    }
                    Some(status.idle_timeout - elapsed)
                }
                ConnState::IdleTimeout
                | ConnState::ReadError(_)
                | ConnState::WriteError(_) => None, // No timers here
                ConnState::ReadTimeout => {
                    panic!("should not be in loop with ReadTimeout");
                }
            };

            // For simplicity, make sure we always have a timeout
            let timeout = match opt_timeout {
                Some(timeout) => timeout,
                None =>
                // Just use the response timeout
                {
                    self.config.response_timeout
                }
            };

            let sleep_fut = sleep(timeout);
            let recv_fut = self.receiver.recv();

            let (do_write, msg) = match &reqmsg {
                None => {
                    let msg: &[u8] = &[];
                    (false, msg)
                }
                Some(msg) => {
                    let msg: &[u8] = msg;
                    (true, msg)
                }
            };

            tokio::select! {
                biased;
                res = &mut reader_fut => {
                    match res {
                        Ok(_) =>
                            // The reader should not
                            // terminate without
                            // error.
                            panic!("reader terminated"),
                        Err(error) => {
                            Self::error(error.clone(), &mut query_vec);
                            status.state = ConnState::ReadError(error);
                            // Reader failed. Break
                            // out of loop and
                            // shut down
                            break
                        }
                    }
                }
                opt_answer = reply_receiver.recv() => {
                    let answer = opt_answer.expect("reader died?");
                    // Check for a edns-tcp-keepalive option
                    let opt_record = answer.opt();
                    if let Some(ref opts) = opt_record {
                        Self::handle_opts(opts,
                            &mut status);
                    };
                    drop(opt_record);
                    Self::demux_reply(answer, &mut status, &mut query_vec).await;
                }
                res = write_stream.write(&msg[reqmsg_offset..]),
                if do_write => {
            match res {
            Err(error) => {
                let error =
                Error::StreamWriteError(Arc::new(error));
                Self::error(error.clone(), &mut query_vec);
                status.state =
                ConnState::WriteError(error);
                break;
            }
            Ok(len) => {
                reqmsg_offset += len;
                if reqmsg_offset >= msg.len() {
                reqmsg = None;
                reqmsg_offset = 0;
                }
            }
            }
                }
                res = recv_fut, if !do_write => {
                    match res {
                        Some(req) => {
                            if req.sender.is_stream() {
                                self.config.response_timeout =
                                    self.config.streaming_response_timeout;
                            } else {
                                self.config.response_timeout =
                                    self.config.single_response_timeout;
                            }
                            Self::insert_req(
                                req, &mut status, &mut reqmsg, &mut query_vec
                            );
                        }
                        None => {
                            // All references to the connection object have
                            // been dropped. Shutdown.
                            break;
                        }
                    }
                }
                _ = sleep_fut => {
                    // Timeout expired, just
                    // continue with the loop
                }

            }

            // Check if the connection is idle
            match status.state {
                ConnState::Active(_) | ConnState::Idle(_) => {
                    // Keep going
                }
                ConnState::IdleTimeout => break,
                ConnState::ReadError(_)
                | ConnState::ReadTimeout
                | ConnState::WriteError(_) => {
                    panic!("Should not be here");
                }
            }
        }

        trace!("Closing TCP connecting in state: {}", status.state);

        // Send FIN
        _ = write_stream.shutdown().await;
    }

    /// This function reads a DNS message from the connection and sends
    /// it to [Transport::run].
    ///
    /// Reading has to be done in two steps: first read a two octet value
    /// the specifies the length of the message, and then read in a loop the
    /// body of the message.
    ///
    /// This function is not async cancellation safe.
    async fn reader(
        mut sock: tokio::io::ReadHalf<Stream>,
        sender: mpsc::Sender<Message<Bytes>>,
    ) -> Result<(), Error> {
        loop {
            let read_res = sock.read_u16().await;
            let len = match read_res {
                Ok(len) => len,
                Err(error) => {
                    return Err(Error::StreamReadError(Arc::new(error)));
                }
            } as usize;

            let mut buf = BytesMut::with_capacity(len);

            loop {
                let curlen = buf.len();
                if curlen >= len {
                    if curlen > len {
                        panic!(
                        "reader: got too much data {curlen}, expetect {len}");
                    }

                    // We got what we need
                    break;
                }

                let read_res = sock.read_buf(&mut buf).await;

                match read_res {
                    Ok(readlen) => {
                        if readlen == 0 {
                            return Err(Error::StreamUnexpectedEndOfData);
                        }
                    }
                    Err(error) => {
                        return Err(Error::StreamReadError(Arc::new(error)));
                    }
                };

                // Check if we are done at the head of the loop
            }

            let reply_message = Message::<Bytes>::from_octets(buf.into());
            match reply_message {
                Ok(answer) => {
                    sender
                        .send(answer)
                        .await
                        .expect("can't send reply to run");
                }
                Err(_) => {
                    // The only possible error is short message
                    return Err(Error::ShortMessage);
                }
            }
        }
    }

    /// Reports an error to all outstanding queries.
    fn error(
        error: Error,
        query_vec: &mut Queries<(ChanReq<Req, ReqMulti>, Option<XFRState>)>,
    ) {
        // Update all requests that are in progress. Don't wait for
        // any reply that may be on its way.
        for (mut req, _) in query_vec.drain() {
            _ = req.sender.send(Err(error.clone()));
        }
    }

    /// Handles received EDNS options.
    ///
    /// In particular, it processes the edns-tcp-keepalive option.
    fn handle_opts<Octs: Octets + AsRef<[u8]>>(
        opts: &OptRecord<Octs>,
        status: &mut Status,
    ) {
        // XXX This handles _all_ keepalive options. I think just using the
        //     first option as returned by Opt::tcp_keepalive should be good
        //     enough? -- M.
        for option in opts.opt().iter().flatten() {
            if let AllOptData::TcpKeepalive(tcpkeepalive) = option {
                Self::handle_keepalive(tcpkeepalive, status);
            }
        }
    }

    /// Demultiplexes a response and sends it to the right query.
    ///
    /// In addition, the status is updated to IdleTimeout or Idle if there
    /// are no remaining pending requests.
    async fn demux_reply(
        answer: Message<Bytes>,
        status: &mut Status,
        query_vec: &mut Queries<(ChanReq<Req, ReqMulti>, Option<XFRState>)>,
    ) {
        // We got an answer, reset the timer
        status.state = ConnState::Active(Some(Instant::now()));

        let id = answer.header().id();

        // Get the correct query and send it the reply.
        let (mut req, mut opt_xfr_data) = match query_vec.try_remove(id) {
            Some(req) => req,
            None => {
                // No query with this ID. We should
                // mark the connection as broken
                return;
            }
        };
        let mut send_eof = false;
        let answer = if match &req.msg {
            ReqSingleMulti::Single(msg) => msg.is_answer(answer.for_slice()),
            ReqSingleMulti::Multi(msg) => {
                let xfr_data =
                    opt_xfr_data.expect("xfr_data should be present");
                let (eof, xfr_data, is_answer) =
                    check_stream(msg, xfr_data, &answer);
                send_eof = eof;
                opt_xfr_data = Some(xfr_data);
                is_answer
            }
        } {
            Ok(answer)
        } else {
            Err(Error::WrongReplyForQuery)
        };
        _ = req.sender.send(answer).await;

        if req.sender.is_stream() {
            if send_eof {
                _ = req.sender.send_eof().await;
            } else {
                query_vec.insert_at(id, (req, opt_xfr_data));
            }
        }

        if query_vec.is_empty() {
            // Clear the activity timer. There is no need to do
            // this because state will be set to either IdleTimeout
            // or Idle just below. However, it is nicer to keep
            // this independent.
            status.state = ConnState::Active(None);

            status.state = if status.idle_timeout.is_zero() {
                // Assume that we can just move to IdleTimeout
                // state
                ConnState::IdleTimeout
            } else {
                ConnState::Idle(Instant::now())
            }
        }
    }

    /// Insert a request in query_vec and return the request to be sent
    /// in *reqmsg.
    ///
    /// First the status is checked, an error is returned if not Active or
    /// idle. Addend a edns-tcp-keepalive option if needed.
    // Note: maybe reqmsg should be a return value.
    fn insert_req(
        mut req: ChanReq<Req, ReqMulti>,
        status: &mut Status,
        reqmsg: &mut Option<Vec<u8>>,
        query_vec: &mut Queries<(ChanReq<Req, ReqMulti>, Option<XFRState>)>,
    ) {
        match &status.state {
            ConnState::Active(timer) => {
                // Set timer if we don't have one already
                if timer.is_none() {
                    status.state = ConnState::Active(Some(Instant::now()));
                }
            }
            ConnState::Idle(_) => {
                // Go back to active
                status.state = ConnState::Active(Some(Instant::now()));
            }
            ConnState::IdleTimeout => {
                // The connection has been closed. Report error
                _ = req.sender.send(Err(Error::StreamIdleTimeout));
                return;
            }
            ConnState::ReadError(error) => {
                _ = req.sender.send(Err(error.clone()));
                return;
            }
            ConnState::ReadTimeout => {
                _ = req.sender.send(Err(Error::StreamReadTimeout));
                return;
            }
            ConnState::WriteError(error) => {
                _ = req.sender.send(Err(error.clone()));
                return;
            }
        }

        let xfr_data = match &req.msg {
            ReqSingleMulti::Single(_) => None,
            ReqSingleMulti::Multi(msg) => {
                let qtype = match msg.to_message().and_then(|m| {
                    m.sole_question()
                        .map_err(|_| Error::MessageParseError)
                        .map(|q| q.qtype())
                }) {
                    Ok(msg) => msg,
                    Err(e) => {
                        _ = req.sender.send(Err(e));
                        return;
                    }
                };
                if qtype == Rtype::AXFR {
                    Some(XFRState::AXFRInit)
                } else if qtype == Rtype::IXFR {
                    Some(XFRState::IXFRInit)
                } else {
                    // Stream requests should be either AXFR or IXFR.
                    _ = req.sender.send(Err(Error::FormError));
                    return;
                }
            }
        };

        // Note that insert may fail if there are too many
        // outstanding queries. First call insert before checking
        // send_keepalive.
        let (index, (req, _)) = match query_vec.insert((req, xfr_data)) {
            Ok(res) => res,
            Err((mut req, _)) => {
                // Send an appropriate error and return.
                _ = req
                    .sender
                    .send(Err(Error::StreamTooManyOutstandingQueries));
                return;
            }
        };

        // We set the ID to the array index. Defense in depth
        // suggests that a random ID is better because it works
        // even if TCP sequence numbers could be predicted. However,
        // Section 9.3 of RFC 5452 recommends retrying over TCP
        // if many spoofed answers arrive over UDP: "TCP, by the
        // nature of its use of sequence numbers, is far more
        // resilient against forgery by third parties."

        let hdr = match &mut req.msg {
            ReqSingleMulti::Single(msg) => msg.header_mut(),
            ReqSingleMulti::Multi(msg) => msg.header_mut(),
        };
        hdr.set_id(index);

        if status.send_keepalive
            && match &mut req.msg {
                ReqSingleMulti::Single(msg) => {
                    msg.add_opt(&TcpKeepalive::new(None)).is_ok()
                }
                ReqSingleMulti::Multi(msg) => {
                    msg.add_opt(&TcpKeepalive::new(None)).is_ok()
                }
            }
        {
            status.send_keepalive = false;
        }

        match Self::convert_query(&req.msg) {
            Ok(msg) => {
                *reqmsg = Some(msg);
            }
            Err(err) => {
                // Take the sender out again and return the error.
                if let Some((mut req, _)) = query_vec.try_remove(index) {
                    _ = req.sender.send(Err(err));
                }
            }
        }
    }

    /// Handle a received edns-tcp-keepalive option.
    fn handle_keepalive(opt_value: TcpKeepalive, status: &mut Status) {
        if let Some(value) = opt_value.timeout() {
            let value_dur = Duration::from(value);
            status.idle_timeout = value_dur;
        }
    }

    /// Convert the query message to a vector.
    fn convert_query(
        msg: &ReqSingleMulti<Req, ReqMulti>,
    ) -> Result<Vec<u8>, Error> {
        match msg {
            ReqSingleMulti::Single(msg) => {
                let mut target = StreamTarget::new_vec();
                msg.append_message(&mut target)
                    .map_err(|_| Error::StreamLongMessage)?;
                Ok(target.into_target())
            }
            ReqSingleMulti::Multi(msg) => {
                let target = StreamTarget::new_vec();
                let target = msg
                    .append_message(target)
                    .map_err(|_| Error::StreamLongMessage)?;
                Ok(target.finish().into_target())
            }
        }
    }
}

/// Upstate the response stream state based on a response message.
fn check_stream<CRM>(
    msg: &CRM,
    mut xfr_state: XFRState,
    answer: &Message<Bytes>,
) -> (bool, XFRState, bool)
where
    CRM: ComposeRequestMulti,
{
    // First check if the reply matches the request.
    // RFC 5936, Section 2.2.2:
    // "In the first response message, this section MUST be copied from the
    // query.  In subsequent messages, this section MAY be copied from the
    // query, or it MAY be empty.  However, in an error response message
    // (see Section 2.2), this section MUST be copied as well."
    match xfr_state {
        XFRState::AXFRInit | XFRState::IXFRInit => {
            if !msg.is_answer(answer.for_slice()) {
                xfr_state = XFRState::Error;
                // If we detect an error, then keep the stream open. We are
                // likely out of sync with respect to the sender.
                return (false, xfr_state, false);
            }
        }
        XFRState::AXFRFirstSoa(_)
        | XFRState::IXFRFirstSoa(_)
        | XFRState::IXFRFirstDiffSoa(_)
        | XFRState::IXFRSecondDiffSoa(_) =>
            // No need to check anything.
            {}
        XFRState::Done => {
            // We should not be here. Switch to error state.
            xfr_state = XFRState::Error;
            return (false, xfr_state, false);
        }
        XFRState::Error =>
        // Keep the stream open.
        {
            return (false, xfr_state, false)
        }
    }

    // Then check if the reply status an error.
    if answer.header().rcode() != Rcode::NOERROR {
        // Also check if this answers the question.
        if !msg.is_answer(answer.for_slice()) {
            xfr_state = XFRState::Error;
            // If we detect an error, then keep the stream open. We are
            // likely out of sync with respect to the sender.
            return (false, xfr_state, false);
        }
        return (true, xfr_state, true);
    }

    let ans_sec = match answer.answer() {
        Ok(ans) => ans,
        Err(_) => {
            // Bad message, switch to error state.
            xfr_state = XFRState::Error;
            // If we detect an error, then keep the stream open.
            return (true, xfr_state, false);
        }
    };
    for rr in
        ans_sec.into_records::<AllRecordData<Bytes, ParsedName<Bytes>>>()
    {
        let rr = match rr {
            Ok(rr) => rr,
            Err(_) => {
                // Bad message, switch to error state.
                xfr_state = XFRState::Error;
                return (true, xfr_state, false);
            }
        };
        match xfr_state {
            XFRState::AXFRInit => {
                // The first record has to be a SOA record.
                if let AllRecordData::Soa(soa) = rr.data() {
                    xfr_state = XFRState::AXFRFirstSoa(soa.serial());
                    continue;
                }
                // Bad data. Switch to error status.
                xfr_state = XFRState::Error;
                return (false, xfr_state, false);
            }
            XFRState::AXFRFirstSoa(serial) => {
                if let AllRecordData::Soa(soa) = rr.data() {
                    if serial == soa.serial() {
                        // We found a match.
                        xfr_state = XFRState::Done;
                        continue;
                    }

                    // Serial does not match. Move to error state.
                    xfr_state = XFRState::Error;
                    return (false, xfr_state, false);
                }

                // Any other record, just continue.
            }
            XFRState::IXFRInit => {
                // The first record has to be a SOA record.
                if let AllRecordData::Soa(soa) = rr.data() {
                    xfr_state = XFRState::IXFRFirstSoa(soa.serial());
                    continue;
                }
                // Bad data. Switch to error status.
                xfr_state = XFRState::Error;
                return (false, xfr_state, false);
            }
            XFRState::IXFRFirstSoa(serial) => {
                // We have three possibilities:
                // 1) The record is not a SOA. In that case the format is AXFR.
                // 2) The record is a SOA and the serial is not the current
                //    serial. That is expected for an IXFR format. Move to
                //    IXFRFirstDiffSoa.
                // 3) The record is a SOA and the serial is equal to the
                //    current serial. Treat this as a strange empty AXFR.
                if let AllRecordData::Soa(soa) = rr.data() {
                    if serial == soa.serial() {
                        // We found a match.
                        xfr_state = XFRState::Done;
                        continue;
                    }

                    xfr_state = XFRState::IXFRFirstDiffSoa(serial);
                    continue;
                }

                // Any other record, move to AXFRFirstSoa.
                xfr_state = XFRState::AXFRFirstSoa(serial);
            }
            XFRState::IXFRFirstDiffSoa(serial) => {
                // Move to IXFRSecondDiffSoa if the record is a SOA record,
                // otherwise stay in the current state.
                if let AllRecordData::Soa(_) = rr.data() {
                    xfr_state = XFRState::IXFRSecondDiffSoa(serial);
                    continue;
                }

                // Any other record, just continue.
            }
            XFRState::IXFRSecondDiffSoa(serial) => {
                // Move to Done if the record is a SOA record and the
                // serial is the one from the first SOA record, move to
                // IXFRFirstDiffSoa for any other SOA record and
                // otherwise stay in the current state.
                if let AllRecordData::Soa(soa) = rr.data() {
                    if serial == soa.serial() {
                        // We found a match.
                        xfr_state = XFRState::Done;
                        continue;
                    }

                    xfr_state = XFRState::IXFRFirstDiffSoa(serial);
                    continue;
                }

                // Any other record, just continue.
            }
            XFRState::Done => {
                // We got a record after we are done. Switch to error state.
                xfr_state = XFRState::Error;
                return (false, xfr_state, false);
            }
            XFRState::Error => panic!("should not be here"),
        }
    }

    // Check the final state.
    match xfr_state {
        XFRState::AXFRInit | XFRState::IXFRInit => {
            // Still in one of the init state. So the data section was empty.
            // Switch to error state.
            xfr_state = XFRState::Error;
            return (false, xfr_state, false);
        }
        XFRState::AXFRFirstSoa(_)
        | XFRState::IXFRFirstDiffSoa(_)
        | XFRState::IXFRSecondDiffSoa(_) =>
            // Just continue.
            {}
        XFRState::IXFRFirstSoa(_) => {
            // We are still in IXFRFirstSoa. Assume the other side doesn't
            // have anything more to say. We could check the SOA serial in
            // the request. Just assume that we are done.
            xfr_state = XFRState::Done;
            return (true, xfr_state, true);
        }
        XFRState::Done => return (true, xfr_state, true),
        XFRState::Error => panic!("should not be here"),
    }

    // (eof, xfr_data, is_answer)
    (false, xfr_state, true)
}

//------------ Queries -------------------------------------------------------

/// Mapping outstanding queries to their ID.
///
/// This is generic over anything rather than our concrete request type for
/// easier testing.
#[derive(Clone, Debug)]
struct Queries<T> {
    /// The number of elements in `vec` that are not None.
    count: usize,

    /// Index in `vec` where to look for a space for a new query.
    curr: usize,

    /// Vector of senders to forward a DNS reply message (or error) to.
    vec: Vec<Option<T>>,
}

impl<T> Queries<T> {
    /// Creates a new empty value.
    fn new() -> Self {
        Self {
            count: 0,
            curr: 0,
            vec: Vec::new(),
        }
    }

    /// Returns whether there are no more outstanding queries.
    fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Inserts the given query.
    ///
    /// Upon success, returns the index and a mutable reference to the stored
    /// query.
    ///
    /// Upon error, which means the set is full, returns the query.
    fn insert(&mut self, req: T) -> Result<(u16, &mut T), T> {
        // Fail if there are to many entries already in this vector
        // We cannot have more than u16::MAX entries because the
        // index needs to fit in an u16. For efficiency we want to
        // keep the vector half empty. So we return a failure if
        // 2*count > u16::MAX
        if 2 * self.count > u16::MAX.into() {
            return Err(req);
        }

        // If more than half the vec is empty, we try and find the index of
        // an empty slot.
        let idx = if self.vec.len() >= 2 * self.count {
            let mut found = None;
            for idx in self.curr..self.vec.len() {
                if self.vec[idx].is_none() {
                    found = Some(idx);
                    break;
                }
            }
            found
        } else {
            None
        };

        // If we have an index, we can insert there, otherwise we need to
        // append.
        let idx = match idx {
            Some(idx) => {
                self.vec[idx] = Some(req);
                idx
            }
            None => {
                let idx = self.vec.len();
                self.vec.push(Some(req));
                idx
            }
        };

        self.count += 1;
        if idx == self.curr {
            self.curr += 1;
        }
        let req = self.vec[idx].as_mut().expect("no inserted item?");
        let idx = u16::try_from(idx).expect("query vec too large");
        Ok((idx, req))
    }

    /// Inserts the given query at a specified position. A pre-condition is
    /// is that the slot has to be empty.
    fn insert_at(&mut self, id: u16, req: T) {
        let id = id as usize;
        self.vec[id] = Some(req);

        self.count += 1;
        if id == self.curr {
            self.curr += 1;
        }
    }

    /// Tries to remove and return the query at the given index.
    ///
    /// Returns `None` if there was no query there.
    fn try_remove(&mut self, index: u16) -> Option<T> {
        let res = self.vec.get_mut(usize::from(index))?.take()?;
        self.count = self.count.saturating_sub(1);
        self.curr = cmp::min(self.curr, index.into());
        Some(res)
    }

    /// Removes all queries and returns an iterator over them.
    fn drain(&mut self) -> impl Iterator<Item = T> + '_ {
        let res = self.vec.drain(..).flatten(); // Skips all the `None`s.
        self.count = 0;
        self.curr = 0;
        res
    }
}

//============ Tests =========================================================

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn queries_insert_remove() {
        // Insert items, remove a few, insert a few more. Check that
        // everything looks right.
        let mut idxs = [None; 20];
        let mut queries = Queries::new();

        for i in 0..12 {
            let (idx, item) = queries.insert(i).expect("test failed");
            idxs[i] = Some(idx);
            assert_eq!(i, *item);
        }
        assert_eq!(queries.count, 12);
        assert_eq!(queries.vec.iter().flatten().count(), 12);

        for i in [1, 2, 3, 4, 7, 9] {
            let item = queries
                .try_remove(idxs[i].expect("test failed"))
                .expect("test failed");
            assert_eq!(i, item);
            idxs[i] = None;
        }
        assert_eq!(queries.count, 6);
        assert_eq!(queries.vec.iter().flatten().count(), 6);

        for i in 12..20 {
            let (idx, item) = queries.insert(i).expect("test failed");
            idxs[i] = Some(idx);
            assert_eq!(i, *item);
        }
        assert_eq!(queries.count, 14);
        assert_eq!(queries.vec.iter().flatten().count(), 14);

        for i in 0..20 {
            if let Some(idx) = idxs[i] {
                let item = queries.try_remove(idx).expect("test failed");
                assert_eq!(i, item);
            }
        }
        assert_eq!(queries.count, 0);
        assert_eq!(queries.vec.iter().flatten().count(), 0);
    }

    #[test]
    fn queries_overrun() {
        // This is just a quick check that inserting to much stuff doesn’t
        // break.
        let mut queries = Queries::new();
        for i in 0..usize::from(u16::MAX) * 2 {
            let _ = queries.insert(i);
        }
    }
}
