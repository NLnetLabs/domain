//! A client transport using a stream socket.

// RFC 7766 describes DNS over TCP
// RFC 7828 describes the edns-tcp-keepalive option

// TODO:
// - errors
//   - connect errors? Retry after connection refused?
//   - server errors
//     - ID out of range
//     - ID not in use
//     - reply for wrong query
// - timeouts
//   - request timeout
// - create new connection after end/failure of previous one

use core::cmp;
use core::future::ready;

use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec::Vec;

use bytes::{Bytes, BytesMut};
use octseq::Octets;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use tracing::trace;

use crate::base::message::Message;
use crate::base::message_builder::StreamTarget;
use crate::base::opt::{AllOptData, OptRecord, TcpKeepalive};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};
use crate::utils::config::DefMinMax;

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
pub struct Connection<Req> {
    /// The sender half of the request channel.
    sender: mpsc::Sender<ChanReq<Req>>,
}

impl<Req> Connection<Req> {
    /// Creates a new stream transport with default configuration.
    ///
    /// Returns a connection and a future that drives the transport using
    /// the provided stream. This future needs to be run while any queries
    /// are active. This is most easly achieved by spawning it into a runtime.
    /// It terminates when the last connection is dropped.
    pub fn new<Stream>(stream: Stream) -> (Self, Transport<Stream, Req>) {
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
    ) -> (Self, Transport<Stream, Req>) {
        let (sender, transport) = Transport::new(stream, config);
        (Self { sender }, transport)
    }
}

impl<Req: ComposeRequest + 'static> Connection<Req> {
    /// Start a DNS request.
    ///
    /// This function takes a precomposed message as a parameter and
    /// returns a response [`Message`] object wrapped in a [`Result`].
    async fn handle_request_impl(
        self,
        msg: Req,
    ) -> Result<Message<Bytes>, Error> {
        let (sender, receiver) = oneshot::channel();
        let sender = ReplySender::Single(Some(sender));
        let req = ChanReq { sender, msg };
        self.sender.send(req).await.map_err(|_| {
            // Send error. The receiver is gone, this means that the
            // connection is closed.
            Error::ConnectionClosed
        })?;
        receiver.await.map_err(|_| Error::StreamReceiveError)?
    }

    /// Start a DNS request that may result in multiple responses.
    ///
    /// This function takes a precomposed message as a parameter and a stream
    /// sender which should be used to send responses back to the caller as
    /// responses are received.
    ///
    /// Note: The return type is and must be compatible with that of
    /// [`handle_request_impl`] but has no meaning and should not be checked.
    async fn handle_streaming_request_impl(
        self,
        msg: Req,
        sender: UnboundedSender<Result<Message<Bytes>, Error>>,
    ) -> Result<Message<Bytes>, Error> {
        let reply_sender = ReplySender::Stream(sender);
        let req = ChanReq {
            sender: reply_sender,
            msg,
        };
        let _ = self.sender.send(req).await;

        // TODO: It would be nicer if we could return Ok(()) here.
        Err(Error::ConnectionClosed)
    }

    /// Returns a request handler for this connection.
    pub fn get_request(&self, request_msg: Req) -> Request {
        Request {
            stream: None,
            fut: Box::pin(self.clone().handle_request_impl(request_msg)),
            stream_complete: false,
        }
    }

    /// TODO
    pub fn get_streaming_request(&self, request_msg: Req) -> Request {
        let (sender, receiver) = mpsc::unbounded_channel();
        Request {
            stream: Some(receiver),
            fut: Box::pin(
                self.clone()
                    .handle_streaming_request_impl(request_msg, sender),
            ),
            stream_complete: false,
        }
    }
}

impl<Req> Clone for Connection<Req> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
        }
    }
}

impl<Req: ComposeRequest + 'static> SendRequest<Req> for Connection<Req> {
    fn send_request(
        &self,
        request_msg: Req,
    ) -> Box<dyn GetResponse + Send + Sync> {
        if request_msg.is_streaming() {
            Box::new(self.get_streaming_request(request_msg))
        } else {
            Box::new(self.get_request(request_msg))
        }
    }
}

//------------ Request -------------------------------------------------------

/// An active request.
pub struct Request {
    /// The stream of responses to await when [`get_streaming_request()`] was
    /// called, None otherwise.
    stream: Option<UnboundedReceiver<Result<Message<Bytes>, Error>>>,

    /// The underlying future.
    fut: Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + Sync>,
    >,

    /// True if the caller has signalled that the last data in the stream has
    /// been received.
    ///
    /// The DNS protocol does not provide a standardized way to detect the end
    /// of a stream of responses. At the time of writing the only query types that
    /// can result in a stream of responses are AXFR and IXFR. In both cases the
    /// end of the response data is detected by examining the content of the DNS
    /// responses, there is no actual END signal per se. So we rely on the caller
    /// inspecting the response messages and telling us that it has detected the
    /// end of the stream by calling [`stream_complete()`] at which point this
    /// flag will be set to true. By default this flag is set to false.
    stream_complete: bool,
}

impl Request {
    /// Async function that waits for the future stored in Request to complete.
    async fn get_response_impl(&mut self) -> Result<Message<Bytes>, Error> {
        // In most cases the caller will have called [`send_request()`] and
        // only a single response is expected which will result from resolving
        // this future to a successful result. However, if
        // [`send_streaming_request()`] was called instead this future will
        // always resolve to Error::ConnectionClosed as the response is not
        // delivered immediately but instead via the separate response stream.
        // In both cases no response will be received if the future is not
        // first resolved to completion, so we must await it in either case.
        let mut res = (&mut self.fut).await;

        // Do we have a response stream that we should consume from? If not
        // the result is already available and can be returned immediately.
        let Some(stream) = self.stream.as_mut() else {
            return res;
        };

        // Fetch from the stream
        res = stream
            .recv()
            .await
            .ok_or(Error::ConnectionClosed)
            .map_err(|_| Error::ConnectionClosed)?;

        // Setup the next future
        self.fut = Box::pin(ready(Err(Error::ConnectionClosed)));

        res
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

    fn stream_complete(&mut self) -> Result<(), Error> {
        if let Some(mut stream) = self.stream.take() {
            trace!("Closing response stream");
            stream.close();
        }

        self.stream_complete = true;

        Ok(())
    }

    fn is_stream_complete(&self) -> bool {
        self.stream_complete
    }
}

impl Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("fut", &format_args!("_"))
            .finish()
    }
}

//------------ Transport -----------------------------------------------------

/// The underlying machinery of a stream transport.
#[derive(Debug)]
pub struct Transport<Stream, Req> {
    /// The stream socket towards the remote end.
    stream: Stream,

    /// Transport configuration.
    config: Config,

    /// The receiver half of request channel.
    receiver: mpsc::Receiver<ChanReq<Req>>,
}

/// A sender used to communicate a received response back to the caller.
#[derive(Debug)]
pub enum ReplySender {
    /// A single immediate response.
    ///
    /// For most DNS query types this is the appropriate sender to use because
    /// most DNS requests result in a single response.
    Single(Option<oneshot::Sender<ChanResp>>),

    /// For DNS query types that can result in a stream of responses use this
    /// sender to send an unknown number of responses back to the caller.
    Stream(mpsc::UnboundedSender<ChanResp>),
}

impl ReplySender {
    /// Send a response back to the caller.
    ///
    /// If this ReplySender is of type Single, attempts to call this function
    /// more than once will return an error containing the response value
    /// supplied by the caller.
    pub fn send(&mut self, resp: ChanResp) -> Result<(), ChanResp> {
        match self {
            ReplySender::Single(sender) => match sender.take() {
                Some(sender) => sender.send(resp),
                None => Err(resp),
            },
            ReplySender::Stream(sender) => {
                sender.send(resp).map_err(|err| err.0)
            }
        }
    }

    /// Is this ReplySender of type Stream?
    pub fn is_stream(&self) -> bool {
        matches!(self, Self::Stream(_))
    }
}

/// A message from a [`Request`] to start a new request.
#[derive(Debug)]
struct ChanReq<Req> {
    /// DNS request message
    msg: Req,

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

impl<Stream, Req> Transport<Stream, Req> {
    /// Creates a new transport.
    fn new(
        stream: Stream,
        config: Config,
    ) -> (mpsc::Sender<ChanReq<Req>>, Self) {
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

impl<Stream, Req> Transport<Stream, Req>
where
    Stream: AsyncRead + AsyncWrite,
    Req: ComposeRequest,
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
        let mut query_vec = Queries::new();

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
                    Self::demux_reply(answer, &mut status, &mut query_vec);
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
                            // Wait longer for response streams than for
                            // single responses.
                            if req.sender.is_stream() {
                                self.config.response_timeout =
                                    self.config.streaming_response_timeout;
                            } else {
                                self.config.response_timeout =
                                    self.config.single_response_timeout;
                            }
                            Self::insert_req(
                                req, &mut status, &mut reqmsg, &mut query_vec
                            )
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
    fn error(error: Error, query_vec: &mut Queries<ChanReq<Req>>) {
        // Update all requests that are in progress. Don't wait for
        // any reply that may be on its way.
        for mut item in query_vec.drain() {
            _ = item.sender.send(Err(error.clone()));
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
    fn demux_reply(
        answer: Message<Bytes>,
        status: &mut Status,
        query_vec: &mut Queries<ChanReq<Req>>,
    ) {
        // We got an answer, reset the timer
        status.state = ConnState::Active(Some(Instant::now()));

        // Get the correct query and send it the reply.
        let mut req = match query_vec.try_remove(answer.header().id()) {
            Some(req) => req,
            None => {
                // No query with this ID. We should
                // mark the connection as broken
                return;
            }
        };
        let answer = if req.msg.is_answer(answer.for_slice()) {
            Ok(answer)
        } else {
            Err(Error::WrongReplyForQuery)
        };
        _ = req.sender.send(answer);

        // TODO: Discard streaming requests once the stream is complete.
        if req.sender.is_stream() {
            query_vec.insert(req).unwrap();
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
        mut req: ChanReq<Req>,
        status: &mut Status,
        reqmsg: &mut Option<Vec<u8>>,
        query_vec: &mut Queries<ChanReq<Req>>,
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

        // Note that insert may fail if there are too many
        // outstanding queries. First call insert before checking
        // send_keepalive.
        let (index, req) = match query_vec.insert(req) {
            Ok(res) => res,
            Err(mut req) => {
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

        let hdr = req.msg.header_mut();
        hdr.set_id(index);

        if status.send_keepalive
            && req.msg.add_opt(&TcpKeepalive::new(None)).is_ok()
        {
            status.send_keepalive = false;
        }

        match Self::convert_query(&req.msg) {
            Ok(msg) => {
                *reqmsg = Some(msg);
            }
            Err(err) => {
                // Take the sender out again and return the error.
                if let Some(mut req) = query_vec.try_remove(index) {
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
    fn convert_query(msg: &Req) -> Result<Vec<u8>, Error> {
        let target = StreamTarget::new_vec();
        let target = msg
            .to_message_builder(target)
            .map_err(|_| Error::StreamLongMessage)?;
        Ok(target.finish().into_target())
    }
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
