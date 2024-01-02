//! A client transport using a stream socket.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

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

use crate::base::opt::{AllOptData, OptRecord, TcpKeepalive};
use crate::base::Message;
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};
use bytes;
use bytes::{Bytes, BytesMut};
use core::cmp;
use core::convert::From;
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

//------------ Configuration Constants ----------------------------------------

/// Default response timeout.
///
/// Note: nsd has 120 seconds, unbound has 3 seconds.
const DEF_RESPONSE_TIMEOUT: Duration = Duration::from_secs(19);

/// Minimum configuration value for the response timeout.
const MIN_RESPONSE_TIMEOUT: Duration = Duration::from_millis(1);

/// Maximum configuration value for the response timeout.
const MAX_RESPONSE_TIMEOUT: Duration = Duration::from_secs(600);

/// Capacity of the channel that transports `ChanReq`s.
const DEF_CHAN_CAP: usize = 8;

/// Capacity of a private channel dispatching responses.
const READ_REPLY_CHAN_CAP: usize = 8;

//------------ Config ---------------------------------------------------------

/// Configuration for a stream transport connection.
#[derive(Clone, Debug)]
pub struct Config {
    /// Response timeout.
    response_timeout: Duration,
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
    /// Excessive values are quietly trimmed.
    //
    //  XXX Maybe that’s wrong and we should rather return an error?
    pub fn set_response_timeout(&mut self, timeout: Duration) {
        self.response_timeout = cmp::max(
            cmp::min(timeout, MAX_RESPONSE_TIMEOUT),
            MIN_RESPONSE_TIMEOUT,
        )
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            response_timeout: DEF_RESPONSE_TIMEOUT,
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

impl<Req: ComposeRequest + Clone + 'static> Connection<Req> {
    /// Start a DNS request.
    ///
    /// This function takes a precomposed message as a parameter and
    /// returns a [ReqRepl] object wrapped in a [Result].
    async fn request_impl(
        &self,
        request_msg: &Req,
    ) -> Result<Box<dyn GetResponse + Send>, Error> {
        let (tx, rx) = oneshot::channel();
        self.request(tx, request_msg.clone()).await?;
        Ok(Box::new(ReqResp::new(request_msg, rx)))
    }

    /// Start a DNS request but do not check if the reply matches the request.
    ///
    /// This function is similar to [Self::query]. Not checking if the reply
    /// match the request avoids having to keep the request around.
    pub async fn query_no_check(
        &self,
        query_msg: &Req,
    ) -> Result<QueryNoCheck, Error> {
        let (tx, rx) = oneshot::channel();
        self.request(tx, query_msg.clone()).await?;
        Ok(QueryNoCheck::new(rx))
    }

    /// Sends a request.
    async fn request(
        &self,
        sender: oneshot::Sender<ChanResp>,
        request_msg: Req,
    ) -> Result<(), Error> {
        let req = ChanReq {
            sender,
            msg: request_msg,
        };
        match self.sender.send(req).await {
            Err(_) =>
            // Send error. The receiver is gone, this means that the
            // connection is closed.
            {
                Err(Error::ConnectionClosed)
            }
            Ok(_) => Ok(()),
        }
    }
}

impl<Req: ComposeRequest + Clone + 'static> SendRequest<Req>
    for Connection<Req>
{
    fn send_request<'a>(
        &'a self,
        request_msg: &'a Req,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn GetResponse + Send>, Error>>
                + Send
                + '_,
        >,
    > {
        return Box::pin(self.request_impl(request_msg));
    }
}

//------------ ReqResp --------------------------------------------------------

/// This struct represent an active DNS request.
#[derive(Debug)]
pub struct ReqResp {
    /// Request message.
    ///
    /// The reply message is compared with the request message to see if
    /// it matches the query.
    request_msg: Message<Vec<u8>>,

    /// Current state of the query.
    state: QueryState,
}

/// Status of a query. Used in [Query].
#[derive(Debug)]
enum QueryState {
    /// A request is in progress.
    ///
    /// The receiver for receiving the response is part of this state.
    Busy(oneshot::Receiver<ChanResp>),

    /// The response has been received and the query is done.
    Done,
}

impl ReqResp {
    /// Constructor for [Query], takes a DNS query and a receiver for the
    /// reply.
    fn new<Req: ComposeRequest>(
        request_msg: &Req,
        receiver: oneshot::Receiver<ChanResp>,
    ) -> ReqResp {
        let vec = request_msg.to_vec();
        let msg = Message::from_octets(vec)
            .expect("Message failed to parse contents of another Message");
        Self {
            request_msg: msg,
            state: QueryState::Busy(receiver),
        }
    }

    /// Get the result of a DNS request.
    ///
    /// This function returns the reply to a DNS request wrapped in a
    /// [Result].
    pub async fn get_response_impl(
        &mut self,
    ) -> Result<Message<Bytes>, Error> {
        match self.state {
            QueryState::Busy(ref mut receiver) => {
                let res = receiver.await;
                self.state = QueryState::Done;
                if res.is_err() {
                    // Assume receive error
                    return Err(Error::StreamReceiveError);
                }
                let res = res.expect("already check error case");

                // clippy seems to be wrong here. Replacing
                // the following with 'res?;' doesn't work
                #[allow(clippy::question_mark)]
                if let Err(err) = res {
                    return Err(err);
                }

                let msg = res.expect("error case is checked already");

                if !is_answer_ignore_id(&msg, &self.request_msg) {
                    return Err(Error::WrongReplyForQuery);
                }
                Ok(msg)
            }
            QueryState::Done => {
                panic!("Already done");
            }
        }
    }
}

impl GetResponse for ReqResp {
    fn get_response(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_response_impl())
    }
}

//------------ QueryNoCheck ---------------------------------------------------

/// This represents that state of an active DNS query if there is no need
/// to check that the reply matches the request. The assumption is that the
/// caller will do this check.
#[derive(Debug)]
pub struct QueryNoCheck {
    /// Current state of the query.
    state: QueryState,
}

impl QueryNoCheck {
    /// Constructor for [Query], takes a DNS query and a receiver for the
    /// reply.
    fn new(receiver: oneshot::Receiver<ChanResp>) -> QueryNoCheck {
        Self {
            state: QueryState::Busy(receiver),
        }
    }

    /// Get the result of a DNS query.
    ///
    /// This function returns the reply to a DNS query wrapped in a
    /// [Result].
    pub async fn get_result(&mut self) -> Result<Message<Bytes>, Error> {
        match self.state {
            QueryState::Busy(ref mut receiver) => {
                let res = receiver.await;
                self.state = QueryState::Done;
                if res.is_err() {
                    // Assume receive error
                    return Err(Error::StreamReceiveError);
                }
                let res = res.expect("error case is checked already");

                // clippy seems to be wrong here. Replacing
                // the following with 'res?;' doesn't work
                #[allow(clippy::question_mark)]
                if let Err(err) = res {
                    return Err(err);
                }

                let msg = res.expect("error case is checked already");

                Ok(msg)
            }
            QueryState::Done => {
                panic!("Already done");
            }
        }
    }
}

//------------ Transport ------------------------------------------------

/// The underlying machinery of a stream transport.
#[derive(Debug)]
pub struct Transport<Stream, Req> {
    /// The stream socket towards the remove end.
    stream: Stream,

    /// Transport configuration.
    config: Config,

    /// The receiver half of request channel.
    receiver: mpsc::Receiver<ChanReq<Req>>,
}

/// A message from a `Query` to start a new request.
#[derive(Debug)]
struct ChanReq<Req> {
    /// DNS request message
    msg: Req,

    /// Sender to send result back to [Query]
    sender: ReplySender,
}

/// This is the type of sender in [ChanReq].
type ReplySender = oneshot::Sender<ChanResp>;

/// A message back to `Query` returning a response.
type ChanResp = Result<Message<Bytes>, Error>;

/// Internal datastructure of [Transport::run] to keep track of
/// outstanding DNS requests.
struct Queries {
    /// The number of elements in [Queries::vec] that are not None.
    count: usize,

    /// Index in the [Queries::vec] where to look for a space for a new query.
    curr: usize,

    /// Vector of senders to forward a DNS reply message (or error) to.
    vec: Vec<Option<ReplySender>>,
}

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
    /// Initially we assume that the idle timeout is zero. A received
    /// edns-tcp-keepalive option may change that.
    idle_timeout: Option<Duration>,
}

/// Status of the connection. Used in [Status].
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
            idle_timeout: None,
            send_keepalive: true,
        };
        let mut query_vec = Queries {
            count: 0,
            curr: 0,
            vec: Vec::new(),
        };

        let mut reqmsg: Option<Vec<u8>> = None;

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
                    if let Some(timeout) = &status.idle_timeout {
                        let elapsed = instant.elapsed();
                        if elapsed >= *timeout {
                            // Move to IdleTimeout and end
                            // the loop
                            status.state = ConnState::IdleTimeout;
                            break;
                        }
                        Some(*timeout - elapsed)
                    } else {
                        panic!("Idle state but no timeout");
                    }
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
                            Self::error(error.clone(),
                                &mut query_vec);
                            status.state =
                                ConnState::ReadError(error);
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
                    Self::demux_reply(answer,
                        &mut status, &mut query_vec);
                }
                res = write_stream.write_all(msg),
                    if do_write => {
                    if let Err(error) = res {
            let error = Error::StreamWriteError(Arc::new(error));
                        Self::error(error.clone(), &mut query_vec);
                        status.state =
                            ConnState::WriteError(error);
                        break;
                    }
                    else {
                        reqmsg = None;
                    }
                }
                res = recv_fut, if !do_write => {
                    match res {
                        Some(req) => {
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
    fn error(error: Error, query_vec: &mut Queries) {
        // Update all requests that are in progress. Don't wait for
        // any reply that may be on its way.
        for index in 0..query_vec.vec.len() {
            if query_vec.vec[index].is_some() {
                let sender = Self::take_query(query_vec, index)
                    .expect("we tested is_none before");
                _ = sender.send(Err(error.clone()));
            }
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
        query_vec: &mut Queries,
    ) {
        // We got an answer, reset the timer
        status.state = ConnState::Active(Some(Instant::now()));

        let ind16 = answer.header().id();
        let index: usize = ind16.into();

        let vec_len = query_vec.vec.len();
        if index >= vec_len {
            // Index is out of bouds. We should mark
            // the connection as broken
            return;
        }

        // Do we have a query with this ID?
        match &mut query_vec.vec[index] {
            None => {
                // No query with this ID. We should
                // mark the connection as broken
                return;
            }
            Some(_) => {
                let sender = Self::take_query(query_vec, index)
                    .expect("sender should be there");
                _ = sender.send(Ok(answer));
            }
        }
        if query_vec.count == 0 {
            // Clear the activity timer. There is no need to do
            // this because state will be set to either IdleTimeout
            // or Idle just below. However, it is nicer to keep
            // this independent.
            status.state = ConnState::Active(None);

            status.state = if status.idle_timeout.is_none() {
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
        query_vec: &mut Queries,
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
        // outstanding queires. First call insert before checking
        // send_keepalive.
        let index = {
            let res = Self::insert(req.sender, query_vec);
            match res {
                Err(_) => {
                    // insert sends an error reply, so we can just
                    // return here
                    return;
                }
                Ok(index) => index,
            }
        };

        let ind16: u16 = index
            .try_into()
            .expect("insert should return a value that fits in u16");

        // We set the ID to the array index. Defense in depth
        // suggests that a random ID is better because it works
        // even if TCP sequence numbers could be predicted. However,
        // Section 9.3 of RFC 5452 recommends retrying over TCP
        // if many spoofed answers arrive over UDP: "TCP, by the
        // nature of its use of sequence numbers, is far more
        // resilient against forgery by third parties."

        let hdr = req.msg.header_mut();
        hdr.set_id(ind16);

        if status.send_keepalive {
            let res = add_tcp_keepalive(&mut req.msg);

            if let Ok(()) = res {
                status.send_keepalive = false;
            }
        }
        Self::convert_query(&req.msg, reqmsg);
    }

    /// Take an element out of query_vec.
    fn take_query(
        query_vec: &mut Queries,
        index: usize,
    ) -> Option<ReplySender> {
        let query = query_vec.vec[index].take();
        query_vec.count -= 1;
        query
    }

    /// Handle a received edns-tcp-keepalive option.
    fn handle_keepalive(opt_value: TcpKeepalive, status: &mut Status) {
        if let Some(value) = opt_value.timeout() {
            let value_dur = Duration::from(value);
            status.idle_timeout = Some(value_dur);
        }
    }

    /// Convert the query message to a vector.
    // This function should return the vector instead of storing it
    // through a reference.
    fn convert_query(msg: &Req, reqmsg: &mut Option<Vec<u8>>) {
        // Ideally there should be a write_all_vectored. Until there is one,
        // copy to a new Vec and prepend the length octets.

        let slice = msg.to_vec();
        let len = slice.len();

        let mut vec = Vec::with_capacity(2 + len);
        let len16 = len as u16;
        vec.extend_from_slice(&len16.to_be_bytes());
        vec.extend_from_slice(&slice);

        *reqmsg = Some(vec);
    }

    /// Insert a sender (for the reply) in the query_vec and return the index.
    fn insert(
        sender: oneshot::Sender<ChanResp>,
        query_vec: &mut Queries,
    ) -> Result<usize, Error> {
        // Fail if there are to many entries already in this vector
        // We cannot have more than u16::MAX entries because the
        // index needs to fit in an u16. For efficiency we want to
        // keep the vector half empty. So we return a failure if
        // 2*count > u16::MAX
        if 2 * query_vec.count > u16::MAX.into() {
            // We own sender. So we need to send the error reply here
            let error = Error::StreamTooManyOutstandingQueries;
            _ = sender.send(Err(error.clone()));
            return Err(error);
        }

        let q = Some(sender);

        let vec_len = query_vec.vec.len();

        // Append if the amount of empty space in the vector is less
        // than half. But limit vec_len to u16::MAX
        if vec_len < 2 * (query_vec.count + 1) && vec_len < u16::MAX.into() {
            // Just append
            query_vec.vec.push(q);
            query_vec.count += 1;
            let index = query_vec.vec.len() - 1;
            return Ok(index);
        }
        let loc_curr = query_vec.curr;

        for index in loc_curr..vec_len {
            if query_vec.vec[index].is_none() {
                Self::insert_at(query_vec, index, q);
                return Ok(index);
            }
        }

        // Nothing until the end of the vector. Try for the entire
        // vector
        for index in 0..vec_len {
            if query_vec.vec[index].is_none() {
                Self::insert_at(query_vec, index, q);
                return Ok(index);
            }
        }

        // Still nothing, that is not good
        panic!("insert failed");
    }

    /// Insert a sender at a specific position in query_vec and update
    /// the statistics.
    fn insert_at(
        query_vec: &mut Queries,
        index: usize,
        q: Option<ReplySender>,
    ) {
        query_vec.vec[index] = q;
        query_vec.count += 1;
        query_vec.curr = index + 1;
    }
}

//------------ Utility --------------------------------------------------------

/// Add an edns-tcp-keepalive option to a BaseMessageBuilder.
fn add_tcp_keepalive<CR: ComposeRequest>(msg: &mut CR) -> Result<(), Error> {
    msg.add_opt(&TcpKeepalive::new(None))?;
    Ok(())
}

/// Check if a DNS reply match the query. Ignore whether id fields match.
fn is_answer_ignore_id<
    Octs1: Octets + AsRef<[u8]>,
    Octs2: Octets + AsRef<[u8]>,
>(
    reply: &Message<Octs1>,
    query: &Message<Octs2>,
) -> bool {
    if !reply.header().qr()
        || reply.header_counts().qdcount() != query.header_counts().qdcount()
    {
        false
    } else {
        reply.question() == query.question()
    }
}
