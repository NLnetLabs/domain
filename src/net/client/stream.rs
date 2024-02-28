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

use crate::base::message::Message;
use crate::base::message_builder::StreamTarget;
use crate::base::opt::{AllOptData, OptRecord, TcpKeepalive};
use crate::net::client::request::{
    ComposeRequest, Error, GetResponse, SendRequest,
};
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
    /// Creates a new connection and transport.
    ///
    /// This is the same as calling [`with_config()`][`Self::with_config()`]
    /// with [`Config::default()`].
    pub fn new<Stream>(stream: Stream) -> (Self, Transport<Stream, Req>) {
        Self::with_config(stream, Default::default())
    }

    /// Creates a new connection and transport with the given configuration.
    ///
    /// Returns a [`Connection`] and a [`Transport`]. Use [`Transport::run()`]
    /// to start the transport running then use [`Connection::send_request()`]
    /// to send a request and receive a response via the transport.
    pub fn with_config<Stream>(
        stream: Stream,
        config: Config,
    ) -> (Self, Transport<Stream, Req>) {
        let (sender, transport) = Transport::new(stream, config);
        (Self { sender }, transport)
    }

    /// Runs a new transport returning a connection to it.
    ///
    /// This is the same as calling
    /// [`run_with_config()`][`Self::run_with_config()`] with
    /// [`Config::default()`].
    pub fn run<Remote>(remote: Remote) -> Self
    where
        Remote: AsyncRead + AsyncWrite + Send + 'static,
        Req: ComposeRequest + 'static,
    {
        Self::run_with_config(remote, Default::default())
    }

    /// Runs a new transport with the given configuration, returning a
    /// connection to it.
    ///
    /// Creates a [`Connection`] and [`Transport`], spawning the future that
    /// drives the transport onto a new Tokio task and returns the
    /// [`Connection`] ready for sending requests.
    pub fn run_with_config<Remote>(remote: Remote, config: Config) -> Self
    where
        Remote: AsyncRead + AsyncWrite + Send + 'static,
        Req: ComposeRequest + 'static,
    {
        let (connection, transport) = Self::with_config(remote, config);
        let _join_handle = tokio::spawn(async move {
            transport.run().await;
        });
        connection
    }

    /// Fetch the response to a single request over a temporary transport.
    ///
    /// This is the same as calling
    /// [`query_with_config()`][`Self::query_with_config()`] with
    /// [`Config::default()`].
    pub async fn query<Remote>(
        remote: Remote,
        request_msg: Req,
    ) -> Result<Message<Bytes>, Error>
    where
        Remote: AsyncRead + AsyncWrite + Send + 'static,
        Req: ComposeRequest + 'static,
        Self: SendRequest<Req>,
    {
        Self::query_with_config(remote, request_msg, Default::default()).await
    }

    /// Fetch the response to a single request over a temporary transport with
    /// the given configuration.
    pub async fn query_with_config<Remote>(
        remote: Remote,
        request_msg: Req,
        config: Config,
    ) -> Result<Message<Bytes>, Error>
    where
        Remote: AsyncRead + AsyncWrite + Send + 'static,
        Req: ComposeRequest + 'static,
        Self: SendRequest<Req>,
    {
        Self::run_with_config(remote, config)
            .send_request(request_msg)
            .get_response()
            .await
    }
}

impl<Req: ComposeRequest + 'static> Connection<Req> {
    /// Start a DNS request.
    ///
    /// This function takes a precomposed message as a parameter and
    /// returns a [ReqRepl] object wrapped in a [Result].
    async fn handle_request_impl(
        self,
        msg: Req,
    ) -> Result<Message<Bytes>, Error> {
        let (sender, receiver) = oneshot::channel();
        let req = ChanReq { sender, msg };
        self.sender.send(req).await.map_err(|_| {
            // Send error. The receiver is gone, this means that the
            // connection is closed.
            Error::ConnectionClosed
        })?;
        receiver.await.map_err(|_| Error::StreamReceiveError)?
    }

    /// Returns a request handler for this connection.
    pub fn get_request(&self, request_msg: Req) -> Request {
        Request {
            fut: Box::pin(self.clone().handle_request_impl(request_msg)),
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

impl<Req: ComposeRequest + Clone + 'static> SendRequest<Req>
    for Connection<Req>
{
    fn send_request(
        &self,
        request_msg: Req,
    ) -> Box<dyn GetResponse + Send + Sync> {
        Box::new(self.get_request(request_msg))
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

//------------ Transport -----------------------------------------------------

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

/// A message from a `Request` to start a new request.
#[derive(Debug)]
struct ChanReq<Req> {
    /// DNS request message
    msg: Req,

    /// Sender to send result back to [Request]
    sender: ReplySender,
}

/// This is the type of sender in [ChanReq].
type ReplySender = oneshot::Sender<ChanResp>;

/// A message back to `Request` returning a response.
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
        for item in query_vec.drain() {
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
        let req = match query_vec.try_remove(answer.header().id()) {
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

        if query_vec.is_empty() {
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
        req: ChanReq<Req>,
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
        // outstanding queires. First call insert before checking
        // send_keepalive.
        let (index, req) = match query_vec.insert(req) {
            Ok(res) => res,
            Err(req) => {
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
                if let Some(req) = query_vec.try_remove(index) {
                    _ = req.sender.send(Err(err));
                }
            }
        }
    }

    /// Handle a received edns-tcp-keepalive option.
    fn handle_keepalive(opt_value: TcpKeepalive, status: &mut Status) {
        if let Some(value) = opt_value.timeout() {
            let value_dur = Duration::from(value);
            status.idle_timeout = Some(value_dur);
        }
    }

    /// Convert the query message to a vector.
    fn convert_query(msg: &Req) -> Result<Vec<u8>, Error> {
        let mut target = StreamTarget::new_vec();
        msg.append_message(&mut target)
            .map_err(|_| Error::StreamLongMessage)?;
        Ok(target.into_target())
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

    /// Index in `vec? where to look for a space for a new query.
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
