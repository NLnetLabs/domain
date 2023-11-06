//! A DNS over octet stream transport

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

use bytes;
use bytes::{Bytes, BytesMut};
use core::convert::From;
use futures::lock::Mutex as Futures_mutex;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::io::ErrorKind;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec::Vec;

use crate::base::{
    opt::{AllOptData, OptRecord, TcpKeepalive},
    Message,
};
use crate::net::client::base_message_builder::BaseMessageBuilder;
use crate::net::client::base_message_builder::OptTypes;
use crate::net::client::error::Error;
use crate::net::client::query::{GetResult, QueryMessage4};
use octseq::Octets;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;

/// Default configuration value for the amount of time to wait on a non-idle
/// connection for the other side to send a response on any outstanding query.
// Implement a simple response timer to see if the connection and the server
// are alive. Set the timer when the connection goes from idle to busy.
// Reset the timer each time a reply arrives. Cancel the timer when the
// connection goes back to idle. When the time expires, mark all outstanding
// queries as timed out and shutdown the connection.
//
// Note: nsd has 120 seconds, unbound has 3 seconds.
const DEF_RESPONSE_TIMEOUT: Duration = Duration::from_secs(19);

/// Minimum configuration value for response_timeout.
const MIN_RESPONSE_TIMEOUT: Duration = Duration::from_millis(1);

/// Maximum configuration value for response_timeout.
const MAX_RESPONSE_TIMEOUT: Duration = Duration::from_secs(600);

/// Capacity of the channel that transports [ChanReq].
const DEF_CHAN_CAP: usize = 8;

/// Capacity of a private channel between [InnerConnection::reader] and
/// [InnerConnection::run].
const READ_REPLY_CHAN_CAP: usize = 8;

//------------ Config ---------------------------------------------------------

/// Configuration for an octet_stream transport connection.
#[derive(Clone, Debug)]
pub struct Config {
    /// Response timeout.
    pub response_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            response_timeout: DEF_RESPONSE_TIMEOUT,
        }
    }
}

//------------ Connection -----------------------------------------------------

#[derive(Clone, Debug)]
/// A single DNS over octect stream connection.
pub struct Connection<BMB> {
    /// Reference counted [InnerConnection].
    inner: Arc<InnerConnection<BMB>>,
}

impl<BMB: BaseMessageBuilder + Clone> Connection<BMB> {
    /// Constructor for [Connection].
    ///
    /// Returns a [Connection] wrapped in a [Result](io::Result).
    pub fn new(config: Option<Config>) -> Result<Self, Error> {
        let config = match config {
            Some(config) => {
                check_config(&config)?;
                config
            }
            None => Default::default(),
        };
        let connection = InnerConnection::new(config)?;
        Ok(Self {
            inner: Arc::new(connection),
        })
    }

    /// Main execution function for [Connection].
    ///
    /// This function has to run in the background or together with
    /// any calls to [query](Self::query) or [Query::get_result].
    pub async fn run<IO: AsyncReadExt + AsyncWriteExt + Unpin>(
        &self,
        io: IO,
    ) -> Option<()> {
        self.inner.run(io).await
    }

    /// Start a DNS request.
    ///
    /// This function takes a precomposed message as a parameter and
    /// returns a [Query] object wrapped in a [Result].
    async fn query_impl4(
        &self,
        query_msg: &BMB,
    ) -> Result<Box<dyn GetResult + Send>, Error> {
        let (tx, rx) = oneshot::channel();
        self.inner.query(tx, query_msg).await?;
        let msg = query_msg;
        Ok(Box::new(Query::new(msg, rx)))
    }

    /// Start a DNS request but do not check if the reply matches the request.
    ///
    /// This function is similar to [Self::query]. Not checking if the reply
    /// match the request avoids having to keep the request around.
    pub async fn query_no_check(
        &self,
        query_msg: &BMB,
    ) -> Result<QueryNoCheck, Error> {
        let (tx, rx) = oneshot::channel();
        self.inner.query(tx, query_msg).await?;
        Ok(QueryNoCheck::new(rx))
    }
}

impl<BMB: BaseMessageBuilder + Clone> QueryMessage4<BMB> for Connection<BMB> {
    fn query<'a>(
        &'a self,
        query_msg: &'a BMB,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<Box<dyn GetResult + Send>, Error>>
                + Send
                + '_,
        >,
    > {
        return Box::pin(self.query_impl4(query_msg));
    }
}

//------------ Query ----------------------------------------------------------

/// This struct represent an active DNS query.
#[derive(Debug)]
pub struct Query {
    /// Request message.
    ///
    /// The reply message is compared with the request message to see if
    /// it matches the query.
    query_msg: Message<Vec<u8>>,

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

impl Query {
    /// Constructor for [Query], takes a DNS query and a receiver for the
    /// reply.
    fn new<BMB: BaseMessageBuilder>(
        query_msg: &BMB,
        receiver: oneshot::Receiver<ChanResp>,
    ) -> Query {
        let vec = query_msg.to_vec();
        let msg = Message::from_octets(vec)
            .expect("Message failed to parse contents of another Message");
        Self {
            query_msg: msg,
            state: QueryState::Busy(receiver),
        }
    }

    /// Get the result of a DNS query.
    ///
    /// This function returns the reply to a DNS query wrapped in a
    /// [Result].
    pub async fn get_result_impl(&mut self) -> Result<Message<Bytes>, Error> {
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

                let resp = res.expect("error case is checked already");
                let msg = resp.reply;

                if !is_answer_ignore_id(&msg, &self.query_msg) {
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

impl GetResult for Query {
    fn get_result(
        &mut self,
    ) -> Pin<
        Box<dyn Future<Output = Result<Message<Bytes>, Error>> + Send + '_>,
    > {
        Box::pin(self.get_result_impl())
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

                let resp = res.expect("error case is checked already");
                let msg = resp.reply;

                Ok(msg)
            }
            QueryState::Done => {
                panic!("Already done");
            }
        }
    }
}

//------------ InnerConnection ------------------------------------------------

/// The actual implementation of [Connection].
#[derive(Debug)]
struct InnerConnection<BMB> {
    /// User configuration variables.
    config: Config,

    /// [InnerConnection::sender] and [InnerConnection::receiver] are
    /// part of a single channel.
    ///
    /// Used by [Query] to send requests to [InnerConnection::run].
    sender: mpsc::Sender<ChanReq<BMB>>,

    /// receiver part of the channel.
    ///
    /// Protected by a mutex to allow read/write access by
    /// [InnerConnection::run].
    /// The Option is to allow [InnerConnection::run] to signal that the
    /// connection is closed.
    receiver: Futures_mutex<Option<mpsc::Receiver<ChanReq<BMB>>>>,
}

#[derive(Debug)]
/// A request from [Query] to [Connection::run] to start a DNS request.
struct ChanReq<BMB> {
    /// DNS request message
    msg: BMB,

    /// Sender to send result back to [Query]
    sender: ReplySender,
}

/// This is the type of sender in [ChanReq].
type ReplySender = oneshot::Sender<ChanResp>;

/// Response to the DNS request sent by [InnerConnection::run] to [Query].
type ChanResp = Result<Response, Error>;

#[derive(Debug)]
/// a response to a [ChanReq].
struct Response {
    /// The DNS reply message.
    reply: Message<Bytes>,
}

/// Internal datastructure of [InnerConnection::run] to keep track of
/// outstanding DNS requests.
struct Queries {
    /// The number of elements in [Queries::vec] that are not None.
    count: usize,

    /// Index in the [Queries::vec] where to look for a space for a new query.
    curr: usize,

    /// Vector of senders to forward a DNS reply message (or error) to.
    vec: Vec<Option<ReplySender>>,
}

/// Internal datastructure of [InnerConnection::run] to keep track of
/// the status of the connection.
// The types Status and ConnState are only used in InnerConnection
struct Status {
    /// State of the connection.
    state: ConnState,

    /// Boolean if we need to include an edns-tcp-keepalive option in an
    /// outogoing request.
    ///
    /// Typically send_keepalive is true at the start of the connection.
    /// it gets cleared when we successfully managed to include the option
    /// in a request.
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

    /// It took too long to receive a (or another) response.
    ReadTimeout,

    /// A write error occurred.
    WriteError(Error),
}

/// A DNS message received to [InnerConnection::reader] and sent to
/// [InnerConnection::run].
// This type could be local to InnerConnection, but I don't know how
type ReaderChanReply = Message<Bytes>;

impl<BMB: BaseMessageBuilder + Clone> InnerConnection<BMB> {
    /// Constructor for [InnerConnection].
    ///
    /// This is the implementation of [Connection::new].
    pub fn new(config: Config) -> Result<Self, Error> {
        let (tx, rx) = mpsc::channel(DEF_CHAN_CAP);
        Ok(Self {
            config,
            sender: tx,
            receiver: Futures_mutex::new(Some(rx)),
        })
    }

    /// Main execution function for [InnerConnection].
    ///
    /// This function Gets called by [Connection::run].
    /// This function is not async cancellation safe
    pub async fn run<IO: AsyncReadExt + AsyncWriteExt + Unpin>(
        &self,
        io: IO,
    ) -> Option<()> {
        let (reply_sender, mut reply_receiver) =
            mpsc::channel::<ReaderChanReply>(READ_REPLY_CHAN_CAP);

        let (mut read_stream, mut write_stream) = tokio::io::split(io);

        let reader_fut = Self::reader(&mut read_stream, reply_sender);
        tokio::pin!(reader_fut);

        let mut receiver = {
            let mut locked_opt_receiver = self.receiver.lock().await;
            let opt_receiver = locked_opt_receiver.take();
            opt_receiver.expect("no receiver present?")
        };

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
            let recv_fut = receiver.recv();

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
                        Some(req) =>
                            self.insert_req(req, &mut status,
                                &mut reqmsg, &mut query_vec),
                        None => panic!("recv failed"),
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

        None
    }

    /// This function sends a DNS request to [InnerConnection::run].
    pub async fn query(
        &self,
        sender: oneshot::Sender<ChanResp>,
        query_msg: &BMB,
    ) -> Result<(), Error> {
        // We should figure out how to get query_msg.

        let req = ChanReq {
            sender,
            msg: query_msg.clone(),
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

    /// This function reads a DNS message from the connection and sends
    /// it to [InnerConnection::run].
    ///
    /// Reading has to be done in two steps: first read a two octet value
    /// the specifies the length of the message, and then read in a loop the
    /// body of the message.
    ///
    /// This function is not async cancellation safe.
    async fn reader<ReadStream: AsyncReadExt + Unpin>(
        //sock: &mut ReadStream,
        mut sock: ReadStream,
        sender: mpsc::Sender<ReaderChanReply>,
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

    /// An error occured, report the error to all outstanding [Query] objects.
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

    /// Handle received EDNS options, in particular the edns-tcp-keepalive
    /// option.
    fn handle_opts<Octs2: Octets + AsRef<[u8]>>(
        opts: &OptRecord<Octs2>,
        status: &mut Status,
    ) {
        for option in opts.opt().iter().flatten() {
            if let AllOptData::TcpKeepalive(tcpkeepalive) = option {
                Self::handle_keepalive(tcpkeepalive, status);
            }
        }
    }

    /// Demultiplex a DNS reply and send it to the right [Query] object.
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
                let reply = Response { reply: answer };
                _ = sender.send(Ok(reply));
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
        &self,
        mut req: ChanReq<BMB>,
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
    fn convert_query(
        msg: &dyn BaseMessageBuilder,
        reqmsg: &mut Option<Vec<u8>>,
    ) {
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
fn add_tcp_keepalive<BMB: BaseMessageBuilder>(
    msg: &mut BMB,
) -> Result<(), Error> {
    msg.add_opt(OptTypes::TypeTcpKeepalive(TcpKeepalive::new(None)));
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

/// Check if config is valid.
fn check_config(config: &Config) -> Result<(), Error> {
    if config.response_timeout < MIN_RESPONSE_TIMEOUT
        || config.response_timeout > MAX_RESPONSE_TIMEOUT
    {
        return Err(Error::OctetStreamConfigError(Arc::new(
            std::io::Error::new(ErrorKind::Other, "response_timeout"),
        )));
    }

    Ok(())
}
