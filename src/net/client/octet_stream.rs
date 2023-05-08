//! A DNS over octet stream transport
//! # Example with TCP connection to port 53
//! ```
#![doc = include_str!("../../../examples/tcp-client.rs")]
//! ```
//! # Example with TLS connection to port 853
//! ```
#![doc = include_str!("../../../examples/tls-client.rs")]
//! ```

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
use std::fmt::Debug;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::vec::Vec;

use crate::base::wire::Composer;
use crate::base::{
    opt::{AllOptData, Opt, OptRecord, TcpKeepalive},
    Message, MessageBuilder, ParsedDname, Rtype, StaticCompressor,
    StreamTarget,
};
use crate::rdata::AllRecordData;
use octseq::{Octets, OctetsBuilder};

use tokio::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;

/// Error returned when too many queries are currently active.
const ERR_TOO_MANY_QUERIES: &str = "too many outstanding queries";

/// Time to wait on a non-idle connection for the other side to send
/// a response on any outstanding query.
// Implement a simple response timer to see if the connection and the server
// are alive. Set the timer when the connection goes from idle to busy.
// Reset the timer each time a reply arrives. Cancel the timer when the
// connection goes back to idle. When the time expires, mark all outstanding
// queries as timed out and shutdown the connection.
//
// Note: nsd has 120 seconds, unbound has 3 seconds.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(19);

/// Capacity of the channel that transports [ChanReq].
const DEF_CHAN_CAP: usize = 8;

/// Capacity of a private channel between [InnerConnection::reader] and
/// [InnerConnection::run].
const READ_REPLY_CHAN_CAP: usize = 8;

/// Error reported when the connection is closed and
/// [InnerConnection::run] terminated.
const ERR_CONN_CLOSED: &str = "connection closed";

/// This is the type of sender in [ChanReq].
type ReplySender = oneshot::Sender<ChanResp>;

#[derive(Debug)]
/// A request from [Query] to [Connection::run] to start a DNS request.
struct ChanReq<Octs: OctetsBuilder> {
    /// DNS request message
    msg: MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,

    /// Sender to send result back to [Query]
    sender: ReplySender,
}

#[derive(Debug)]
/// a response to a [ChanReq].
struct Response {
    /// The 2 octet id that went into the outgoing DNS request.
    ///
    /// This id is needed to match the response with the query.
    id: u16,

    /// The DNS reply message.
    reply: Message<Bytes>,
}
/// Response to the DNS request sent by [InnerConnection::run] to [Query].
type ChanResp = Result<Response, Arc<std::io::Error>>;

/// The actual implementation of [Connection].
struct InnerConnection<Octs: OctetsBuilder> {
    /// [InnerConnection::sender] and [InnerConnection::receiver] are
    /// part of a single channel.
    ///
    /// Used by [Query] to send requests to [InnerConnection::run].
    sender: mpsc::Sender<ChanReq<Octs>>,

    /// receiver part of the channel.
    ///
    /// Protected by a mutex to allow read/write access by
    /// [InnerConnection::run].
    /// The Option is to allow [InnerConnection::run] to signal that the
    /// connection is closed.
    receiver: Futures_mutex<Option<mpsc::Receiver<ChanReq<Octs>>>>,
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

#[derive(Clone)]
/// A single DNS over octect stream connection.
pub struct Connection<Octs: OctetsBuilder> {
    /// Reference counted [InnerConnection].
    inner: Arc<InnerConnection<Octs>>,
}

/// Status of a query. Used in [Query].
enum QueryState {
    /// A request is in progress.
    ///
    /// The receiver for receiving the response is part of this state.
    Busy(oneshot::Receiver<ChanResp>),

    /// The response has been received and the query is done.
    Done,
}

/// This struct represent an active DNS query.
pub struct Query {
    /// Request message.
    ///
    /// The reply message is compared with the request message to see if
    /// it matches the query.
    query_msg: Message<Vec<u8>>,

    /// Current state of the query.
    state: QueryState,
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
    ReadError,

    /// It took too long to receive a (or another) response.
    ReadTimeout,

    /// A write error occurred.
    WriteError,
}

/// A DNS message received to [InnerConnection::reader] and sent to
/// [InnerConnection::run].
// This type could be local to InnerConnection, but I don't know how
type ReaderChanReply = Message<Bytes>;

impl<Octs: AsMut<[u8]> + Clone + Composer + Debug + OctetsBuilder>
    InnerConnection<Octs>
{
    /// Constructor for [InnerConnection].
    ///
    /// This is the implementation of [Connection::new].
    pub fn new() -> io::Result<InnerConnection<Octs>> {
        let (tx, rx) = mpsc::channel(DEF_CHAN_CAP);
        Ok(Self {
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
                        if elapsed > RESPONSE_TIMEOUT {
                            let error = io::Error::new(
                                io::ErrorKind::Other,
                                "read timeout",
                            );
                            Self::error(error, &mut query_vec);
                            status.state = ConnState::ReadTimeout;
                            break;
                        }
                        Some(RESPONSE_TIMEOUT - elapsed)
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
                | ConnState::ReadError
                | ConnState::WriteError => None, // No timers here
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
                    RESPONSE_TIMEOUT
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
                            Self::error(error,
                                &mut query_vec);
                            status.state =
                                ConnState::ReadError;
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
                        Self::error(error,
                            &mut query_vec);
                        status.state =
                            ConnState::WriteError;
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
                ConnState::ReadError
                | ConnState::ReadTimeout
                | ConnState::WriteError => {
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
        query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,
    ) -> Result<(), &'static str> {
        // We should figure out how to get query_msg.
        let msg_clone = query_msg.clone();

        let req = ChanReq {
            sender,
            msg: msg_clone,
        };
        match self.sender.send(req).await {
            Err(_) =>
            // Send error. The receiver is gone, this means that the
            // connection is closed.
            {
                Err(ERR_CONN_CLOSED)
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
    ) -> Result<(), std::io::Error> {
        loop {
            let read_res = sock.read_u16().await;
            let len = match read_res {
                Ok(len) => len,
                Err(error) => {
                    return Err(error);
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
                            let error = io::Error::new(
                                io::ErrorKind::Other,
                                "unexpected end of data",
                            );
                            return Err(error);
                        }
                    }
                    Err(error) => {
                        return Err(error);
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
                    let error =
                        io::Error::new(io::ErrorKind::Other, "short buf");
                    return Err(error);
                }
            }
        }
    }

    /// An error occured, report the error to all outstanding [Query] objects.
    fn error(error: std::io::Error, query_vec: &mut Queries) {
        // Update all requests that are in progress. Don't wait for
        // any reply that may be on its way.
        let arc_error = Arc::new(error);
        for index in 0..query_vec.vec.len() {
            if query_vec.vec[index].is_some() {
                let sender = Self::take_query(query_vec, index)
                    .expect("we tested is_none before");
                _ = sender.send(Err(arc_error.clone()));
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
                let sender = Self::take_query(query_vec, index).unwrap();
                let ind16: u16 = index.try_into().unwrap();
                let reply = Response {
                    reply: answer,
                    id: ind16,
                };
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
        mut req: ChanReq<Octs>,
        status: &mut Status,
        reqmsg: &mut Option<Vec<u8>>,
        query_vec: &mut Queries,
    ) {
        match status.state {
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
                _ = req.sender.send(Err(Arc::new(io::Error::new(
                    io::ErrorKind::Other,
                    "idle timeout",
                ))));
                return;
            }
            ConnState::ReadError => {
                _ = req.sender.send(Err(Arc::new(io::Error::new(
                    io::ErrorKind::Other,
                    "read error",
                ))));
                return;
            }
            ConnState::ReadTimeout => {
                _ = req.sender.send(Err(Arc::new(io::Error::new(
                    io::ErrorKind::Other,
                    "read timeout",
                ))));
                return;
            }
            ConnState::WriteError => {
                _ = req.sender.send(Err(Arc::new(io::Error::new(
                    io::ErrorKind::Other,
                    "write error",
                ))));
                return;
            }
        }

        // Note that insert may fail if there are too many
        // outstanding queires. First call insert before checking
        // send_keepalive.
        // XXX
        let index = Self::insert(req.sender, query_vec).unwrap();

        let ind16: u16 = index.try_into().unwrap();

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
            let res_msg = add_tcp_keepalive(&req.msg);

            match res_msg {
                Ok(msg) => {
                    Self::convert_query(&msg, reqmsg);
                    status.send_keepalive = false;
                }
                Err(_) => {
                    // Adding keepalive option
                    // failed. Send the original
                    // request.
                    Self::convert_query(&req.msg, reqmsg);
                }
            }
        } else {
            Self::convert_query(&req.msg, reqmsg);
        }
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
    fn convert_query<Target: AsMut<[u8]> + AsRef<[u8]>>(
        msg: &MessageBuilder<StaticCompressor<StreamTarget<Target>>>,
        reqmsg: &mut Option<Vec<u8>>,
    ) {
        let vec = msg.as_target().as_target().as_stream_slice();

        // Store a clone of the request. That makes life easier
        // and requests tend to be small
        *reqmsg = Some(vec.to_vec());
    }

    /// Insert a sender (for the reply) in the query_vec and return the index.
    fn insert(
        sender: oneshot::Sender<ChanResp>,
        query_vec: &mut Queries,
    ) -> Result<usize, &'static str> {
        let q = Some(sender);

        // Fail if there are to many entries already in this vector
        // We cannot have more than u16::MAX entries because the
        // index needs to fit in an u16. For efficiency we want to
        // keep the vector half empty. So we return a failure if
        // 2*count > u16::MAX
        if 2 * query_vec.count > u16::MAX.into() {
            return Err(ERR_TOO_MANY_QUERIES);
        }

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

impl<
        Octs: AsMut<[u8]> + AsRef<[u8]> + Clone + Composer + Debug + OctetsBuilder,
    > Connection<Octs>
{
    /// Constructor for [Connection].
    ///
    /// Returns a [Connection] wrapped in a [Result](io::Result).
    pub fn new() -> io::Result<Connection<Octs>> {
        let connection = InnerConnection::new()?;
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
    pub async fn query(
        &self,
        query_msg: &mut MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,
    ) -> Result<Query, &'static str> {
        let (tx, rx) = oneshot::channel();
        self.inner.query(tx, query_msg).await?;
        let msg = &query_msg.as_message();
        Ok(Query::new(msg, rx))
    }
}

impl Query {
    /// Constructor for [Query], takes a DNS query and a receiver for the
    /// reply.
    fn new<Octs: Octets>(
        query_msg: &Message<Octs>,
        receiver: oneshot::Receiver<ChanResp>,
    ) -> Query {
        let msg_ref: &[u8] = query_msg.as_ref();
        let vec = msg_ref.to_vec();
        let msg = Message::from_octets(vec).unwrap();
        Self {
            query_msg: msg,
            state: QueryState::Busy(receiver),
        }
    }

    /// Get the result of a DNS query.
    ///
    /// This function returns the reply to a DNS query wrapped in a
    /// [Result].
    pub async fn get_result(
        &mut self,
    ) -> Result<Message<Bytes>, Arc<std::io::Error>> {
        match self.state {
            QueryState::Busy(ref mut receiver) => {
                let res = receiver.await;
                self.state = QueryState::Done;
                if res.is_err() {
                    // Assume receive error
                    return Err(Arc::new(io::Error::new(
                        io::ErrorKind::Other,
                        "receive error",
                    )));
                }
                let res = res.unwrap();

                // clippy seems to be wrong here. Replacing
                // the following with 'res?;' doesn't work
                #[allow(clippy::question_mark)]
                if let Err(err) = res {
                    return Err(err);
                }

                let resp = res.unwrap();
                let msg = resp.reply;

                let hdr = self.query_msg.header_mut();
                hdr.set_id(resp.id);

                if !msg.is_answer(&self.query_msg) {
                    return Err(Arc::new(io::Error::new(
                        io::ErrorKind::Other,
                        "wrong answer",
                    )));
                }
                Ok(msg)
            }
            QueryState::Done => {
                panic!("Already done");
            }
        }
    }
}

/// Add an edns-tcp-keepalive option to a MessageBuilder.
///
/// This is surprisingly difficult. We need to copy the original message to
/// a new MessageBuilder because MessageBuilder has no support for changing the
/// opt record.
fn add_tcp_keepalive<Octs: Clone + Composer + OctetsBuilder>(
    msg: &MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,
) -> Result<
    MessageBuilder<StaticCompressor<StreamTarget<Octs>>>,
    crate::base::message_builder::PushError,
> {
    // We can't just insert a new option in an existing
    // opt record. So we have to create new message and copy records
    // from the old one. And insert our option while copying the opt
    // record.
    let src_clone = msg.clone();
    let source = Message::from_octets(
        src_clone.as_target().as_target().as_dgram_slice(),
    )
    .unwrap();
    let target = msg.clone();

    let source = source.question();
    // Go to additional and back to builder to delete all sections
    // except for the header
    let mut target = target.additional().builder().question();
    for rr in source {
        let rr = rr.unwrap();
        target.push(rr)?;
    }
    let mut source = source.answer().unwrap();
    let mut target = target.answer();
    for rr in &mut source {
        let rr = rr.unwrap();
        let rr = rr
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .unwrap();
        target.push(rr)?;
    }

    let mut source = source.next_section().unwrap().unwrap();
    let mut target = target.authority();
    for rr in &mut source {
        let rr = rr.unwrap();
        let rr = rr
            .into_record::<AllRecordData<_, ParsedDname<_>>>()
            .unwrap()
            .unwrap();
        target.push(rr)?;
    }

    let source = source.next_section().unwrap().unwrap();
    let mut target = target.additional();
    let mut found_opt_rr = false;
    for rr in source {
        let rr = rr.unwrap();
        if rr.rtype() == Rtype::Opt {
            found_opt_rr = true;
            let rr = rr.into_record::<Opt<_>>().unwrap().unwrap();
            let opt_record = OptRecord::from_record(rr);
            target
                .opt(|newopt| {
                    newopt
                        .set_udp_payload_size(opt_record.udp_payload_size());
                    newopt.set_version(opt_record.version());
                    newopt.set_dnssec_ok(opt_record.dnssec_ok());
                    for option in opt_record.opt().iter::<AllOptData<_, _>>()
                    {
                        let option = option.unwrap();
                        if let AllOptData::TcpKeepalive(_) = option {
                            panic!("handle keepalive");
                        } else {
                            newopt.push(&option).unwrap();
                        }
                    }
                    // send an empty keepalive option
                    newopt.tcp_keepalive(None).unwrap();
                    Ok(())
                })
                .unwrap();
        } else {
            let rr = rr
                .into_record::<AllRecordData<_, ParsedDname<_>>>()
                .unwrap()
                .unwrap();
            target.push(rr)?;
        }
    }
    if !found_opt_rr {
        // send an empty keepalive option
        target.opt(|opt| opt.tcp_keepalive(None))?;
    }

    // It would be nice to use .builder() here. But that one deletes all
    // section. We have to resort to .as_builder() which gives a
    // reference and then .clone()
    Ok(target.as_builder().clone())
}
