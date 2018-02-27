//! DNS requests: the bridge between query and transport.
//!
//! While the future of the `Query` can be driven by any task, the network
//! transports are spawned into a reactor core each as a task of their own.
//! Requests and responses are exchanged between them using futures’s sync
//! primitives. Each transport holds the receiving end of an unbounded MPSC
//! channel for requests (defined as a type alias `RequestReceiver` herein),
//! with the sending end wrapped into the `TransportHandle` type and stored
//! in the `Resolver` for use by `Query`s.
//!
//! The query takes this transport handle and a `RequestMessage` (a light
//! wrapper around a DNS message ensuring that it is of the expected format)
//! and creates the query side of a request, aptly named `QueryRequest`. It
//! is a future resolving into either a response and the original request
//! message or an error and the very same request message.
//!
//! The reason for handing back the request message is that we can then
//! reuse it for further requests. Since we internally store DNS messages in
//! wire-format, anyway, they can be used as the send buffer directly and
//! reuse does make sense.
//!
//! The request sent over the channel is a `TransportRequest`. It consists
//! of the actual message now in the disguise of a `TransportMessage` 
//! providing what the transport needs and the sending end of a oneshot
//! channel into which the transport is supposed to throw the response to
//! the request.
//!
//! The receiving end of the oneshot is part of the query request which polls
//! it for its completion.
//!
//! Note that timeouts happen on the transport side. While this is a little
//! less robust that we’d like, timeouts are tokio-core thing and need a
//! reactor. This way, we also potentially need fewer timeouts of lots of
//! requests are in flight.

use std::{fmt, io, ops};
use futures::{Async, Future, Poll};
use futures::sync::{mpsc, oneshot, BiLock, BiLockGuard};
use ::bits::{AdditionalBuilder, ComposeMode, ComposeResult, DName,
             Message, MessageBuf, MessageBuilder, Question};
use super::conf::ResolvConf;
use super::error::Error;


//============ The Path of a Message Through a Request =======================

//------------ RequestMessage ------------------------------------------------

/// The DNS message for input into a request.
///
/// The wrapped message is a message builder in stream mode. It consists of
/// exactly one question which is why compression is unnecessary and turned
/// off. It also has been advanced into a additional section builder. This
/// allows transports to add their EDNS0 information and, once they are done
/// with that, rewind their additions for reuse.
///
/// The only thing you can do with a request message is turn them into a
/// transport message using the `into_service()` method.
pub struct RequestMessage(AdditionalBuilder);

impl RequestMessage {
    /// Creates a new request message from a question and resolver config.
    ///
    /// This may fail if the domain name of the question isn’t absolute.
    pub fn new<N, Q>(question: Q, conf: &ResolvConf) -> ComposeResult<Self>
               where N: DName,
                     Q: Into<Question<N>> {
        let mut msg = MessageBuilder::new(ComposeMode::Stream, false)?;
        msg.header_mut().set_rd(conf.options.recurse);
        msg.push(question)?;
        Ok(RequestMessage(msg.additional()))
    }

    /// Converts the request message into a transport message.
    ///
    /// This method returns the transport message wrapped into a pair of
    /// bi-locks. See `TransportMessage` for a discussion as to why that
    /// is useful.
    fn into_service(self) -> (BiLock<Option<TransportMessage>>,
                              BiLock<Option<TransportMessage>>) {
        BiLock::new(Some(TransportMessage(self.0)))
    }
}


//------------ TransportMessage ----------------------------------------------

/// The DNS message passed to and used by the service.
///
/// This is a DNS request with exactly one question. The transport can add
/// its EDNS0 information to it and then access the message bytes for
/// sending. Once done, the transport message can be returned into a
/// request message by dropping all EDNS0 information thus making it ready
/// for reuse by the next transport.
/// 
/// *Note:* EDNS0 is not yet implemented.
///
/// Transport messages are always kept wrapped into a pair of bi-locks. One
/// of those locks goes into the transport request for use by the transport,
/// the other one is kept by the query request. This way, we don’t need to
/// pass the message back when the transport is done which makes a lot easier
/// to treat all these cases where values along the way are dropped. In order
/// to allow the message being taken out of the lock, the lock’s content is
/// an option.
///
/// The rule is simple, violation will result in panics (but everything is
/// wrapped in `QueryRequest` and `TransportRequest` herein): The locks are
/// created with `Some` message. As long as the oneshot of the query request
/// has not been resolved, either successfully or by the sending end being
/// dropped, the transport has exclusive access to the message. It must,
/// however, not `take()` out the message. By resolving the oneshot, access
/// is transferred back to the query request. It then can `take()` out the
/// message.
pub struct TransportMessage(AdditionalBuilder);

impl TransportMessage {
    /// Sets the message ID to the given value.
    pub fn set_id(&mut self, id: u16) {
        self.0.header_mut().set_id(id)
    }

    /// Checks whether `answer` is an answer to this message.
    pub fn is_answer(&self, answer: &Message) -> bool {
        answer.is_answer(&self.0)
    }

    /// Trades in this transport message for a request message.
    ///
    /// This rewinds all additions made to the message since creation but
    /// leaves the ID in place.
    pub fn rewind(self) -> RequestMessage {
        RequestMessage(self.0)
    }

    /// Returns a bytes slice with the data to be sent over stream transports.
    pub fn stream_bytes(&mut self) -> &[u8] {
        self.0.preview()
    }

    /// Returns a bytes slice for sending over datagram transports.
    pub fn dgram_bytes(&mut self) -> &[u8] {
        &self.0.preview()[2..]
    }
}


//------------ TransportMessageGuard -----------------------------------------

/// A RAII guard for a locked transport message.
///
/// This implements both `Deref` and `DerefMut` into the underlying, locked
/// transport message. Once the value is dropped, the lock is released.
pub struct TransportMessageGuard<'a>(
    BiLockGuard<'a, Option<TransportMessage>>
);


//--- Deref, DerefMut

impl<'a> ops::Deref for TransportMessageGuard<'a> {
    type Target = TransportMessage;

    fn deref(&self) -> &TransportMessage {
        self.0.deref().as_ref().expect("message already taken")
    }
}

impl<'a> ops::DerefMut for TransportMessageGuard<'a> {
    fn deref_mut(&mut self) -> &mut TransportMessage {
        self.0.deref_mut().as_mut().expect("message alread taken")
    }
}


//------------ TransportResult -----------------------------------------------

/// The result returned by the transport.
///
/// This is the item type of the oneshot channel between transport request and
/// query request.
type TransportResult = Result<MessageBuf, Error>;


//============ The Query Side of a Request ===================================

//------------ QueryRequest --------------------------------------------------

/// The query side of a request.
///
/// This type is used by `Query` to dispatch and wait for requests. It is a
/// future resolving either into a both the response and request message or
/// an error and the request message.
pub struct QueryRequest {
    /// The reading end of the oneshot channel for the reponse.
    rx: Option<oneshot::Receiver<TransportResult>>,

    /// Our side of the bi-locked transport message.
    msg: BiLock<Option<TransportMessage>>,
}

impl QueryRequest {
    /// Creates a new query request.
    ///
    /// The request will attempt to answer `message` using the transport
    /// referenced by `transport`.
    pub fn new(message: RequestMessage, transport: &TransportHandle) -> Self {
        let (tx, rx) = oneshot::channel();
        let (smsg, qmsg) = message.into_service();
        let sreq = TransportRequest::new(smsg, tx);
        let rx = transport.send(sreq).ok().map(|_| rx);
        QueryRequest {
            rx: rx,
            msg: qmsg
        }
    }
}


//--- Future

impl Future for QueryRequest {
    type Item = (MessageBuf, RequestMessage);
    type Error = (Error, RequestMessage);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.rx {
            Some(ref mut rx) => {
                match rx.poll() {
                    Ok(Async::NotReady) => Ok(Async::NotReady),
                    Ok(Async::Ready(response)) => {
                        let msg = into_message(&mut self.msg);
                        match response {
                            Ok(response) => Ok(Async::Ready((response, msg))),
                            Err(err) => Err((err, msg)),
                        }
                    }
                    Err(_) => {
                        // The transport disappeared. Let’s do a connection
                        // aborted error even if that isn’t quite right for
                        // UDP.
                        let msg = into_message(&mut self.msg);
                        Err((Error::Io(
                                io::Error::new(
                                    io::ErrorKind::ConnectionAborted,
                                    "transport disappeared")),
                             msg))
                    }
                }
            }
            None => {
                let msg = into_message(&mut self.msg);
                Err((Error::Io(
                        io::Error::new(io::ErrorKind::ConnectionAborted,
                                       "service disappeared")),
                        msg))
            }
        }
    }
}

/// Helper function for unwrapping the transport message.
/// 
/// The function will take the transport message out of the lock if and only
/// if it can do so without blocking, panicing otherwise. See
/// `TransportMessage` for the rules when this is allowed.
fn into_message(msg: &mut BiLock<Option<TransportMessage>>) -> RequestMessage {
    match msg.poll_lock() {
        Async::Ready(ref mut msg) => {
            match msg.take() {
                Some(msg) => msg.rewind(),
                None => panic!("called poll on a resolved QueryRequest"),
            }
        }
        Async::NotReady => panic!("service kept message locked"),
    }
}


//============ The Transport Side of a Request ===============================

//------------ TransportRequest ----------------------------------------------

/// The transport side of a request.
///
/// This type is used by a transport to try and discover the answer to a DNS
/// request. It contains both the message for this request and the sending
/// end of a oneshot channel to deliver the result to.
///
/// The transport requesst can safely be dropped at any time. However, it is
/// always better to resolve it with a specific error, allowing the query to
/// decide on its strategy based on this error instead of having to guess.
pub struct TransportRequest {
    /// The request message behind a bi-lock.
    message: BiLock<Option<TransportMessage>>,

    /// The sending side of a oneshot channel for the result of the request.
    complete: oneshot::Sender<TransportResult>,

    /// The message ID of the request message.
    ///
    /// This is initially `None` to indicate that it hasn’t been set for this
    /// particular iteration yet.
    id: Option<u16>,
}

impl TransportRequest {
    /// Creates a new transport request from its components.
    fn new(message: BiLock<Option<TransportMessage>>,
           complete: oneshot::Sender<TransportResult>) 
           -> Self {
        TransportRequest {
            message: message,
            complete: complete,
            id: None
        }
    }

    /// Provides access to the transport message.
    ///
    /// Access happens in the form of a RAII guard that locks the message
    /// while being alive.
    ///
    /// # Panics
    ///
    /// Panics if the message has been taken out of the lock. This should
    /// not happen while the transport request is alive. Hence the panic.
    pub fn message(&self) -> TransportMessageGuard {
        if let Async::Ready(guard) = self.message.poll_lock() {
            TransportMessageGuard(guard)
        }
        else {
            panic!("message not ready");
        }
    }

    /// Returns the request message’s ID or `None` if it hasn’t been set yet.
    pub fn id(&self) -> Option<u16> {
        self.id
    }

    /// Sets the request message’s ID to the given value.
    pub fn set_id(&mut self, id: u16) {
        self.id = Some(id);
        self.message().set_id(id)
    }

    /// Completes the request with the given result.
    pub fn complete(self, result: TransportResult) {
        // Drop the message’s lock before completing as per the rules for
        // transport messages.
        let complete = self.complete;
        drop(self.message);
        complete.send(result).ok();
    }

    /// Completes the request with a response message.
    ///
    /// This will produce a successful result only if `response` actually is
    /// an answer to the request message. Else drops the message and produces
    /// an error.
    pub fn response(self, response: MessageBuf) {
        if self.message().is_answer(&response) {
            self.complete(Ok(response))
        }
        else {
            self.fail(io::Error::new(io::ErrorKind::Other, "server failure")
                                .into())
        }
    }

    /// Completes the request with the given error.
    pub fn fail(self, err: Error) {
        self.complete(Err(err))
    }

    /// Completes the request with a timeout error.
    pub fn timeout(self) {
        self.complete(Err(Error::Timeout))
    }
}


//------------ TransportHandle -----------------------------------------------

/// A handle for communicating with a transport.
///
/// You can use this handle to send requests to the transport via the `send()`
/// method.
#[derive(Clone)]
pub struct TransportHandle {
    /// The sending end of the transport’s request queue
    tx: mpsc::UnboundedSender<TransportRequest>,
}

impl TransportHandle {
    /// Creates a new request channel, returning both ends.
    pub fn channel() -> (TransportHandle, RequestReceiver) {
        let (tx, rx) = mpsc::unbounded();
        (TransportHandle::from_sender(tx), rx)
    } 

    /// Creates a new handle from the sender side of an MPCS channel.
    pub fn from_sender(tx: mpsc::UnboundedSender<TransportRequest>) -> Self {
        TransportHandle {
            tx: tx
        }
    }

    /// Sends a transport request to the transport.
    ///
    /// This only fails if the receiver was dropped.
    #[allow(deprecated)]
    pub fn send(&self, sreq: TransportRequest)
                -> Result<(), mpsc::SendError<TransportRequest>> {
        self.tx.send(sreq)
    }
}


//--- Debug

impl fmt::Debug for TransportHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TransportHandle{{...}}")
    }
}


//------------ RequestReceiver -----------------------------------------------

/// The type of the receiving end of the request channel.
pub type RequestReceiver = mpsc::UnboundedReceiver<TransportRequest>;


