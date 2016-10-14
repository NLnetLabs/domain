//! A DNS request.
//!
//! We call the cycle of sending a question to a single upstream DNS resolver
//! and hopefully receiving a response a *request* (as opposed to *query*
//! which is the process of asking as many known upstream resolvers as
//! necessary to get an answer).
//!
//! Requests also bridge the gap between the future of the query that can
//! run anywhere and the future of the service in question that runs inside
//! a reactor core. Because of that, there are two types herein, one for
//! each side of that gap and somewhat lamely named `QueryRequest` and
//! `ServiceRequest`.
//!
//! Since queries normally run a sequence of requests until the first one
//! succeeds, we should be able to reuse the request message in subsequent
//! requests. However, a service needs to be able to add its own OPT record
//! to the additional section for EDNS0 support, so we can’t really use the
//! same message for each service. Instead, we need to revert to the
//! end of the question section. While this is not yet supported by
//! `MessageBuilder`, the types herein already support this notion by
//! returning the request message as part of their responses. However, there
//! is a possibility that the message gets lost during transfer over the gap.
//! Since the query doesn’t store a copy, this case means that the query
//! fails fatally.
//!
//! Worse, since the `ServiceRequest` contains the message and the `Drop`
//! trait operates on a mutable reference, we can’t fail the request in its
//! `Drop` implementation and instead have to rely on services always either
//! succeeding or failing all their requests.

use std::io;
use futures::{Future, Complete, Oneshot, Poll, oneshot};
use tokio_core::channel::{Receiver, Sender};
use ::bits::{Message, MessageBuf, MessageBuilder};
use super::error::{Error};


//------------ QueryRequest --------------------------------------------------

/// Query side of a request.
///
/// This type is used by `Query` to dispatch and wait for requests. It is a
/// future resolving either into both the actual request result, either a
/// `MessageBuf` with a response or an `Error`, and the original request
/// message or an `io::Error` in which case the original message is lost.
///
/// The request has to send a service request to a service which can fail.
/// Because of that, it is internally a `Result`. When sending fails, it
/// contains an `Err` which is translated into a fatal error. If all is
/// well, it contains an `Ok` with the oneshot future that will receive the
/// result from the service request.
#[allow(type_complexity)]
pub struct QueryRequest(Result<Oneshot<(Result<MessageBuf, Error>,
                                        MessageBuilder)>,
                               Option<io::Error>>);


impl QueryRequest {
    /// Starts the request dispatching a message to a service.
    pub fn new(message: MessageBuilder, service: &ServiceHandle) -> Self {
        let (c, o) = oneshot();
        let sreq = ServiceRequest::new(message, c);
        match service.tx.send(sreq) {
            Ok(()) => QueryRequest(Ok(o)),
            Err(err) => QueryRequest(Err(Some(err)))
        }
    }
}


//--- Future

impl Future for QueryRequest {
    type Item = (Result<MessageBuf, Error>, MessageBuilder);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0 {
            Ok(ref mut oneshot) => {
                oneshot.poll().map_err(|_| {
                    io::Error::new(io::ErrorKind::Other,
                                   "ServiceRequest’s complete dropped")
                })
            }
            Err(ref mut err) => {
                match err.take() {
                    Some(err) => Err(err),
                    None => panic!("polling a resolved QueryRequest")
                }
            }
        }
    }
}


//------------ ServiceRequest ------------------------------------------------

/// Service side of a request.
///
/// This type is used by a DNS service in order to discover either an answer
/// or an error. Once the service has one, it completes the request with it
/// which will be reported to the associated `QueryRequest`.
///
/// The service request owns the DNS message for the request and allows the
/// service to get access to the bytes of that message for sending. When we
/// start supporting EDNS, the type will gain methods for adding an OPT
/// record to the message, too.
pub struct ServiceRequest {
    /// The request message.
    ///
    /// This value contains a message builder in stream mode containing
    /// one question. Assuming a minimum message size of 512 for non-EDNS
    /// UDP, there should be no fragmentation issues, so this is all fine.
    message: MessageBuilder,

    /// The complete side of our oneshot to return a response.
    complete: Complete<(Result<MessageBuf, Error>, MessageBuilder)>,

    /// The message ID of the request message.
    id: u16,
}


impl ServiceRequest {
    /// Creates a new service request.
    fn new(message: MessageBuilder,
           complete: Complete<(Result<MessageBuf, Error>, MessageBuilder)>)
           -> Self {
        ServiceRequest{message: message, complete: complete, id: 0}
    }

    /// Returns the ID of the request.
    ///
    /// Note that this may differ from what’s in the message until
    /// `set_id()` is called first.
    ///
    /// (We could make this an option but, really, this is an internal type
    /// and should be fine.)
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Sets the request’s and message’s ID.
    pub fn set_id(&mut self, id: u16) {
        self.id = id;
        self.message.header_mut().set_id(id)
    }

    /// Returns a bytes slice of the message for datagram transports.
    pub fn dgram_bytes(&mut self) -> &[u8] {
        &self.message.preview()[2..]
    }

    /// Returns a bytes slice of the message for stream transports.
    pub fn stream_bytes(&mut self) -> &[u8] {
        self.message.preview()
    }

    /// Respond to the request with `response`.
    ///
    /// This will succeed the request if `response` really is an answer
    /// to our request message or fail it otherwise.
    pub fn response(mut self, response: MessageBuf) {
        let is_answer = {
            let request = Message::from_bytes(self.dgram_bytes()).unwrap();
            response.is_answer(request)
        };
        if is_answer {
            self.complete.complete((Ok(response), self.message))
        }
        else {
            self.fail(io::Error::new(io::ErrorKind::Other, "server failure")
                                .into())
        }
    }
    
    /// Fails this request with the given error.
    pub fn fail(self, err: Error) {
        self.complete.complete((Err(err), self.message))
    }
}


//------------ ServiceHandle -------------------------------------------------

/// A handle to a service.
pub struct ServiceHandle {
    tx: Sender<ServiceRequest>,
}

impl ServiceHandle {
    /// Creates a new handle from the sender side of a channel.
    pub fn from_sender(tx: Sender<ServiceRequest>) -> Self {
        ServiceHandle{tx: tx}
    }
}

impl Clone for ServiceHandle {
    fn clone(&self) -> Self {
        ServiceHandle{tx: self.tx.clone()}
    }
}


//------------ RequestReceiver -----------------------------------------------

/// A receiver for service requests.
pub type RequestReceiver = Receiver<ServiceRequest>;
