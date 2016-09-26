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
//! returning the request message as part of their error response. See the
//! `RequestError` type for that.

use std::io;
use futures::{Future, Complete, Oneshot, Poll, oneshot};
use tokio_core::channel::{Receiver, Sender};
use ::bits::{Message, MessageBuf, MessageBuilder};
use super::error::{Error};


//------------ QueryRequest --------------------------------------------------

/// Query side of a request.
///
/// This type is used by `Query` to dispatch and wait for requests. It is a
/// future resolving either into a `MessageBuf` of a successfully received
/// response or a `RequestError` upon failure.
pub struct QueryRequest(Result<Oneshot<(Result<MessageBuf, Error>,
                                        MessageBuilder)>,
                               Option<io::Error>>);


impl QueryRequest {
    /// Starts the request with a given message.
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
/// support EDNS, the type will gain methods for adding an OPT record to the
/// message, too.
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
    ///
    /// This is initialized to 0. It may differ from what’s in the message
    /// if it has’t been updated yet.
    id: u16,
}


impl ServiceRequest {
    fn new(message: MessageBuilder,
           complete: Complete<(Result<MessageBuf, Error>, MessageBuilder)>)
           -> Self {
        ServiceRequest{message: message, complete: complete, id: 0}
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id;
        self.message.header_mut().set_id(id)
    }

    pub fn dgram_bytes(&mut self) -> &[u8] {
        &self.message.preview()[2..]
    }

    pub fn stream_bytes(&mut self) -> &[u8] {
        self.message.preview()
    }

    pub fn response(mut self, response: MessageBuf) {
        let is_answer = {
            let request = Message::from_bytes(self.dgram_bytes()).unwrap();
            response.is_answer(&request)
        };
        if is_answer {
            self.complete.complete((Ok(response), self.message))
        }
        else {
            self.fail(io::Error::new(io::ErrorKind::Other, "server failure")
                                .into())
        }
    }
    
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

pub type RequestReceiver = Receiver<ServiceRequest>;
