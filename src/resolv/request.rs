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

use std::cell::RefCell;
use std::io;
use std::mem;
use futures::{Async, Future, Complete, Oneshot, Poll, oneshot};
use tokio_core::channel::Sender;
use ::bits::{AsDName, ComposeMode, Message, MessageBuf, MessageBuilder,
             Question};
use ::iana::{Class, RRType};
use super::conf::ResolvOptions;
use super::error::Error;


//------------ QueryRequest --------------------------------------------------

/// Query side of a request.
///
/// This type is used by `Query` to dispatch and wait for requests. It is a
/// future resolving either into a `MessageBuf` of a successfully received
/// response or a `RequestError` upon failure.
pub struct QueryRequest(QueryRequestState);

enum QueryRequestState {
    Active {
        /// A reference to the request message.
        ///
        /// We’ll only ever touch the message after the oneshot has resolved.
        message: RefCell<MessageBuilder>,

        /// A future resolving into the request’s result.
        ///
        /// If this is `None`, the query should resolve into a timeout
        /// immediately. This happens if the service has gone.
        future: Option<Oneshot<Result<MessageBuf, Error>>>
    },
    Gone
}


impl QueryRequest {
    /// Starts a new request.
    ///
    /// This function starts a new request for the given name, record type,
    /// and class and sends it to `service`.
    pub fn start<N>(name: &N, rtype: RRType, class: Class,
                    service: &ServiceHandle, opts: &ResolvOptions)
                    -> Result<Self, Error>
                 where N: AsDName {
        Ok(Self::start_with_message(
                        try!(Self::build_message(name, rtype, class, opts)),
                        service))
    }

    /// Starts the request with a given message.
    fn start_with_message(message: MessageBuilder, service: &ServiceHandle)
                          -> Self {
        let (c, o) = oneshot();
        let message = RefCell::new(message);
        let sreq = ServiceRequest::new(message.clone(), c);
        let fut = service.tx.send(sreq).ok().map(|_| o);
        QueryRequest(QueryRequestState::Active{message: message, future: fut})
    }

    /// Builds the message for this request.
    fn build_message<N>(name: &N, rtype: RRType, class: Class,
                        opts: &ResolvOptions) -> Result<MessageBuilder, Error>
                     where N: AsDName {
        let mut res = try!(MessageBuilder::new(ComposeMode::Stream, true));
        res.header_mut().set_rd(opts.recurse);
        try!(Question::push(&mut res, name, rtype, class));
        Ok(res)
    }
}


//--- Future

impl Future for QueryRequest {
    type Item = MessageBuf;
    type Error = RequestError;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let err = match self.0 {
            QueryRequestState::Active{ref mut future, ..} => {
                match future {
                    &mut Some(ref mut future) => match future.poll() {
                        Ok(Async::NotReady) => return Ok(Async::NotReady),
                        Ok(Async::Ready(Ok(msg))) => {
                            return Ok(Async::Ready(msg))
                        }
                        Ok(Async::Ready(Err(err))) => err, 
                        Err(_) => Error::Timeout
                    },
                    &mut None => return Ok(Async::NotReady)
                }
            }
            QueryRequestState::Gone => {
                panic!("poll on resolved QueryRequest");
            }
        };
        match mem::replace(&mut self.0, QueryRequestState::Gone) {
            QueryRequestState::Active{message, ..} => {
                Err(RequestError::new(err, message.into_inner()))
            }
            QueryRequestState::Gone => panic!()
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
    message: RefCell<MessageBuilder>,

    /// The complete side of our oneshot to return a response.
    complete: Complete<Result<MessageBuf, Error>>,

    /// The message ID of the request message.
    ///
    /// This is initialized to 0. It may differ from what’s in the message
    /// if it has’t been updated yet.
    id: u16,
}


impl ServiceRequest {
    fn new(message: RefCell<MessageBuilder>,
           complete: Complete<Result<MessageBuf, Error>>) -> Self {
        ServiceRequest{message: message, complete: complete, id: 0}
    }

    pub fn id(&self) -> u16 {
        self.id
    }

    pub fn set_id(&mut self, id: u16) {
        self.id = id;
        self.message.borrow_mut().header_mut().set_id(id)
    }

    pub fn with_stream_bytes<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(self.message.borrow_mut().preview())
    }

    pub fn with_dgram_bytes<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        f(&self.message.borrow_mut().preview()[2..])
    }

    pub fn response(self, response: MessageBuf) {
        let is_answer = self.with_dgram_bytes(|buf| {
            let request = Message::from_bytes(buf).unwrap();
            response.is_answer(request)
        });
        if is_answer {
            self.complete.complete(Ok(response))
        }
        else {
            self.fail(io::Error::new(io::ErrorKind::Other, "server failure")
                                .into())
        }
    }
    
    pub fn fail(self, err: Error) {
        self.complete.complete(Err(err))
    }
}


//------------ RequestError --------------------------------------------------

/// An error has happened while processing a request.
///
/// Apart from a `Error` value indicating the actual error, the type
/// also transfers ownership of a request message back for reuse.
pub struct RequestError {
    error: Error,
    message: MessageBuilder
}


impl RequestError {
    /// Create a new request error from a query error and a message.
    pub fn new(error: Error, message: MessageBuilder) -> Self {
        RequestError{error: error, message: message}
    }

    /// Returns a reference to the query error.
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// Disolves the value into the contained message builder.
    pub fn into_message(self) -> MessageBuilder {
        self.message
    }

    pub fn restart(self, service: &ServiceHandle) -> QueryRequest {
        QueryRequest::start_with_message(self.message, service)
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
