//! A DNS request.

use std::sync::Arc;
use futures::Complete;
use ::bits::{DNameBuf, MessageBuf, MessageBuilder};
use ::iana::{Class, RRType};
use super::error::{Error, Result};


//------------ Question ------------------------------------------------------

/// The content of the query.
#[derive(Debug)]
pub struct Question {
    pub name: DNameBuf,
    pub rtype: RRType,
    pub class: Class
}


//------------ Request ------------------------------------------------------

/// A DNS request is one step in trying to resolv the query.
///
/// A collects a question and the complete side of a oneshot to drop of an
/// answer.
///
/// Currently, the question is an owned question inside an arc to avoid
/// copying when running queries or requests in parallel. The result is that
/// each service has to create its own message from scratch. While that is
/// simpler given that datagram and stream services use slightly different
/// messages to begin with and that, once we start implementing EDNS each
/// service will have to add its own OPT record, there is quite a bit of
/// potential for optimization by keeping a pre-assembled message here that
/// is being reused when requests are run in sequence.
///
/// So, this is likely to change quite a bit once we have gathered a little
/// more experience.
pub struct Request {
    /// The question.
    query: Arc<Question>,

    /// The complete side of a oneshot for the result.
    ///
    /// Upon success, it should complete with the response. Upon failure,
    /// it should complete with a request error.
    complete: Complete<Result<MessageBuf>>
}

impl Request {
    /// Creates a new request from its components.
    pub fn new(query: Arc<Question>,
               complete: Complete<Result<MessageBuf>>) -> Self {
        Request{query: query, complete: complete}
    }

    /// Returns a reference to the question.
    pub fn query(&self) -> &Question {
        &self.query
    }

    /// Succeeds the request with `response`.
    pub fn succeed(self, response: MessageBuf) {
        self.complete.complete(Ok(response))
    }
    
    /// Fails the request with `error`.
    pub fn fail(self, error: Error) {
        self.complete.complete(Err(error))
    }
}


//------------ RequestMessage ------------------------------------------------

#[derive(Clone, Debug)]
pub struct RequestMessage {
    original: MessageBuilder,
}
