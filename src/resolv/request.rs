//! A DNS request.

use std::sync::Arc;
use futures::Complete;
use ::bits::{DNameBuf, MessageBuf};
use ::iana::{Class, RRType};

/// The content of the query.
#[derive(Debug)]
pub struct Question {
    pub name: DNameBuf,
    pub rtype: RRType,
    pub class: Class
}

/// A DNS request is one step in trying to resolv the query.
///
pub struct Request {
    query: Arc<Question>,

    /// The complete side of a oneshot for the result.
    ///
    /// Upon success, it should complete with the response. Upon failure,
    /// it should complete with a request error.
    complete: Complete<Result<MessageBuf, RequestError>>
}

impl Request {
    pub fn new(query: Arc<Question>,
               complete: Complete<Result<MessageBuf, RequestError>>) -> Self {
        Request{query: query, complete: complete}
    }

    pub fn query(&self) -> &Question {
        &self.query
    }

    pub fn succeed(self, response: MessageBuf) {
        self.complete.complete(Ok(response))
    }
    
    pub fn fail(self, error: RequestError) {
        self.complete.complete(Err(error))
    }
}

#[derive(Debug)]
pub enum RequestError {
    Global,
    Local,
    Timeout,
    NeedsStream,
}

impl RequestError {
    pub fn is_fatal(&self) -> bool {
        match *self {
            RequestError::Global | RequestError::NeedsStream => true,
            _ => false
        }
    }
}
