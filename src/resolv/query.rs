//! A DNS query.

use futures::{Async, Future, Poll};
use futures::task::TaskRc;
use rand::random;
use ::bits::{AsDName, ComposeMode, ComposeResult, MessageBuilder,
             MessageBuf, Question};
use ::iana::{Class, RRType};
use super::ResolverTask;
use super::conf::ResolvOptions;
use super::core::Core;
use super::error::Error;
use super::request::QueryRequest;


//------------ Query ---------------------------------------------------------

/// A DNS query.
///
/// A query is a future that resolves a DNS question for all the resource
/// records for a given domain name, record type, and class into either a
/// response or a query error. It will follow the rules set down by the
/// resolver configuration in trying to find an upstream server that
/// replies to the question.
///
/// A query is actually a combinator of sorts. It needs a [`ResolverTask`]
/// to operate on which in itself is the result of a future, namely that
/// returned by [`Resolver::start()`]. As such, you cannot use a query by
/// itself. Please see the module level documentation for some examples on
/// how to start a query.
//
//  Since a query can fail very early on when building the request message,
//  it internally consists of a `Result`. If it is `Ok()`, we really do have
//  a query to poll, otherwise we have an error to take out and return.
pub struct Query(Result<RealQuery, Option<Error>>);


impl Query {
    /// Creates a new query.
    pub fn new<N: AsDName>(resolv: &ResolverTask, name: N, rtype: RRType,
                       class: Class) -> Self {
        let core = resolv.core.clone();
        let message = core.with(|core| {
            Self::build_message(name, rtype, class, core.options())
        });
        let message = match message {
            Ok(message) => message,
            Err(err) => return Query(Err(Some(err.into())))
        };
        let dgram = core.with(|core| !core.conf().options.use_vc);
        let (index, request) = core.with(|c| RealQuery::start(c, dgram,
                                                              message));
        Query(Ok(RealQuery {
            core: core, request: request,
            dgram: dgram, start_index: index, curr_index: index,
            attempt: 0
        }))
    }

    /// Builds the message for this query.
    ///
    /// If this function fails, we are done.
    fn build_message<N: AsDName>(name: N, rtype: RRType, class: Class,
                                 opts: &ResolvOptions)
                                 -> ComposeResult<MessageBuilder> {
        let mut res = try!(MessageBuilder::new(ComposeMode::Stream, true));
        res.header_mut().set_rd(opts.recurse);
        try!(Question::push(&mut res, &name, rtype, class));
        Ok(res)
    }
}


//--- Future

impl Future for Query {
    type Item = MessageBuf;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0 {
            Ok(ref mut query) => query.poll(),
            Err(ref mut err) => {
                match err.take() {
                    Some(err) => Err(err),
                    None => panic!("polling a resolved Query")
                }
            }
        }
    }
}


//------------ RealQuery -----------------------------------------------------

/// An ongoing query.
struct RealQuery {
    /// The resolver core we are working on.
    core: TaskRc<Core>,

    /// The request we are currently processing.
    request: QueryRequest,

    /// Are we on datagram track?
    ///
    /// A query can be in one of two *tracks,* datagram track or stream
    /// track. Unless the config states that we should use the stream
    /// track only, we will start out in datagram track and only switch to
    /// the stream track if we receive a truncated response.
    dgram: bool,

    /// The index of the service we started at.
    ///
    /// The index references either `core.udp` or `core.tcp`, depending on
    /// the value of `dgram`. We need to keep the index we started at
    /// because of the rotate option which makes us start at a random
    /// service.
    start_index: usize,

    /// The index of the service we currently are using.
    curr_index: usize,

    /// The how-many-th attempt this is, starting at attempt 0.
    attempt: usize
}


impl RealQuery {
    /// Starts a new query.
    ///
    /// Takes a reference to the core, whether to use the datagram track,
    /// and the message and returns the index of the service used and a
    /// new request.
    fn start(core: &Core, dgram: bool, message: MessageBuilder)
             -> (usize, QueryRequest) {
        let track = if dgram { core.udp() }
                    else { core.tcp() };
        let index = if core.conf().options.rotate {
            random::<usize>() % track.len()
        }
        else { 0 };
        let request = QueryRequest::new(message, &track[index]);
        (index, request)
    }

    /// Processes a response.
    ///
    /// This will either resolve the future or switch to stream mode.
    fn response(&mut self, response: MessageBuf, message: MessageBuilder)
                -> Poll<MessageBuf, Error> {
        if response.header().tc() && self.dgram
                && !self.core.with(|core| core.options().ign_tc)
        {
            self.start_stream(message)
        }
        else { Ok(response.into()) }
    }

    /// Proceeds to the next request or errors out.
    fn next_request(&mut self, message: MessageBuilder)
                    -> Poll<MessageBuf, Error> {
        self.curr_index += 1;
        if (self.curr_index % self.track_len()) == self.start_index {
            self.attempt += 1;
            if self.attempt == self.core.with(|core| core.conf().attempts) {
                return Err(Error::Timeout)
            }
            let dgram = self.dgram;
            let (index, request) = self.core.with(|core| {
                Self::start(core, dgram, message)
            });
            self.start_index = index;
            self.curr_index = index;
            self.request = request;
        }
        else {
            let dgram = self.dgram;
            let curr_index = self.curr_index;
            self.request = self.core.with(|core| {
                let track = if dgram { core.udp() }
                            else { core.tcp() };
                QueryRequest::new(message, &track[curr_index])
            });
        }
        self.poll()
    }

    /// Switches to stream mode and starts the first request or errors out.
    fn start_stream(&mut self, message: MessageBuilder)
                    -> Poll<MessageBuf, Error> {
        self.dgram = false;
        let (index, request) = self.core.with(|core| {
            Self::start(core, false, message)
        });
        self.start_index = index;
        self.curr_index = index;
        self.request = request;
        self.poll()
    }

    /// Returns the number of services in the current track.
    fn track_len(&self) -> usize {
        if self.dgram { self.core.with(|core| core.udp().len()) }
        else { self.core.with(|core| core.tcp().len()) }
    }
}


//--- Future

impl Future for RealQuery {
    type Item = MessageBuf;
    type Error = Error;

    /// Polls for completion.
    ///
    /// Polls the current request. If that succeeded, returns the result. If
    /// it failed fatally, returns an error. If it failed non-fatally,
    /// proceeds to the next request.
    fn poll(&mut self) -> Poll<MessageBuf, Error> {
        match self.request.poll() {
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Ok(Async::Ready((Ok(response), message))) => {
                self.response(response, message)
            }
            Ok(Async::Ready((Err(_), message))) => {
                self.next_request(message)
            }
            Err(err) => Err(err.into())
        }
    }
}

