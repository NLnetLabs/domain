//! The two public types `Resolver` and `Query`.
//!
//! These two are here together because `Query` needs to be able to access 
//! `Resolver`’s transport handles yet I don’t want to expose them publicly.

use std::io;
use std::sync::Arc;
use futures::{Async, Future, Poll};
use rand::random;
use tokio_core::reactor;
use ::bits::{DName, MessageBuf, Question};
use ::iana::Rcode;
use super::conf::{ResolvConf, ResolvOptions};
use super::error::Error;
use super::request::{QueryRequest, RequestMessage, TransportHandle};
use super::tcp::tcp_transport;
use super::udp::udp_transport;


//------------ Resolver ------------------------------------------------------

/// Access to a DNS resolver.
///
/// This type collects all information making it possible to start DNS
/// queries. You can create a new resoler using the system’s configuration
/// using the [`new()`] associate function or using your own configuration
/// with [`from_conf()`]. Either function will spawn everything necessary
/// into a `tokio_core` reactor core represented by a handle.
///
/// Resolver values can be cloned relatively cheaply as they keep all
/// information behind an arc. This is may already be useful when starting
/// a query using the [`query()`] method. Since queries need their own copy
/// of resolver, the method consumes the resolver leaving it to clone it if
/// you need it later on or saving a clone if you don’t.
///
/// If you want to run a single query or lookup on a resolver synchronously,
/// you can safe yourself all the boiler plate of creating a reactor core
/// (even if this is nowhere near as dangerous as it sounds) and resolver by
/// using the [`run()`] or [`run_with_conf()`] associated functions.
///
/// [`new()`]: #method.new
/// [`from_conf()`]: #method.from_conf
/// [`query()`]: #method.query
/// [`run()`]: #method.run
/// [`run_with_conf()`]: #method.run_with_conf
#[derive(Clone, Debug)]
pub struct Resolver(Arc<ResolverInner>);

/// The actual resolver.
#[derive(Clone, Debug)]
struct ResolverInner {
    /// Handles to all UDP transports.
    udp: Vec<TransportHandle>,

    /// Handles to all TCP transports.
    tcp: Vec<TransportHandle>,

    /// Our resolver configuration.
    conf: ResolvConf,
}

impl Resolver {
    /// Creates a new resolver using the system’s default configuration.
    ///
    /// All the networking components of the resolver will be spawned into
    /// the reactor core referenced by `reactor`.
    pub fn new(reactor: &reactor::Handle) -> Self {
        Self::from_conf(reactor, ResolvConf::default())
    }

    /// Creates a new resolver using the given configuration.
    ///
    /// All the components of the resolver will be spawned into the reactor
    /// referenced by `reactor`.
    pub fn from_conf(reactor: &reactor::Handle, conf: ResolvConf)
                     -> Self {
        let mut udp = Vec::new();
        let mut tcp = Vec::new();

        for server in &conf.servers {
            if let Some(transport) = udp_transport(reactor, server) {
                udp.push(transport)
            }
            if let Some(transport) = tcp_transport(reactor, server) {
                tcp.push(transport)
            }
        }

        Resolver(Arc::new(ResolverInner {
            udp: udp,
            tcp: tcp,
            conf: conf
        }))
    }

    /// Trades the resolver for a DNS query.
    ///
    /// This starts a query for something that can be turned into a question.
    /// In particular, both a tripel of a domain name, record type, and class
    /// as well as a pair of domain name and record type can be turned into
    /// a question, the latter assuming the class IN.
    ///
    /// If you need to keep the resolver, clone it before calling `query()`.
    pub fn query<N, Q>(self, question: Q) -> Query
                 where N: DName, Q: Into<Question<N>> {
        Query::new(self, question)
    }

    /// Returns a reference to the list of UDP service handles.
    fn udp(&self) -> &[TransportHandle] {
        &self.0.udp
    }

    /// Returns a reference to the list of TCP service handles.
    fn tcp(&self) -> &[TransportHandle] {
        &self.0.tcp
    }

    /// Returns a reference to the configuration of this resolver.
    pub fn conf(&self) -> &ResolvConf {
        &self.0.conf
    }

    /// Returns a reference to the configuration options of this resolver.
    pub fn options(&self) -> &ResolvOptions {
        &self.0.conf.options
    }
}

/// # Shortcuts
///
impl Resolver {
    /// Synchronously perform a DNS operation atop a standard resolver.
    ///
    /// This associated functions removes almost all boiler plate for the
    /// case that you want to perform some DNS operation, either a query or
    /// lookup, on a resolver using the system’s configuration and wait for
    /// the result.
    ///
    /// The only argument is a closure taking a `Resolver` and returning a
    /// future. Whatever that future resolves to will be returned.
    pub fn run<R, F>(op: F) -> Result<R::Item, R::Error>
               where R: Future,
                     R::Error: From<io::Error>,
                     F: FnOnce(Resolver) -> R {
        Self::run_with_conf(ResolvConf::default(), op)
    }

    /// Synchronously perform a DNS operation atop a configuredresolver.
    ///
    /// This is like [`run()`] but also takes a resolver configuration for
    /// tailor-making your own resolver.
    ///
    /// [`run()`]: #method.run
    pub fn run_with_conf<R, F>(conf: ResolvConf, op: F)
                               -> Result<R::Item, R::Error>
                         where R: Future,
                               R::Error: From<io::Error>,
                               F: FnOnce(Resolver) -> R {
        let mut reactor = reactor::Core::new()?;
        let resolver = Self::from_conf(&reactor.handle(), conf);
        reactor.run(op(resolver))
    }
}


//------------ Query ---------------------------------------------------------

/// A DNS query.
///
/// A query is a future that resolves a DNS question for all the resource
/// records for a given domain name, record type, and class into either a
/// successful response or query error. It will follow the rules set down
/// by the resolver configuration in trying to find an upstream server that
/// replies to the question.
///
/// While you can start a query directly by calling the `Query::new()`
/// function, the resolver’s `query()` method may be more convenient.
//
//  Since a query can fail very early on when building the request message,
//  but we don’t really want to complicate things by `Query::new()` returning
//  a result, it internally consists of that `Result`. If it is `Ok()`, we
//  really do have a query to poll, otherwise we have an error to take out
//  and return.
//
//  This is okay because the early failure should be rather unlikely.
pub struct Query(Result<QueryInner, Option<Error>>);

impl Query {
    /// Starts a new query.
    pub fn new<N, Q>(resolv: Resolver, question: Q) -> Self
               where N: DName, Q: Into<Question<N>> {
        let message = match RequestMessage::new(question, resolv.conf()) {
            Ok(message) => message,
            Err(err) => return Query(Err(Some(err.into())))
        };
        Query(Ok(QueryInner::new(resolv, message)))
    }
}


//--- Future

impl Future for Query {
    type Item = MessageBuf;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0 {
            Ok(ref mut inner) => inner.poll(),
            Err(ref mut err) => {
                match err.take() {
                    Some(err) => Err(err),
                    None => panic!("polling a resolved Query")
                }
            }
        }
    }
}


//------------ QueryInner ----------------------------------------------------

struct QueryInner {
    /// The resolver we are working with.
    resolver: Resolver,

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
    /// The index references either `resolver.udp` or `resolver.tcp`,
    /// depending on the value of `dgram`. We need to keep the index we
    /// started at because of the rotate option which makes us start at a
    /// random service.
    start_index: usize,

    /// The index of the service we currently are using.
    curr_index: usize,

    /// The how-many-th attempt this is, starting at attempt 0.
    attempt: usize,
}


impl QueryInner {
    fn new(resolver: Resolver, message: RequestMessage) -> Self {
        let dgram = !resolver.options().use_vc;
        let (index, request) = Self::start(&resolver, dgram, message);
        QueryInner {
            resolver: resolver,
            request: request,
            dgram: dgram,
            start_index: index,
            curr_index: index,
            attempt: 0
        }
    }

    /// Processes a response received from a request.
    ///
    /// This will either resolve the future or switch to stream mode and
    /// continue.
    fn response(&mut self, response: MessageBuf, message: RequestMessage)
                -> Poll<MessageBuf, Error> {
        if response.header().tc() && self.dgram
                && !self.resolver.options().ign_tc {
            self.start_stream(message)
        }
        else if response.header().rcode() != Rcode::NoError {
            Err(response.header().rcode().into())
        }
        else {
            Ok(Async::Ready(response))
        }
    }

    /// Processes an error received from a request.
    ///
    /// Proceeds to the next request or errors out.
    fn error(&mut self, _error: Error, message: RequestMessage)
             -> Poll<MessageBuf, Error> {
        self.curr_index = (self.curr_index + 1) % self.track().len();
        if self.curr_index == self.start_index {
            self.attempt += 1;
            if self.attempt == self.resolver.conf().attempts {
                return Err(Error::Timeout)
            }
            let (index, request) = Self::start(&self.resolver,
                                               self.dgram, message);
            self.start_index = index;
            self.curr_index = index;
            self.request = request;
        }
        else {
            self.request = QueryRequest::new(message,
                                             &self.track()[self.curr_index]);
        }
        self.poll()
    }

    /// Switches to stream mode and starts the first request.
    fn start_stream(&mut self, message: RequestMessage)
                    -> Poll<MessageBuf, Error> {
        self.dgram = false;
        let (index, request) = Self::start(&self.resolver, false,
                                           message);
        self.start_index = index;
        self.curr_index = index;
        self.request = request;
        self.poll()
    }

    /// Determines the start index and request for a new attempt.
    fn start(resolver: &Resolver, dgram: bool, message: RequestMessage)
             -> (usize, QueryRequest) {
        let track = if dgram { resolver.udp() }
                    else { resolver.tcp() };
        let index = if resolver.options().rotate {
            random::<usize>() % track.len()
        }
        else { 0 };
        let request = QueryRequest::new(message, &track[index]);
        (index, request)
    }

    /// Returns the current track.
    ///
    /// This is either the UDP or TCP service handles of the resolver,
    /// depending on whether we are in datagram or stream mode.
    fn track(&self) -> &[TransportHandle] {
        if self.dgram {
            self.resolver.udp()
        }
        else {
            self.resolver.tcp()
        }
    }
}


//--- Future

impl Future for QueryInner {
    type Item = MessageBuf;
    type Error = Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.request.poll() {
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Ok(Async::Ready((response, message))) => {
                self.response(response, message)
            }
            Err((error, message)) => {
                self.error(error, message)
            }
        }
    }
}

