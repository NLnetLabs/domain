//! The stub resolver.
//!
//! This module contains the type [`StubResolver`] that represents a resolver.
//! The type is also re-exported at crate level. You are encouraged to use
//! that definition.
//!
//! [`StubResolver`]: struct.StubResolver.html

use std::{io, ops};
use std::sync::Arc;
use domain_core::bits::{Dname, Message, Question, ToDname};
use domain_core::bits::query::{QueryBuilder, QueryMessage};
use domain_core::iana::Rcode;
use tokio::prelude::{Async, Future};
use tokio::prelude::future::lazy;
use tokio::runtime::Runtime;
use crate::resolver::{Resolver, SearchNames};
use super::conf::{ResolvConf, ResolvOptions};
use super::net::{ServerInfo, ServerList, ServerListCounter, ServerQuery};


//------------ StubResolver --------------------------------------------------

/// A DNS stub resolver.
///
/// This type collects all information making it possible to start DNS
/// queries. You can create a new resoler using the system’s configuration
/// using the [`new()`] associate function or using your own configuration
/// with [`from_conf()`].
///
/// Stub resolver values can be cloned relatively cheaply as they keep all
/// information behind an arc.
///
/// If you want to run a single query or lookup on a resolver synchronously,
/// you can do so simply by using the [`run()`] or [`run_with_conf()`]
/// associated functions.
///
/// [`new()`]: #method.new
/// [`from_conf()`]: #method.from_conf
/// [`query()`]: #method.query
/// [`run()`]: #method.run
/// [`run_with_conf()`]: #method.run_with_conf
#[derive(Clone, Debug)]
pub struct StubResolver(Arc<ResolverInner>);


#[derive(Debug)]
struct ResolverInner {
    /// Preferred servers.
    preferred: ServerList,

    /// Streaming servers.
    stream: ServerList,

    /// Resolver options.
    options: ResolvOptions,
}


impl StubResolver {
    /// Creates a new resolver using the system’s default configuration.
    pub fn new() -> Self {
        Self::from_conf(ResolvConf::default())
    }

    /// Creates a new resolver using the given configuraiton.
    pub fn from_conf(conf: ResolvConf) -> Self {
        StubResolver(Arc::new(ResolverInner::from_conf(conf)))
    }

    pub fn options(&self) -> &ResolvOptions {
        &self.0.options
    }
}

impl ResolverInner {
    fn from_conf(conf: ResolvConf) -> Self {
        ResolverInner {
            preferred: ServerList::from_conf(&conf, |s| {
                s.transport.is_preferred()
            }),
            stream: ServerList::from_conf(&conf, |s| {
                s.transport.is_stream()
            }),
            options: conf.options
        }
    }
}

impl StubResolver {
    /// Synchronously perform a DNS operation atop a standard resolver.
    ///
    /// This associated functions removes almost all boiler plate for the
    /// case that you want to perform some DNS operation, either a query or
    /// lookup, on a resolver using the system’s configuration and wait for
    /// the result.
    ///
    /// The only argument is a closure taking a reference to a `StubResolver`
    /// and returning a future. Whatever that future resolves to will be
    /// returned.
    pub fn run<R, F>(op: F) -> Result<R::Item, R::Error>
    where
        R: Future + Send + 'static,
        R::Item: Send + 'static,
        R::Error: Send + 'static,
        F: FnOnce(StubResolver) -> R + Send + 'static,
    {
        Self::run_with_conf(ResolvConf::default(), op)
    }

    /// Synchronously perform a DNS operation atop a configured resolver.
    ///
    /// This is like [`run()`] but also takes a resolver configuration for
    /// tailor-making your own resolver.
    ///
    /// [`run()`]: #method.run
    pub fn run_with_conf<R, F>(
        conf: ResolvConf,
        op: F
    ) -> Result<R::Item, R::Error>
    where
        R: Future + Send + 'static,
        R::Item: Send + 'static,
        R::Error: Send + 'static,
        F: FnOnce(StubResolver) -> R + Send + 'static,
    {
        let resolver = Self::from_conf(conf);
        let mut runtime = Runtime::new().unwrap(); // XXX unwrap
        let res = runtime.block_on(lazy(|| op(resolver)));
        runtime.shutdown_on_idle().wait().unwrap();
        res
    }
}

impl Resolver for StubResolver {
    type Answer = Answer;
    type Query = Query;

    fn query<N, Q>(&self, question: Q) -> Query
    where N: ToDname, Q: Into<Question<N>> {
        Query::new(self.clone(), question)
    }
}

impl SearchNames for StubResolver {
    type Iter = SearchIter;

    fn search_iter(&self) -> Self::Iter {
        SearchIter {
            resolver: self.clone(),
            pos: 0
        }
    }
}


//------------ Query ---------------------------------------------------------

#[derive(Debug)]
pub struct Query {
    /// The resolver whose configuration we are using.
    resolver: StubResolver,

    /// Are we still in the preferred server list or have gone streaming?
    preferred: bool,

    /// The number of attempts, starting with zero.
    attempt: usize,

    /// The index in the server list we currently trying.
    counter: ServerListCounter,

    /// The server query we are currently performing.
    ///
    /// If this is an error, we had to bail out before ever starting a query.
    query: Result<ServerQuery, Option<io::Error>>,

    /// The query message we currently work on.
    ///
    /// This is an option so we can take it out temporarily to manipulate it.
    message: Option<QueryMessage>,
}

impl Query {
    fn new<N, Q>(resolver: StubResolver, question: Q) -> Self
    where N: ToDname, Q: Into<Question<N>> {
        let mut message = QueryBuilder::new(question);
        message.set_rd(true);
        if resolver.options().use_dnssec {
            message.header_mut().set_ad(true);
            message.set_use_dnssec(true);
        }
        let message = message.freeze();
        let (preferred, counter) = if resolver.options().use_vc {
            (false, resolver.0.stream.counter(resolver.options().rotate))
        }
        else {
            (true, resolver.0.preferred.counter(resolver.options().rotate))
        };
        let mut res = Query {
            resolver,
            preferred,
            attempt: 0,
            counter,
            query: Err(None),
            message: Some(message)
        };
        res.query = match res.start_query() {
            Some(query) => Ok(query),
            None => Err(Some(no_servers_error()))
        };
        res
    }

    /// Starts a new query for the current server.
    ///
    /// Prepares the query message and then starts the server query. Returns
    /// `None` if a query cannot be started because there are no more servers
    /// left.
    fn start_query(&mut self) -> Option<ServerQuery> {
        let message = self.message.take().unwrap();
        let (message, res) = {
            match self.current_server() {
                Some(info) => {
                    let mut message = message.unfreeze();
                    info.prepare_message(&mut message);
                    let message = message.freeze();
                    let res = ServerQuery::new(message.clone(), info);
                    (message, Some(res))
                }
                None => (message, None)
            }
        };
        self.message = Some(message);
        res
    }

    /// Returns the info for the current server.
    fn current_server(&self) -> Option<&ServerInfo> {
        let list = if self.preferred { &self.resolver.0.preferred }
                   else { &self.resolver.0.stream };
        self.counter.info(list)
    }


    fn switch_to_stream(&mut self) -> bool {
        self.preferred = false;
        self.attempt = 0;
        self.counter = self.resolver.0.stream.counter(
            self.resolver.options().rotate
        );
        match self.start_query() {
            Some(query) => {
                self.query = Ok(query);
                true
            }
            None => {
                self.query = Err(None);
                false
            }
        }
    }

    fn next_server(&mut self) {
        self.counter.next();
        if let Some(query) = self.start_query() {
            self.query = Ok(query);
            return;
        }
        self.attempt += 1;
        if self.attempt >= self.resolver.options().attempts {
            self.query = Err(Some(giving_up_error()));
            return;
        }
        self.counter = if self.preferred {
            self.resolver.0.preferred.counter(self.resolver.options().rotate)
        }
        else {
            self.resolver.0.stream.counter(self.resolver.options().rotate)
        };
        self.query = match self.start_query() {
            Some(query) => Ok(query),
            None => Err(Some(giving_up_error()))
        }
    }
}

impl Future for Query {
    type Item = Answer;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        let answer = {
            let query = match self.query {
                Ok(ref mut query) => query,
                Err(ref mut err) => {
                    let err = err.take();
                    match err {
                        Some(err) => return Err(err),
                        None => panic!("polled a resolved future")
                    }
                }
            };
            match query.poll() {
                Ok(Async::NotReady) => return Ok(Async::NotReady),
                Ok(Async::Ready(answer)) => Some(answer),
                Err(_) => None,
            }
        };
        match answer {
            Some(answer) => {
                if answer.header().rcode() == Rcode::FormErr
                    && self.current_server().unwrap().does_edns()
                {
                    // FORMERR with EDNS: turn off EDNS and try again.
                    self.current_server().unwrap().disable_edns();
                    self.query = Ok(self.start_query().unwrap());
                }
                else if answer.header().rcode() == Rcode::ServFail {
                    // SERVFAIL: go to next server.
                    self.next_server();
                }
                else if answer.header().tc() && self.preferred
                    && !self.resolver.options().ign_tc
                {
                    // Truncated. If we can, switch to stream transports.
                    if !self.switch_to_stream() {
                        return Ok(Async::Ready(answer))
                    }
                }
                else {
                    // I guess we have an answer ...
                    self.query = Err(None); // Make it panic if polled again.
                    return Ok(Async::Ready(answer));
                }
            }
            None => {
                self.next_server();
            }
        }
        self.poll()
    }
}


//------------ Answer --------------------------------------------------------

/// The answer to a question.
///
/// This type is a wrapper around the DNS [`Message`] containing the answer
/// that provides some additional information.
#[derive(Clone, Debug)]
pub struct Answer {
    message: Message,
}

impl Answer {
    /// Returns whether the answer is a final answer to be returned.
    pub fn is_final(&self) -> bool {
        (self.message.header().rcode() == Rcode::NoError
            || self.message.header().rcode() == Rcode::NXDomain)
        && !self.message.header().tc()
    }

    /// Returns whether the answer is truncated.
    pub fn is_truncated(&self) -> bool {
        self.message.header().tc()
    }

    pub fn into_message(self) -> Message {
        self.message
    }
}

impl From<Message> for Answer {
    fn from(message: Message) -> Self {
        Answer { message }
    }
}

impl ops::Deref for Answer {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl AsRef<Message> for Answer {
    fn as_ref(&self) -> &Message {
        &self.message
    }
}


//------------ SearchIter ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SearchIter {
    resolver: StubResolver,
    pos: usize,
}

impl Iterator for SearchIter {
    type Item = Dname;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(res) = self.resolver.options().search.get(self.pos) {
            self.pos += 1;
            Some(res.clone())
        }
        else {
            None
        }
    }
}


//------------ Making Errors -------------------------------------------------
//
// Because we want to use io::Error and creating them is tedious, we have some
// friendly helpers for that.

fn no_servers_error() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no servers available")
}

fn giving_up_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "timed out")
}

