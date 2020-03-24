//! The stub resolver.
//!
//! This module contains the type [`StubResolver`] that represents a resolver.
//! The type is also re-exported at crate level. You are encouraged to use
//! that definition.
//!
//! [`StubResolver`]: struct.StubResolver.html

use std::{io, ops};
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use bytes::Bytes;
use futures::future::FutureExt;
#[cfg(feature = "sync")] use tokio::runtime;
use domain::base::iana::Rcode;
use domain::base::message::Message;
use domain::base::message_builder::{
    AdditionalBuilder, MessageBuilder, StreamTarget
};
use domain::base::name::{ToDname, ToRelativeDname};
use domain::base::octets::Octets512;
use domain::base::question::Question;
use super::conf::{ResolvConf, ResolvOptions, SearchSuffix};
use super::net::{ServerInfo, ServerList, ServerListCounter};
use crate::lookup::addr::{lookup_addr, FoundAddrs};
use crate::lookup::host::{lookup_host, search_host, FoundHosts};
use crate::lookup::srv::{lookup_srv, FoundSrvs, SrvError};
use crate::resolver;
use crate::resolver::{Resolver, SearchNames};


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
pub struct StubResolver {
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
        StubResolver {
            preferred: ServerList::from_conf(&conf, |s| {
                s.transport.is_preferred()
            }),
            stream: ServerList::from_conf(&conf, |s| {
                s.transport.is_stream()
            }),
            options: conf.options
        }
    }

    pub fn options(&self) -> &ResolvOptions {
        &self.options
    }

    pub async fn query<N: ToDname, Q: Into<Question<N>>>(
        &self, question: Q
    ) -> Result<Answer, resolver::Error> {
        Query::new(self)?.run(
            Query::create_message(question.into())
        ).await
    }

    async fn query_message(
        &self, message: QueryMessage
    ) -> Result<Answer, resolver::Error> {
        Query::new(self)?.run(message).await
    }
}

impl StubResolver {
    pub async fn lookup_addr(
        &self, addr: IpAddr
    ) -> Result<FoundAddrs<&Self>, resolver::Error> {
        lookup_addr(&self, addr).await
    }

    pub async fn lookup_host(
        &self, qname: impl ToDname
    ) -> Result<FoundHosts<&Self>, resolver::Error> {
        lookup_host(&self, qname).await
    }

    pub async fn search_host(
        &self, qname: impl ToRelativeDname
    ) -> Result<FoundHosts<&Self>, resolver::Error> {
        search_host(&self, qname).await
    }

    pub async fn lookup_srv(
        &self,
        service: impl ToRelativeDname,
        name: impl ToDname,
        fallback_port: u16
    ) -> Result<Option<FoundSrvs>, SrvError> {
        lookup_srv(&self, service, name, fallback_port).await
    }
}

#[cfg(feature = "sync")]
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
    pub fn run<R, F>(op: F) -> R::Output
    where
        R: Future + Send + 'static,
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
    ) -> R::Output
    where
        R: Future + Send + 'static,
        F: FnOnce(StubResolver) -> R + Send + 'static,
    {
        let resolver = Self::from_conf(conf);
        let mut runtime = runtime::Builder::new()
            .basic_scheduler()
            .build().unwrap();
        runtime.block_on(op(resolver))
    }
}

impl Default for StubResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Resolver for &'a StubResolver {
    type Octets = Bytes;
    type Answer = Answer;
    type Query = Pin<Box<
        dyn Future<Output = Result<Answer, resolver::Error>> + 'a
    >>;

    fn query<N, Q>(&self, question: Q) -> Self::Query
    where N: ToDname, Q: Into<Question<N>> {
        let message = Query::create_message(question.into());
        self.query_message(message).boxed()
    }
}

impl<'a> SearchNames for &'a StubResolver {
    type Name = SearchSuffix;
    type Iter = SearchIter<'a>;

    fn search_iter(&self) -> Self::Iter {
        SearchIter {
            resolver: self.clone(),
            pos: 0
        }
    }
}


//------------ Query ---------------------------------------------------------

pub struct Query<'a> {
    /// The resolver whose configuration we are using.
    resolver: &'a StubResolver,

    /// Are we still in the preferred server list or have gone streaming?
    preferred: bool,

    /// The number of attempts, starting with zero.
    attempt: usize,

    /// The index in the server list we currently trying.
    counter: ServerListCounter,

    /// The preferred error to return.
    ///
    /// Every time we finish a single query, we see if we can update this with
    /// a better one. If we finally have to fail, we return this result. This
    /// is a result so we can return a servfail answer if that is the only
    /// answer we get. (Remember, SERVFAIL is returned for a bogus answer, so
    /// you might want to know.)
    error: resolver::Error,
}

impl<'a> Query<'a> {
    pub fn new(
        resolver: &'a StubResolver,
    ) -> Result<Self, resolver::Error> {
        let (preferred, counter) = if
            resolver.options().use_vc ||
            resolver.preferred.is_empty()
        {
            if resolver.stream.is_empty() {
                return Err(
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "no servers available"
                    ).into()
                )
            }
            (false, resolver.stream.counter(resolver.options().rotate))
        }
        else {
            (true, resolver.preferred.counter(resolver.options().rotate))
        };
        Ok(Query {
            resolver,
            preferred,
            attempt: 0,
            counter,
            error: io::Error::new(
                io::ErrorKind::TimedOut,
                "all timed out"
            ).into()
        })
    }

    pub async fn run(
        mut self,
        mut message: QueryMessage,
    ) -> Result<Answer, resolver::Error> {
        loop {
            match self.run_query(&mut message).await {
                Ok(answer) => {
                    if answer.header().rcode() == Rcode::FormErr
                        && self.current_server().does_edns()
                    {
                        // FORMERR with EDNS: turn off EDNS and try again.
                        self.current_server().disable_edns();
                        continue
                    }
                    else if answer.header().rcode() == Rcode::ServFail {
                        // SERVFAIL: go to next server.
                        self.update_error_servfail();
                    }
                    else if answer.header().tc() && self.preferred
                        && !self.resolver.options().ign_tc
                    {
                        // Truncated. If we can, switch to stream transports
                        // and try again. Otherwise return the truncated
                        // answer.
                        if self.switch_to_stream() {
                            continue
                        }
                        else {
                            return Ok(answer)
                        }
                    }
                    else {
                        // I guess we have an answer ...
                        return Ok(answer);
                    }
                }
                Err(err) => self.update_error(err),
            }
            if !self.next_server() {
                return Err(self.error)
            }
        }
    }

    fn create_message(
        question: Question<impl ToDname>
    ) -> QueryMessage {
        let mut message = MessageBuilder::from_target(
            StreamTarget::new(Octets512::new()).unwrap()
        ).unwrap();
        message.header_mut().set_rd(true);
        let mut message = message.question();
        message.push(question).unwrap();
        message.additional()
    }

    async fn run_query(
        &mut self, message: &mut QueryMessage
    ) -> Result<Answer, resolver::Error> {
        let server = self.current_server();
        server.prepare_message(message);
        server.query(message).await
    }

    fn current_server(&self) -> &ServerInfo {
        let list = if self.preferred { &self.resolver.preferred }
                   else { &self.resolver.stream };
        self.counter.info(list)
    }

    fn update_error(&mut self, err: resolver::Error) {
        // We keep the last error except for timeouts or if we have a servfail
        // answer already. Since we start with a timeout, we still get a that
        // if everything times out.
        if !err.is_timeout() {
            self.error = err
        }
    }

    fn update_error_servfail(&mut self) {
        self.error = resolver::Error::ServFail
    }

    fn switch_to_stream(&mut self) -> bool {
        if !self.preferred {
            // We already did this.
            return false
        }
        self.preferred = false;
        self.attempt = 0;
        self.counter = self.resolver.stream.counter(
            self.resolver.options().rotate
        );
        true
    }

    fn next_server(&mut self) -> bool {
        if self.counter.next() {
            return true
        }
        self.attempt += 1;
        if self.attempt >= self.resolver.options().attempts {
            return false
        }
        self.counter = if self.preferred {
            self.resolver.preferred.counter(self.resolver.options().rotate)
        }
        else {
            self.resolver.stream.counter(self.resolver.options().rotate)
        };
        true
    }
}


//------------ QueryMessage --------------------------------------------------

// XXX This needs to be re-evaluated if we start adding OPTtions to the query.
pub(super) type QueryMessage = AdditionalBuilder<StreamTarget<Octets512>>;


//------------ Answer --------------------------------------------------------

/// The answer to a question.
///
/// This type is a wrapper around the DNS [`Message`] containing the answer
/// that provides some additional information.
#[derive(Clone)]
pub struct Answer {
    message: Message<Bytes>,
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

    pub fn into_message(self) -> Message<Bytes> {
        self.message
    }
}

impl From<Message<Bytes>> for Answer {
    fn from(message: Message<Bytes>) -> Self {
        Answer { message }
    }
}

impl ops::Deref for Answer {
    type Target = Message<Bytes>;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl AsRef<Message<Bytes>> for Answer {
    fn as_ref(&self) -> &Message<Bytes> {
        &self.message
    }
}


//------------ SearchIter ----------------------------------------------------

#[derive(Clone, Debug)]
pub struct SearchIter<'a> {
    resolver: &'a StubResolver,
    pos: usize,
}

impl<'a> Iterator for SearchIter<'a> {
    type Item = SearchSuffix;

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

