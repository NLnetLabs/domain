//! A stub resolver.
//!
//! The most simple resolver possible simply relays all messages to one of a
//! set of pre-configured resolvers that will do the actual work. This is
//! equivalent to what the resolver part of the C library does. This module
//! provides such a stub resolver that emulates this C resolver as closely
//! as possible, in particular in the way it is being configured.
//!
//! The main type is [`StubResolver`] that implements the [`Resolver`] trait
//! and thus can be used with the various lookup functions.

use self::conf::{
    ResolvConf, ResolvOptions, SearchSuffix, ServerConf, Transport,
};
use crate::base::iana::Rcode;
use crate::base::message::Message;
use crate::base::message_builder::{
    AdditionalBuilder, MessageBuilder, StreamTarget,
};
use crate::base::name::{ToDname, ToRelativeDname};
use crate::base::octets::Octets512;
use crate::base::question::Question;
use crate::resolv::lookup::addr::{lookup_addr, FoundAddrs};
use crate::resolv::lookup::host::{lookup_host, search_host, FoundHosts};
use crate::resolv::lookup::srv::{lookup_srv, FoundSrvs, SrvError};
use crate::resolv::resolver::{Resolver, SearchNames};
use bytes::Bytes;
use std::boxed::Box;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::vec::Vec;
use std::{io, ops};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
#[cfg(feature = "resolv-sync")]
use tokio::runtime;
use tokio::time::timeout;

//------------ Sub-modules ---------------------------------------------------

pub mod conf;

//------------ Module Configuration ------------------------------------------

/// How many times do we try a new random port if we get ‘address in use.’
const RETRY_RANDOM_PORT: usize = 10;

//------------ StubResolver --------------------------------------------------

/// A DNS stub resolver.
///
/// This type collects all information making it possible to start DNS
/// queries. You can create a new resolver using the system’s configuration
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
            stream: ServerList::from_conf(&conf, |s| s.transport.is_stream()),
            options: conf.options,
        }
    }

    pub fn options(&self) -> &ResolvOptions {
        &self.options
    }

    pub async fn query<N: ToDname, Q: Into<Question<N>>>(
        &self,
        question: Q,
    ) -> Result<Answer, io::Error> {
        Query::new(self)?
            .run(Query::create_message(question.into()))
            .await
    }

    async fn query_message(
        &self,
        message: QueryMessage,
    ) -> Result<Answer, io::Error> {
        Query::new(self)?.run(message).await
    }
}

impl StubResolver {
    pub async fn lookup_addr(
        &self,
        addr: IpAddr,
    ) -> Result<FoundAddrs<&Self>, io::Error> {
        lookup_addr(&self, addr).await
    }

    pub async fn lookup_host(
        &self,
        qname: impl ToDname,
    ) -> Result<FoundHosts<&Self>, io::Error> {
        lookup_host(&self, qname).await
    }

    pub async fn search_host(
        &self,
        qname: impl ToRelativeDname,
    ) -> Result<FoundHosts<&Self>, io::Error> {
        search_host(&self, qname).await
    }

    pub async fn lookup_srv(
        &self,
        service: impl ToRelativeDname,
        name: impl ToDname,
        fallback_port: u16,
    ) -> Result<Option<FoundSrvs>, SrvError> {
        lookup_srv(&self, service, name, fallback_port).await
    }
}

#[cfg(feature = "resolv-sync")]
#[cfg_attr(docsrs, doc(cfg(feature = "resolv-sync")))]
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
        R::Output: Send + 'static,
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
    pub fn run_with_conf<R, F>(conf: ResolvConf, op: F) -> R::Output
    where
        R: Future + Send + 'static,
        R::Output: Send + 'static,
        F: FnOnce(StubResolver) -> R + Send + 'static,
    {
        let resolver = Self::from_conf(conf);
        let runtime = runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
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
    type Query =
        Pin<Box<dyn Future<Output = Result<Answer, io::Error>> + Send + 'a>>;

    fn query<N, Q>(&self, question: Q) -> Self::Query
    where
        N: ToDname,
        Q: Into<Question<N>>,
    {
        let message = Query::create_message(question.into());
        Box::pin(self.query_message(message))
    }
}

impl<'a> SearchNames for &'a StubResolver {
    type Name = SearchSuffix;
    type Iter = SearchIter<'a>;

    fn search_iter(&self) -> Self::Iter {
        SearchIter {
            resolver: self,
            pos: 0,
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
    error: Result<Answer, io::Error>,
}

impl<'a> Query<'a> {
    pub fn new(resolver: &'a StubResolver) -> Result<Self, io::Error> {
        let (preferred, counter) =
            if resolver.options().use_vc || resolver.preferred.is_empty() {
                if resolver.stream.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "no servers available",
                    ));
                }
                (false, resolver.stream.counter(resolver.options().rotate))
            } else {
                (true, resolver.preferred.counter(resolver.options().rotate))
            };
        Ok(Query {
            resolver,
            preferred,
            attempt: 0,
            counter,
            error: Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "all timed out",
            )),
        })
    }

    pub async fn run(
        mut self,
        mut message: QueryMessage,
    ) -> Result<Answer, io::Error> {
        loop {
            match self.run_query(&mut message).await {
                Ok(answer) => {
                    if answer.header().rcode() == Rcode::FormErr
                        && self.current_server().does_edns()
                    {
                        // FORMERR with EDNS: turn off EDNS and try again.
                        self.current_server().disable_edns();
                        continue;
                    } else if answer.header().rcode() == Rcode::ServFail {
                        // SERVFAIL: go to next server.
                        self.update_error_servfail(answer);
                    } else if answer.header().tc()
                        && self.preferred
                        && !self.resolver.options().ign_tc
                    {
                        // Truncated. If we can, switch to stream transports
                        // and try again. Otherwise return the truncated
                        // answer.
                        if self.switch_to_stream() {
                            continue;
                        } else {
                            return Ok(answer);
                        }
                    } else {
                        // I guess we have an answer ...
                        return Ok(answer);
                    }
                }
                Err(err) => self.update_error(err),
            }
            if !self.next_server() {
                return self.error;
            }
        }
    }

    fn create_message(question: Question<impl ToDname>) -> QueryMessage {
        let mut message = MessageBuilder::from_target(
            StreamTarget::new(Octets512::new()).unwrap(),
        )
        .unwrap();
        message.header_mut().set_rd(true);
        let mut message = message.question();
        message.push(question).unwrap();
        message.additional()
    }

    async fn run_query(
        &mut self,
        message: &mut QueryMessage,
    ) -> Result<Answer, io::Error> {
        let server = self.current_server();
        server.prepare_message(message);
        server.query(message).await
    }

    fn current_server(&self) -> &ServerInfo {
        let list = if self.preferred {
            &self.resolver.preferred
        } else {
            &self.resolver.stream
        };
        self.counter.info(list)
    }

    fn update_error(&mut self, err: io::Error) {
        // We keep the last error except for timeouts or if we have a servfail
        // answer already. Since we start with a timeout, we still get a that
        // if everything times out.
        if err.kind() != io::ErrorKind::TimedOut && self.error.is_err() {
            self.error = Err(err)
        }
    }

    fn update_error_servfail(&mut self, answer: Answer) {
        self.error = Ok(answer)
    }

    fn switch_to_stream(&mut self) -> bool {
        if !self.preferred {
            // We already did this.
            return false;
        }
        self.preferred = false;
        self.attempt = 0;
        self.counter =
            self.resolver.stream.counter(self.resolver.options().rotate);
        true
    }

    fn next_server(&mut self) -> bool {
        if self.counter.next() {
            return true;
        }
        self.attempt += 1;
        if self.attempt >= self.resolver.options().attempts {
            return false;
        }
        self.counter = if self.preferred {
            self.resolver
                .preferred
                .counter(self.resolver.options().rotate)
        } else {
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

//------------ ServerInfo ----------------------------------------------------

#[derive(Clone, Debug)]
struct ServerInfo {
    /// The basic server configuration.
    conf: ServerConf,

    /// Whether this server supports EDNS.
    ///
    /// We start out with assuming it does and unset it if we get a FORMERR.
    edns: Arc<AtomicBool>,
}

impl ServerInfo {
    pub fn does_edns(&self) -> bool {
        self.edns.load(Ordering::Relaxed)
    }

    pub fn disable_edns(&self) {
        self.edns.store(false, Ordering::Relaxed);
    }

    pub fn prepare_message(&self, query: &mut QueryMessage) {
        query.rewind();
        if self.does_edns() {
            query
                .opt(|opt| {
                    opt.set_udp_payload_size(self.conf.udp_payload_size);
                    Ok(())
                })
                .unwrap();
        }
    }

    pub async fn query(
        &self,
        query: &QueryMessage,
    ) -> Result<Answer, io::Error> {
        let res = match self.conf.transport {
            Transport::Udp => {
                timeout(
                    self.conf.request_timeout,
                    Self::udp_query(
                        query,
                        self.conf.addr,
                        self.conf.recv_size,
                    ),
                )
                .await
            }
            Transport::Tcp => {
                timeout(
                    self.conf.request_timeout,
                    Self::tcp_query(query, self.conf.addr),
                )
                .await
            }
        };
        match res {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "request timed out",
            )),
        }
    }

    pub async fn tcp_query(
        query: &QueryMessage,
        addr: SocketAddr,
    ) -> Result<Answer, io::Error> {
        let mut sock = TcpStream::connect(&addr).await?;
        sock.write_all(query.as_target().as_stream_slice()).await?;

        // This loop can be infinite because we have a timeout on this whole
        // thing, anyway.
        loop {
            let mut buf = Vec::new();
            let len = sock.read_u16().await? as u64;
            AsyncReadExt::take(&mut sock, len)
                .read_to_end(&mut buf)
                .await?;
            if let Ok(answer) = Message::from_octets(buf.into()) {
                if answer.is_answer(&query.as_message()) {
                    return Ok(answer.into());
                }
            // else try with the next message.
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "short buf",
                ));
            }
        }
    }

    pub async fn udp_query(
        query: &QueryMessage,
        addr: SocketAddr,
        recv_size: usize,
    ) -> Result<Answer, io::Error> {
        let sock = Self::udp_bind(addr.is_ipv4()).await?;
        sock.connect(addr).await?;
        let sent = sock.send(query.as_target().as_dgram_slice()).await?;
        if sent != query.as_target().as_dgram_slice().len() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "short UDP send",
            ));
        }
        loop {
            let mut buf = vec![0; recv_size]; // XXX use uninit'ed mem here.
            let len = sock.recv(&mut buf).await?;
            buf.truncate(len);

            // We ignore garbage since there is a timer on this whole thing.
            let answer = match Message::from_octets(buf.into()) {
                Ok(answer) => answer,
                Err(_) => continue,
            };
            if !answer.is_answer(&query.as_message()) {
                continue;
            }
            return Ok(answer.into());
        }
    }

    async fn udp_bind(v4: bool) -> Result<UdpSocket, io::Error> {
        let mut i = 0;
        loop {
            let local: SocketAddr = if v4 {
                ([0u8; 4], 0).into()
            } else {
                ([0u16; 8], 0).into()
            };
            match UdpSocket::bind(&local).await {
                Ok(sock) => return Ok(sock),
                Err(err) => {
                    if i == RETRY_RANDOM_PORT {
                        return Err(err);
                    } else {
                        i += 1
                    }
                }
            }
        }
    }
}

impl From<ServerConf> for ServerInfo {
    fn from(conf: ServerConf) -> Self {
        ServerInfo {
            conf,
            edns: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl<'a> From<&'a ServerConf> for ServerInfo {
    fn from(conf: &'a ServerConf) -> Self {
        conf.clone().into()
    }
}

//------------ ServerList ----------------------------------------------------

#[derive(Clone, Debug)]
struct ServerList {
    /// The actual list of servers.
    servers: Vec<ServerInfo>,

    /// Where to start accessing the list.
    ///
    /// In rotate mode, this value will always keep growing and will have to
    /// be used modulo `servers`’s length.
    ///
    /// When it eventually wraps around the end of usize’s range, there will
    /// be a jump in rotation. Since that will happen only oh-so-often, we
    /// accept that in favour of simpler code.
    start: Arc<AtomicUsize>,
}

impl ServerList {
    pub fn from_conf<F>(conf: &ResolvConf, filter: F) -> Self
    where
        F: Fn(&ServerConf) -> bool,
    {
        ServerList {
            servers: {
                conf.servers
                    .iter()
                    .filter(|f| filter(f))
                    .map(Into::into)
                    .collect()
            },
            start: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    pub fn counter(&self, rotate: bool) -> ServerListCounter {
        let res = ServerListCounter::new(self);
        if rotate {
            self.rotate()
        }
        res
    }

    pub fn iter(&self) -> ServerListIter {
        ServerListIter::new(self)
    }

    pub fn rotate(&self) {
        self.start.fetch_add(1, Ordering::SeqCst);
    }
}

impl<'a> IntoIterator for &'a ServerList {
    type Item = &'a ServerInfo;
    type IntoIter = ServerListIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl ops::Deref for ServerList {
    type Target = [ServerInfo];

    fn deref(&self) -> &Self::Target {
        self.servers.as_ref()
    }
}

//------------ ServerListCounter ---------------------------------------------

#[derive(Clone, Debug)]
struct ServerListCounter {
    cur: usize,
    end: usize,
}

impl ServerListCounter {
    fn new(list: &ServerList) -> Self {
        if list.servers.is_empty() {
            return ServerListCounter { cur: 0, end: 0 };
        }

        // We modulo the start value here to prevent hick-ups towards the
        // end of usize’s range.
        let start = list.start.load(Ordering::Relaxed) % list.servers.len();
        ServerListCounter {
            cur: start,
            end: start + list.servers.len(),
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> bool {
        let next = self.cur + 1;
        if next < self.end {
            self.cur = next;
            true
        } else {
            false
        }
    }

    pub fn info<'a>(&self, list: &'a ServerList) -> &'a ServerInfo {
        &list[self.cur % list.servers.len()]
    }
}

//------------ ServerListIter ------------------------------------------------

#[derive(Clone, Debug)]
struct ServerListIter<'a> {
    servers: &'a ServerList,
    counter: ServerListCounter,
}

impl<'a> ServerListIter<'a> {
    fn new(list: &'a ServerList) -> Self {
        ServerListIter {
            servers: list,
            counter: ServerListCounter::new(list),
        }
    }
}

impl<'a> Iterator for ServerListIter<'a> {
    type Item = &'a ServerInfo;

    fn next(&mut self) -> Option<Self::Item> {
        if self.counter.next() {
            Some(self.counter.info(self.servers))
        } else {
            None
        }
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
        } else {
            None
        }
    }
}
