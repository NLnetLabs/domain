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
use crate::base::message_builder::{AdditionalBuilder, MessageBuilder};
use crate::base::name::{ToName, ToRelativeName};
use crate::base::question::Question;
use crate::net::client::dgram_stream;
use crate::net::client::multi_stream;
use crate::net::client::protocol::{TcpConnect, UdpConnect};
use crate::net::client::redundant;
use crate::net::client::request::{
    ComposeRequest, Error, RequestMessage, SendRequest,
};
use crate::resolv::lookup::addr::{lookup_addr, FoundAddrs};
use crate::resolv::lookup::host::{lookup_host, search_host, FoundHosts};
use crate::resolv::lookup::srv::{lookup_srv, FoundSrvs, SrvError};
use crate::resolv::resolver::{Resolver, SearchNames};
use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use octseq::array::Array;
use std::boxed::Box;
use std::fmt::Debug;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::string::ToString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::vec::Vec;
use std::{io, ops};
#[cfg(feature = "resolv-sync")]
use tokio::runtime;
use tokio::sync::Mutex;
use tokio::time::timeout;

//------------ Sub-modules ---------------------------------------------------

pub mod conf;

//------------ Module Configuration ------------------------------------------

//------------ StubResolver --------------------------------------------------

/// A DNS stub resolver.
///
/// This type collects all information making it possible to start DNS
/// queries. You can create a new resolver using the system’s configuration
/// using the [`new`] associate function or using your own configuration with
/// [`from_conf`].
///
/// Stub resolver values can be cloned relatively cheaply as they keep all
/// information behind an arc.
///
/// If you want to run a single query or lookup on a resolver synchronously,
/// you can do so simply by using the [`run`] or [`run_with_conf`] associated
/// functions.
///
/// [`new`]: #method.new
/// [`from_conf`]: #method.from_conf
/// [`query`]: #method.query
/// [`run`]: #method.run
/// [`run_with_conf`]: #method.run_with_conf
#[derive(Debug)]
pub struct StubResolver {
    transport: Mutex<Option<redundant::Connection<RequestMessage<Vec<u8>>>>>,

    /// Resolver options.
    options: ResolvOptions,

    servers: Vec<ServerConf>,
}

impl StubResolver {
    /// Creates a new resolver using the system’s default configuration.
    pub fn new() -> Self {
        Self::from_conf(ResolvConf::default())
    }

    /// Creates a new resolver using the given configuraiton.
    pub fn from_conf(conf: ResolvConf) -> Self {
        StubResolver {
            transport: None.into(),
            options: conf.options,

            servers: conf.servers,
        }
    }

    pub fn options(&self) -> &ResolvOptions {
        &self.options
    }

    /// Adds a new connection to the running resolver.
    pub async fn add_connection(
        &self,
        connection: Box<
            dyn SendRequest<RequestMessage<Vec<u8>>> + Send + Sync,
        >,
    ) {
        self.get_transport()
            .await
            .expect("The 'redundant::Connection' task should not fail")
            .add(connection)
            .await
            .expect("The 'redundant::Connection' task should not fail");
    }

    pub async fn query<N: ToName, Q: Into<Question<N>>>(
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

    async fn setup_transport<
        CR: Clone + Debug + ComposeRequest + Send + Sync + 'static,
    >(
        &self,
    ) -> Result<redundant::Connection<CR>, Error> {
        // Create a redundant transport and fill it with the right transports
        let (redun, transp) = redundant::Connection::new();

        // Start the run function on a separate task.
        let redun_run_fut = transp.run();

        // It would be nice to have just one task. However redun.run() has to
        // execute before we can call redun.add(). However, we need to know
        // the type of the elements we add to FuturesUnordered. For the moment
        // we have two tasks.
        tokio::spawn(async move {
            redun_run_fut.await;
        });

        let fut_list_tcp = FuturesUnordered::new();
        let fut_list_udp_tcp = FuturesUnordered::new();

        // Start the tasks with empty base transports. We need redun to be
        // running before we can add transports.

        // We have 3 modes of operation: use_vc: only use TCP, ign_tc: only
        // UDP no fallback to TCP, and normal with is UDP falling back to TCP.

        for s in &self.servers {
            // This assumes that Transport only has UdpTcp and Tcp. Sadly, a
            // match doesn’t work here because of the use_cv flag.
            if self.options.use_vc || matches!(s.transport, Transport::Tcp) {
                let (conn, tran) =
                    multi_stream::Connection::new(TcpConnect::new(s.addr));
                // Start the run function on a separate task.
                fut_list_tcp.push(tran.run());
                redun.add(Box::new(conn)).await?;
            } else {
                let udp_connect = UdpConnect::new(s.addr);
                let tcp_connect = TcpConnect::new(s.addr);
                let (conn, tran) =
                    dgram_stream::Connection::new(udp_connect, tcp_connect);
                // Start the run function on a separate task.
                fut_list_udp_tcp.push(tran.run());
                redun.add(Box::new(conn)).await?;
            }
        }

        tokio::spawn(async move {
            run(fut_list_tcp, fut_list_udp_tcp).await;
        });

        Ok(redun)
    }

    async fn get_transport(
        &self,
    ) -> Result<redundant::Connection<RequestMessage<Vec<u8>>>, Error> {
        let mut opt_transport = self.transport.lock().await;

        match &*opt_transport {
            Some(transport) => Ok(transport.clone()),
            None => {
                let transport = self.setup_transport().await?;
                *opt_transport = Some(transport.clone());
                Ok(transport)
            }
        }
    }
}

async fn run<TcpFut: Future, UdpTcpFut: Future>(
    mut fut_list_tcp: FuturesUnordered<TcpFut>,
    mut fut_list_udp_tcp: FuturesUnordered<UdpTcpFut>,
) {
    loop {
        let tcp_empty = fut_list_tcp.is_empty();
        let udp_tcp_empty = fut_list_udp_tcp.is_empty();
        if tcp_empty && udp_tcp_empty {
            break;
        }
        tokio::select! {
        _ = fut_list_tcp.next(), if !tcp_empty => {
            // Nothing to do
        }
        _ = fut_list_udp_tcp.next(), if !udp_tcp_empty => {
            // Nothing to do
        }
        }
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
        qname: impl ToName,
    ) -> Result<FoundHosts<&Self>, io::Error> {
        lookup_host(&self, qname).await
    }

    pub async fn search_host(
        &self,
        qname: impl ToRelativeName,
    ) -> Result<FoundHosts<&Self>, io::Error> {
        search_host(&self, qname).await
    }

    /// Performs an SRV lookup using this resolver.
    ///
    /// See the documentation for the [`lookup_srv`] function for details.
    pub async fn lookup_srv(
        &self,
        service: impl ToRelativeName,
        name: impl ToName,
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
    /// The only argument is a closure taking a reference to a [`StubResolver`]
    /// and returning a future. Whatever that future resolves to will be
    /// returned.
    pub fn run<R, T, E, F>(op: F) -> R::Output
    where
        R: Future<Output = Result<T, E>> + Send + 'static,
        E: From<io::Error>,
        F: FnOnce(StubResolver) -> R + Send + 'static,
    {
        Self::run_with_conf(ResolvConf::default(), op)
    }

    /// Synchronously perform a DNS operation atop a configured resolver.
    ///
    /// This is like [`run`] but also takes a resolver configuration for
    /// tailor-making your own resolver.
    ///
    /// [`run`]: Self::run
    pub fn run_with_conf<R, T, E, F>(conf: ResolvConf, op: F) -> R::Output
    where
        R: Future<Output = Result<T, E>> + Send + 'static,
        E: From<io::Error>,
        F: FnOnce(StubResolver) -> R + Send + 'static,
    {
        let resolver = Self::from_conf(conf);
        let runtime = runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
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
        N: ToName,
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

    edns: Arc<AtomicBool>,

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
        Ok(Query {
            resolver,
            edns: Arc::new(AtomicBool::new(true)),
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
                    if answer.header().rcode() == Rcode::FORMERR
                        && self.does_edns()
                    {
                        // FORMERR with EDNS: turn off EDNS and try again.
                        self.disable_edns();
                        continue;
                    } else if answer.header().rcode() == Rcode::SERVFAIL {
                        // SERVFAIL: go to next server.
                        self.update_error_servfail(answer);
                    } else {
                        // I guess we have an answer ...
                        return Ok(answer);
                    }
                }
                Err(err) => self.update_error(err),
            }
            return self.error;
        }
    }

    fn create_message(question: Question<impl ToName>) -> QueryMessage {
        let mut message = MessageBuilder::from_target(Default::default())
            .expect("MessageBuilder should not fail");
        message.header_mut().set_rd(true);
        let mut message = message.question();
        message.push(question).expect("push should not fail");
        message.additional()
    }

    async fn run_query(
        &mut self,
        message: &mut QueryMessage,
    ) -> Result<Answer, io::Error> {
        let msg = Message::from_octets(message.as_target().to_vec())
            .expect("Message::from_octets should not fail");

        let request_msg = RequestMessage::new(msg).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?;

        let transport = self.resolver.get_transport().await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, e.to_string())
        })?;
        let mut gr_fut = transport.send_request(request_msg);
        let reply =
            timeout(self.resolver.options.timeout, gr_fut.get_response())
                .await?
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, e.to_string())
                })?;
        Ok(Answer { message: reply })
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

    pub fn does_edns(&self) -> bool {
        self.edns.load(Ordering::Relaxed)
    }

    pub fn disable_edns(&self) {
        self.edns.store(false, Ordering::Relaxed);
    }
}

//------------ QueryMessage --------------------------------------------------

// XXX This needs to be re-evaluated if we start adding OPTions to the query.
pub(super) type QueryMessage = AdditionalBuilder<Array<512>>;

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
        (self.message.header().rcode() == Rcode::NOERROR
            || self.message.header().rcode() == Rcode::NXDOMAIN)
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

impl Iterator for SearchIter<'_> {
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
