//! The resolver and related types.

use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::sync::Arc;
use futures::{Async, BoxFuture, Future, IntoFuture, Poll, lazy, oneshot};
use futures::task::TaskRc;
use rand;
use tokio_core::channel::Sender;
use tokio_core::reactor;
use ::bits::{DNameSlice, MessageBuf};
use ::iana::{RRType, Class};
use super::conf::{ResolvConf, ResolvOptions};
use super::error::Error;
use super::request::{Question, Request};
use super::tcp::tcp_service;
use super::udp::udp_service;


//------------ Resolver -----------------------------------------------------

/// Access to a resolver.
///
/// This types collects all information in order to be able to start a DNS
/// query on a resolver. You can create a new resolver by calling either
/// the `new()` or `from_conf()` functions passing in a handle to a Tokio
/// reactor core. Either function will spawn everything necessary for a
/// resolver into that core. Existing resolver values can be cloned. Clones
/// will refer to the same resolver.
/// 
/// In order to perform a query, you will have to call the `start()` method
/// to create a future that will resolve into an intermediary value that
/// will than allow calling a `query()` method on it and will also allow
/// more complex operations as a complex future.
///
/// Alternatively, you can use the `run()` associated function to
/// synchronously perfrom a series of queries.
#[derive(Clone, Debug)]
pub struct Resolver {
    core: Arc<Core>
}

impl Resolver {
    /// Creates a new resolver using the system’s default configuration.
    ///
    /// All the components of the resolver will be spawned into the reactor
    /// referenced by `handle`.
    pub fn new(reactor: &reactor::Handle) -> Self {
        Self::from_conf(reactor, ResolvConf::default())
    }

    /// Creates a new resolver using the given configuration.
    ///
    /// All the components of the resolver will be spawned into the reactor
    /// referenced by `handle`.
    pub fn from_conf(reactor: &reactor::Handle, conf: ResolvConf) -> Self {
        Resolver{core: Arc::new(Core::new(reactor, conf))}
    }

    /// Returns a reference to the configuration of this resolver.
    pub fn conf(&self) -> &ResolvConf {
        &self.core.conf
    }

    /// Returns a reference to the configuration options of this resolver.
    pub fn options(&self) -> &ResolvOptions {
        &self.core.conf.options
    }

    /// Starts a resolver future atop this resolver.
    ///
    /// The method returns a future that will resolve into a [ResolverTask]
    /// value that can be used to start queries atop this resolver.
    ///
    /// Since the future will never error, it is generic over the error type.
    ///
    /// [ResolverTask]: struct.ResolverTask.html
    pub fn start<E>(&self) -> BoxFuture<ResolverTask, E>
                 where E: Send + 'static {
        let core = self.core.deref().clone();
        lazy(move || Ok(ResolverTask{core: TaskRc::new(core)})).boxed()
    }
}

/// # Shortcuts
///
impl Resolver {
    /// Synchronously perform a DNS operation atop a standard resolver.
    ///
    /// This associated functions removes almost all boiler plate for the
    /// case if you want to perform some DNS operation on a resolver using
    /// the system’s configuration and wait for the result.
    ///
    /// The only argument is a closure taking a [ResolverTask] for creating
    /// queries and returning a future. Whatever that future resolves to will
    /// be returned.
    pub fn run<R, F>(f: F) -> Result<R::Item, R::Error>
               where R: Future, R::Error: From<io::Error> + Send + 'static,
                     F: FnOnce(ResolverTask) -> R {
        let mut reactor = try!(reactor::Core::new());
        let resolver = Resolver::new(&reactor.handle());
        let fut = resolver.start().and_then(f);
        reactor.run(fut)
    }

    /// Spawn a query.
    ///
    /// This method is a shortcut for `self.start().and_then(f).boxed()`.
    /// Because of the `boxed()` bit, it requires lots of things to be
    /// `Send + 'static` and because of that isn’t necessarily better than
    /// the longer way.
    ///
    /// I am also not sure if *spawn* is the right name. Probably not since
    /// it actually returns the future.
    pub fn spawn<R, F>(&self, f: F) -> BoxFuture<R::Item, R::Error>
                 where R: Future + Send + 'static,
                       R::Error: From<io::Error> + Send + 'static,
                       F: FnOnce(ResolverTask) -> R + Send + 'static {
        self.start().and_then(f).boxed()
    }
}


//------------ ResolverTask -------------------------------------------------

/// A resolver bound to a futures task.
///
/// You can use this type within a running future to start a query on top
/// of the resolver using the `query()` method.
#[derive(Clone)]
pub struct ResolverTask {
    core: TaskRc<Core>
}

impl ResolverTask {
    /// Start a DNS query on this resolver.
    ///
    /// Returns a future that, if successful, will resolve into a DNS
    /// message containing a response to a query for resource records of type
    /// `rtype` associated with the domain name `name` and class `class`. The
    /// name must be an absolute name or else the query will fail.
    pub fn query<N>(&self, name: N, rtype: RRType, class: Class) -> Query
                 where N: AsRef<DNameSlice> {
        let question = Arc::new(Question{name: name.as_ref().to_owned(),
                                         rtype: rtype, class: class});
        Query::new(self.core.clone(), question)
    }

    /// Returns an arc reference to the resolver’s config.
    pub fn conf(&self) -> Arc<ResolvConf> {
        self.core.with(|core| core.conf.clone())
    }
}


//------------ Query --------------------------------------------------------

/// The future of an ongoing query.
pub struct Query {
    /// The core of the resolver we are working on.
    core: TaskRc<Core>,

    /// The question we need to process.
    question: Arc<Question>,

    /// The request we are currently processing.
    request: BoxFuture<Result<MessageBuf, Error>, Error>,

    /// Are we still in datagram stage?
    ///
    /// Assuming the resolver config allows using datagram services at all,
    /// we’ll start with `true`. Only if a response is truncated do we have
    /// to switch to `false` and go through the stream services.
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

    /// The how-many-th attempt is this, starting at attempt 0.
    attempt: usize
}

impl Query {
    /// Creates a new query using the given core and question.
    fn new(core: TaskRc<Core>, question: Arc<Question>) -> Self {
        let (index, dgram, request) = Self::start(&core, question.clone());
        Query {
            core: core, question: question, request: request,

            dgram: dgram, start_index: index, curr_index: index,
            attempt: 0
        }
    }

    /// Starts the query with the first request.
    ///
    /// Uses `core` and `question` to figure out the first request and
    /// fires it off. Returns, in this order, the index of the service we
    /// are using, the value of `dgram`, and a future for the request.
    fn start(core: &TaskRc<Core>, question: Arc<Question>)
             -> (usize, bool,
                 BoxFuture<Result<MessageBuf, Error>, Error>) {
        core.with(|core| {
            if !core.options().use_vc {
                let index = if core.options().rotate {
                    rand::random::<usize>() % core.udp.len()
                }
                else { 0 };
                let request = core.udp[index].request(question);
                (index, true, request)
            }
            else {
                let index = if core.options().rotate {
                    rand::random::<usize>() % core.tcp.len()
                }
                else { 0 };
                let request = core.tcp[index].request(question);
                (index, false, request)
            }
        })
    }

    /// Starts the next attempt for this query.
    fn restart(&mut self) -> Poll<MessageBuf, Error> {
        let (index, dgram, request) = Self::start(&self.core,
                                                  self.question.clone());
        self.dgram = dgram;
        self.start_index = index;
        self.curr_index = index;
        self.request = request;
        self.poll() // Poll to register interest in the request.
    }

    /// Processes a response.
    ///
    /// This will either resolve the future or switch to stream mode.
    fn response(&mut self, response: MessageBuf) -> Poll<MessageBuf, Error> {
        if response.header().tc() && self.dgram
                && !self.core.with(|core| core.options().ign_tc)
        {
            self.start_stream()
        }
        else { Ok(response.into()) }
    }

    /// Proceeds to the next request or errors out.
    fn next_request(&mut self) -> Poll<MessageBuf, Error> {
        if self.dgram {
            self.curr_index += 1;
            let udp_len = self.core.with(|core| core.udp.len());
            if (self.curr_index % udp_len) == self.start_index {
                self.start_stream()
            }
            else {
                self.request = self.core.with(|core| {
                    core.udp[self.curr_index].request(self.question.clone())
                });
                self.poll()
            }
        }
        else {
            self.curr_index += 1;
            let tcp_len = self.core.with(|core| core.tcp.len());
            if (self.curr_index % tcp_len) == self.start_index {
                self.attempt += 1;
                if self.attempt == self.core.with(|core| core.conf.attempts) {
                    Err(Error::Timeout)
                }
                else {
                    self.restart()
                }
            }
            else {
                self.request = self.core.with(|core| {
                    core.tcp[self.curr_index].request(self.question.clone())
                });
                self.poll()
            }
        }
    }

    /// Switches to stream mode and starts the first request or errors out.
    fn start_stream(&mut self) -> Poll<MessageBuf, Error> {
        self.dgram = false;
        self.start_index = if self.core.with(|core| core.options().rotate) {
            rand::random::<usize>() % self.core.with(|core| core.tcp.len())
        }
        else { 0 };
        self.curr_index = self.start_index;
        self.request = self.core.with(|core| {
            core.tcp[self.curr_index].request(self.question.clone())
        });
        self.poll()
    }
}


//--- Future

impl Future for Query {
    type Item = MessageBuf;
    type Error = Error;

    /// Polls for completion.
    ///
    /// Polls the current request. If that succeeded, returns the result. If
    /// it failed fatally, returns an error. If it failed non-fatally,
    /// proceeds to the next request.
    fn poll(&mut self) -> Poll<MessageBuf, Error> {
        match self.request.poll() {
            Ok(Async::Ready(Ok(response))) => {
                self.response(response)
            }
            Ok(Async::Ready(Err(err))) => Err(err),
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(err) => {
                if err.is_fatal() { Err(err.into()) }
                else { self.next_request() }
            }
        }
    }
}



//------------ Core ---------------------------------------------------------

/// The resolver core.
///
/// This type collects the sender sides of the channels to all the services
/// of this resolver plus and arc with the config.
#[derive(Clone)]
struct Core {
    udp: Vec<ServiceHandle>,
    tcp: Vec<ServiceHandle>,
    conf: Arc<ResolvConf>,
}

impl Core {
    /// Creates a new resolver core using the given reactor and config.
    fn new(reactor: &reactor::Handle, conf: ResolvConf) -> Self {
        let mut udp = Vec::new();
        let mut tcp = Vec::new();

        for addr in &conf.servers {
            let local = match *addr {
                SocketAddr::V4(_)
                    => SocketAddr::new(IpAddr::V4(0.into()), 0),
                SocketAddr::V6(_)
                    => SocketAddr::new(IpAddr::V6([0;16].into()), 0)
            };
            if let Ok(service) = udp_service(reactor.clone(), local,
                                             *addr, conf.timeout, 512) {
                udp.push(service);
            }
            if let Ok(service) = tcp_service(reactor.clone(),
                                             *addr, conf.idle_timeout,
                                             conf.timeout) {
                tcp.push(service);
            }
        }

        Core {
            udp: udp,
            tcp: tcp,
            conf: Arc::new(conf)
        }
    }

    /// Returns a reference to the configuration options of this core.
    fn options(&self) -> &ResolvOptions {
        &self.conf.options
    }
}


//--- Debug

impl fmt::Debug for Core {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.conf.fmt(f)
    }
}


//------------ ServiceHandle ------------------------------------------------

/// A handle to a service.
pub struct ServiceHandle {
    tx: Sender<Request>,
}

impl ServiceHandle {
    /// Creates a new handle from the sender side of a channel.
    pub fn from_sender(tx: Sender<Request>) -> Self {
        ServiceHandle{tx: tx}
    }

    /// Starts a new request using this service.
    ///
    /// If the request can be queued up with the service, returns a oneshot
    /// eventually resulting in the request’s result. If the channel has gone
    /// away, the future will return a timeout error.
    pub fn request(&self, question: Arc<Question>)
                   -> BoxFuture<Result<MessageBuf, Error>, Error> {
        let (c, o) = oneshot();
        let request = Request::new(question, c);
        let sent = self.tx.send(request).into_future()
                       .map_err(|_| Error::Timeout);
        
        let mapped_o = o.then(|res| {
            match res {
                Ok(Ok(response)) => Ok(Ok(response)),
                Ok(Err(err)) => {
                    if err.is_fatal() { Ok(Err(err.into())) }
                    else { Err(err) }
                }
                Err(_) => Err(Error::Timeout)
            }
        });

        sent.and_then(|_| mapped_o).boxed()
    }
}


//--- Clone

impl Clone for ServiceHandle {
    fn clone(&self) -> Self {
        ServiceHandle{tx: self.tx.clone()}
    }
}

