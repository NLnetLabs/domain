//! The Resolver.

use std::io;
use std::net::{IpAddr, SocketAddr};
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


//------------ ResolverTask -------------------------------------------------

#[derive(Clone)]
pub struct ResolverTask {
    core: TaskRc<Core>
}

impl ResolverTask {
    pub fn query<N>(&self, name: N, rtype: RRType, class: Class) -> Query
                 where N: AsRef<DNameSlice> {
        let question = Arc::new(Question{name: name.as_ref().to_owned(),
                                         rtype: rtype, class: class});
        Query::new(self.core.clone(), question)
    }

    pub fn conf(&self) -> Arc<ResolvConf> {
        self.core.with(|core| core.conf.clone())
    }
}


//------------ Resolver -----------------------------------------------------

#[derive(Clone)]
pub struct Resolver {
    core: Core
}

impl Resolver {
    pub fn new(reactor: &reactor::Handle, conf: ResolvConf) -> Self {
        Resolver{core: Core::new(reactor, conf)}
    }

    pub fn default(reactor: &reactor::Handle) -> Self {
        Resolver{core: Core::new(reactor, ResolvConf::default())}
    }

    pub fn conf(&self) -> &ResolvConf {
        &self.core.conf
    }

    pub fn options(&self) -> &ResolvOptions {
        &self.core.conf.options
    }

    pub fn run<R, F>(conf: ResolvConf, f: F) -> Result<R::Item, R::Error>
               where R: Future, R::Error: From<io::Error> + Send + 'static,
                     F: FnOnce(ResolverTask) -> R {
        let mut reactor = try!(reactor::Core::new());
        let resolver = Resolver::new(&reactor.handle(), conf);
        let fut = resolver.start().and_then(|resolv| f(resolv));
        reactor.run(fut)
    }
 
    pub fn start<E>(&self) -> BoxFuture<ResolverTask, E>
                 where E: Send + 'static {
        let core = self.core.clone();
        lazy(move || Ok(ResolverTask{core: TaskRc::new(core)})).boxed()
    }
}


//------------ Query --------------------------------------------------------

pub struct Query {
    core: TaskRc<Core>,
    question: Arc<Question>,
    request: BoxFuture<Result<MessageBuf, Error>, Error>,

    dgram: bool,
    start_index: usize,
    curr_index: usize,
    attempt: usize
}

impl Query {
    fn new(core: TaskRc<Core>, question: Arc<Question>) -> Self {
        let (index, dgram, request) = Self::start(&core, question.clone());
        Query {
            core: core, question: question, request: request,

            dgram: dgram, start_index: index, curr_index: index,
            attempt: 0
        }
    }
}


impl Future for Query {
    type Item = MessageBuf;
    type Error = Error;

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

impl Query {
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

    fn restart(&mut self) -> Poll<MessageBuf, Error> {
        let (index, dgram, request) = Self::start(&self.core,
                                                  self.question.clone());
        self.dgram = dgram;
        self.start_index = index;
        self.curr_index = index;
        self.request = request;
        //Ok(Async::NotReady)
        self.poll()
    }

    /// Processes a response.
    fn response(&mut self, response: MessageBuf)
                -> Poll<MessageBuf, Error> {
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
                // Ok(Async::NotReady)
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
                //Ok(Async::NotReady)
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
        Ok(Async::NotReady)
    }
}


//------------ Core ---------------------------------------------------------

#[derive(Clone)]
struct Core {
    udp: Vec<ServiceHandle>,
    tcp: Vec<ServiceHandle>,
    conf: Arc<ResolvConf>,
}


impl Core {
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
                                             addr.clone(), conf.timeout,
                                             512) {
                udp.push(service);
            }
            if let Ok(service) = tcp_service(reactor.clone(),
                                             addr.clone(), conf.idle_timeout,
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

    fn options(&self) -> &ResolvOptions {
        &self.conf.options
    }
}


//------------ ServiceHandle ------------------------------------------------

pub struct ServiceHandle {
    tx: Sender<Request>,
}

impl ServiceHandle {
    pub fn from_sender(tx: Sender<Request>) -> Self {
        ServiceHandle{tx: tx}
    }

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

impl Clone for ServiceHandle {
    fn clone(&self) -> Self {
        ServiceHandle{tx: self.tx.clone()}
    }
}

