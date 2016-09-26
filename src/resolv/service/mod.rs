//! Service for DNS.

use std::io;
use std::time::Duration;
use futures::{Async, Future, Poll};
use futures::stream::Stream;
use tokio_core::reactor;
use tokio_core::channel::channel;
use super::conf::{ServerConf, TransportMode};
use super::request::{RequestReceiver, ServiceHandle, ServiceRequest};
use super::transport::{Transport};
use super::utils::{IoStreamFuture, Passthrough};

mod single;
mod sequential;
mod multiplex;


//------------ ServiceMode ---------------------------------------------------

/// The mode a service will run in.
///
/// This is essentially `conf::TransportMode` stripped of the variants that a
/// real service can’t have.
pub enum ServiceMode {
    SingleRequest,
    Sequential,
    Multiplex,
}

impl ServiceMode {
    pub fn resolve(t: TransportMode, default: ServiceMode) -> Option<Self> {
        match t {
            TransportMode::None => None,
            TransportMode::Default => Some(default),
            TransportMode::SingleRequest => Some(ServiceMode::SingleRequest),
            TransportMode::Sequential => Some(ServiceMode::Sequential),
            TransportMode::Multiplex => Some(ServiceMode::Multiplex)
        }
    }
}


//------------ Service -------------------------------------------------------

/// A service processes DNS requests.
pub struct Service<T: Transport>(TrueService<T>);

enum TrueService<T: Transport> {
    Single(single::Service<T>),
    Sequential(Expiring<T, sequential::Service<T>>),
    Multiplex(Expiring<T, multiplex::Service<T>>)
}


impl<T: Transport> Service<T> {
    /// Creates a new service.
    fn new(reactor: reactor::Handle, receiver: RequestReceiver, transport: T,
           mode: ServiceMode, conf: &ServerConf)
           -> Self {
        match mode {
            ServiceMode::SingleRequest => {
                Service(
                    TrueService::Single(
                        single::Service::new(receiver, transport, reactor,
                                             conf)
                    )
                )
            }
            ServiceMode::Sequential => {
                Service(
                    TrueService::Sequential(
                        Expiring::new(receiver, transport, reactor, conf)
                    )
                )
            }
            ServiceMode::Multiplex => {
                Service(
                    TrueService::Multiplex(
                        Expiring::new(receiver, transport, reactor, conf)
                    )
                )
            }
        }
    }

    /// Spawns a new service.
    pub fn spawn(reactor: reactor::Handle, transport: T, mode: ServiceMode,
                 conf: &ServerConf) -> io::Result<ServiceHandle> {
        let (tx, rx) = try!(channel(&reactor));
        let res = ServiceHandle::from_sender(tx);
        let service = Self::new(reactor.clone(), rx, transport, mode, conf);
        reactor.spawn(service.map_err(|_| ()));
        Ok(res)
    }
}


//--- Future

impl<T: Transport> Future for Service<T> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        match self.0 {
            TrueService::Single(ref mut s) => s.poll(),
            TrueService::Sequential(ref mut s) => s.poll(),
            TrueService::Multiplex(ref mut s) => s.poll()
        }
    }
}


//------------ ExpiringService -----------------------------------------------

trait ExpiringService<T: Transport>: Stream<Item=(), Error=io::Error> {
    fn create(rd: T::Read, wr: T::Write, receiver: RequestReceiver,
              request: ServiceRequest, reactor: reactor::Handle,
              request_timeout: Duration) -> Self;
    fn take(&mut self) -> Option<RequestReceiver>;
}


//------------ Expiring ------------------------------------------------------

/// A wrapper for a service that will expire if nothing happens for too long.
struct Expiring<T: Transport, S: ExpiringService<T>> {
    state: State<T, S>,
    transport: T,
    reactor: reactor::Handle,
    request_timeout: Duration,
    keep_alive: Duration,
}

enum State<T: Transport, S: ExpiringService<T>> {
    Idle(IoStreamFuture<RequestReceiver>),
    Connecting(Passthrough<T::Future, (RequestReceiver, ServiceRequest)>),
    Active(S, Option<reactor::Timeout>)
}


impl<T: Transport, S: ExpiringService<T>> Expiring<T, S> {
    fn new(receiver: RequestReceiver, transport: T,
           reactor: reactor::Handle, conf: &ServerConf) -> Self {
        Expiring {
            state: State::Idle(receiver.into()),
            transport: transport,
            reactor: reactor,
            request_timeout: conf.request_timeout,
            keep_alive: conf.keep_alive
        }
    }
}


//--- Future

impl<T: Transport, S: ExpiringService<T>> Future for Expiring<T, S> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        let state = match self.state {
            State::Idle(ref mut fut) => {
                let (request, receiver) = match try_ready!(fut.poll()) {
                    (Some(request), receiver) => {
                        (request, receiver)
                    }
                    (None, _) => return Ok(().into()),
                };
                let sock = try!(self.transport.create(&self.reactor));
                State::Connecting(Passthrough::new(sock, (receiver, request)))
            }
            State::Connecting(ref mut fut) => {
                let ((rd, wr), (receiver, request)) = try_ready!(fut.poll());
                let service = S::create(rd, wr, receiver, request,
                                        self.reactor.clone(),
                                        self.request_timeout);
                let timeout = reactor::Timeout::new(self.keep_alive,
                                                    &self.reactor).ok();
                State::Active(service, timeout)
            }
            State::Active(ref mut service, ref mut timeout) => {
                match try!(service.poll()) {
                    Async::Ready(Some(())) => {
                        *timeout = reactor::Timeout::new(self.keep_alive,
                                                         &self.reactor).ok();
                        if let Some(ref mut timeout) = *timeout {
                            try_ready!(timeout.poll());
                            // If we come here, the timeout triggered
                            // already. Let’s panic because this can only lead
                            // to trouble later ...
                            panic!("Timeout triggered right away.");
                        }
                        return Ok(Async::NotReady)
                    }
                    Async::Ready(None) => { }
                    Async::NotReady => {
                        if let Some(ref mut timeout) = *timeout {
                            if let Async::NotReady = try!(timeout.poll()) {
                                return Ok(Async::NotReady)
                            }
                        }
                        else {
                            return Ok(Async::NotReady)
                        }
                    }
                }
                // Either the service is done or the timeout hit. Back
                // to idle if there’s still a receiver or we are done.
                if let Some(receiver) = service.take() {
                    State::Idle(receiver.into())
                }
                else {
                    return Ok(().into())
                }
            }
        };
        self.state = state;
        self.poll()
    }
}



