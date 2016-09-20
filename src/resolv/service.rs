//! Service for DNS.

use std::io;
use std::mem;
use std::time::Duration;
use futures::{Async, Future, Poll};
use futures::stream::{Peekable, Stream};
use tokio_core::reactor;
use tokio_core::channel::Receiver;
use super::conf::{ServerConf, TransportMode};
use super::request::ServiceRequest;


//------------ Transport -----------------------------------------------------

/// Something that can send and receive DNS messages.
pub trait Transport: io::Read + io::Write { }


//------------ TransportFactory ----------------------------------------------

/// Something that can make a new `Transport`.
pub trait TransportFactory {
    /// The type of transport created by this factory.
    type Transport: Transport;

    /// The type of future resolved while making a new transport.
    type Future: Future<Item=Self::Transport, Error=io::Error>;

    /// Starts creating a new transport atop a given reactor.
    fn create(&self, reactor: &reactor::Handle) -> io::Result<Self::Future>;
}


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
    pub fn from_transport_mode(t: TransportMode, default: ServiceMode)
                               -> Option<Self> {
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
pub struct Service<T: TransportFactory>(TrueService<T>);

enum TrueService<T: TransportFactory> {
    Single(SingleService<T>),
    Sequential(Expiring<T, SequentialService<T>>),
    Multiplex(Expiring<T, MultiplexService<T>>)
}


impl<T: TransportFactory> Service<T> {
    /// Creates a new service.
    fn new(receiver: Receiver<ServiceRequest>, factory: T,
           reactor: reactor::Handle, mode: ServiceMode, conf: &ServerConf)
           -> Self {
        match mode {
            ServiceMode::SingleRequest => {
                Service(
                    TrueService::Single(
                        SingleService::new(receiver, factory, reactor, conf)
                    )
                )
            }
            ServiceMode::Sequential => {
                Service(
                    TrueService::Sequential(
                        Expiring::new(receiver, factory, reactor, conf)
                    )
                )
            }
            ServiceMode::Multiplex => {
                Service(
                    TrueService::Multiplex(
                        Expiring::new(receiver, factory, reactor, conf)
                    )
                )
            }
        }
    }
}


//--- Future

impl<T: TransportFactory> Future for Service<T> {
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


//------------ SingleService -------------------------------------------------

/// A service in single request mode.
struct SingleService<T: TransportFactory> {
    receiver: Receiver<ServiceRequest>,
    factory: T,
    reactor: reactor::Handle,
}


impl<T: TransportFactory> SingleService<T> {
    fn new(receiver: Receiver<ServiceRequest>, factory: T,
           reactor: reactor::Handle, conf: &ServerConf) -> Self {
        unimplemented!()
    }
}


//--- Future

impl<T: TransportFactory> Future for SingleService<T> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        unimplemented!()
    }
}


//------------ ExpiringService -----------------------------------------------

/// The service underneath `Expiring`.
///
/// Implementors need to be a stream of `()`, returning an item every time
/// the timeout needs to be refreshed. When they are done streaming, they
/// will be destroyed via their `finalize()` method, thereby retrieving the
/// receiver if it still exists.
trait ExpiringService<T: TransportFactory>: Stream<Item=(), Error=io::Error> {
    fn create(sock: T::Future, receiver: Peekable<Receiver<ServiceRequest>>,
              request_timeout: Duration) -> Self;
    fn finalize(self) -> Option<Peekable<Receiver<ServiceRequest>>>;
}


//------------ Expiring ------------------------------------------------------

/// A wrapper for a service that will expire if nothing happens for too long.
struct Expiring<T: TransportFactory, S: ExpiringService<T>> {
    state: State<S>,
    factory: T,
    reactor: reactor::Handle,
    request_timeout: Duration,
    keep_alive: Duration,
}

enum State<S> {
    Idle(Peekable<Receiver<ServiceRequest>>),
    Active {
        service: S,
        timeout: Option<reactor::Timeout>
    },
    Dead
}


impl<T: TransportFactory, S: ExpiringService<T>> Expiring<T, S> {
    fn new(receiver: Receiver<ServiceRequest>, factory: T,
           reactor: reactor::Handle, conf: &ServerConf) -> Self {
        Expiring {
            state: State::Idle(receiver.peekable()),
            factory: factory,
            reactor: reactor,
            request_timeout: conf.request_timeout,
            keep_alive: conf.keep_alive
        }
    }
}


//--- Future

impl<T: TransportFactory, S: ExpiringService<T>> Future for Expiring<T, S> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        match self.state {
            State::Idle(ref mut receiver) => {
                try_ready!(receiver.peek());
            }
            State::Active{ref mut service, ref mut timeout} => {
                if let Some(ref mut timeout) = *timeout {
                    match timeout.poll() {
                        Ok(Async::Ready(())) => { }
                        other => return other
                    }
                }
                if let Some(()) = try_ready!(service.poll()) {
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
            }
            State::Dead => panic!("poll on a dead service")
        }

        self.state = match mem::replace(&mut self.state, State::Dead) {
            State::Idle(receiver) => {
                let sock = try!(self.factory.create(&self.reactor));
                let service = S::create(sock, receiver, self.request_timeout);
                let timeout = reactor::Timeout::new(self.keep_alive,
                                                    &self.reactor).ok();
                State::Active{service: service, timeout: timeout}
            }
            State::Active{service, ..} => {
                match service.finalize() {
                    Some(receiver) => State::Idle(receiver),
                    None => return Ok(Async::Ready(()))
                }
            }
            State::Dead => panic!()
        };
        Ok(Async::NotReady)
    }
}


//------------ SequentialService ---------------------------------------------

/// A service in sequential request mode.
struct SequentialService<T: TransportFactory> {
    phantom: ::std::marker::PhantomData<T>
}


//--- ExpiringService

impl<T: TransportFactory> ExpiringService<T> for SequentialService<T> {
    fn create(sock: T::Future, recv: Peekable<Receiver<ServiceRequest>>,
              request_timeout: Duration) -> Self {
        unimplemented!()
    }

    fn finalize(self) -> Option<Peekable<Receiver<ServiceRequest>>> {
        unimplemented!()
    }
}


//--- Stream

impl<T: TransportFactory> Stream for SequentialService<T> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<()>, io::Error> {
        unimplemented!()
    }
}


//------------ MultiplexService ----------------------------------------------

/// A service in multiplex mode.
struct MultiplexService<T: TransportFactory> {
    phantom: ::std::marker::PhantomData<T>
}


//--- ExpiringService

impl<T: TransportFactory> ExpiringService<T> for MultiplexService<T> {
    fn create(sock: T::Future, recv: Peekable<Receiver<ServiceRequest>>,
              request_timeout: Duration) -> Self {
        unimplemented!()
    }

    fn finalize(self) -> Option<Peekable<Receiver<ServiceRequest>>> {
        unimplemented!()
    }
}


//--- Stream

impl<T: TransportFactory> Stream for MultiplexService<T> {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<()>, io::Error> {
        unimplemented!()
    }
}

