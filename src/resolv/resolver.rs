//! A DNS Resolver using rotor.

use std::io;
use std::sync::mpsc::TryRecvError;
use std::thread;
use rotor::{self, EventSet, GenericScope, Machine, Notifier, Response,
            Scope, Void};
use bits::message::MessageBuf;
use resolv::conf::ResolvConf;
use resolv::error::{Error, Result};
use resolv::tasks::traits::{Progress, Task, TaskRunner};
use super::dispatcher::{BootstrapItem, Dispatcher};
use super::query::Query;
use super::sync::{RotorReceiver, RotorSender};
use super::tcp::TcpTransport;
use super::udp::UdpTransport;


//------------ DnsTransport -------------------------------------------------

/// The rotor state machine for the DNS transport.
pub struct DnsTransport<X=Void>(Composition<X>);

impl<X> DnsTransport<X> {
    /// Creates a new DNS transport.
    ///
    /// Returns the transport and a resolver.
    pub fn new<S: GenericScope>(conf: ResolvConf, scope: &mut S)
                                -> (Self, Resolver) {
        let (dispatcher, tx) = Dispatcher::new(conf, scope);
        let resolver = Resolver::new(tx);
        (DnsTransport(Composition::Dispatcher(dispatcher)),
         resolver)
    }
}


impl<X> Machine for DnsTransport<X> {
    type Context = X;
    type Seed = BootstrapItem;

    fn create(seed: Self::Seed, scope: &mut Scope<Self::Context>)
              -> Response<Self, Void> {
        use super::dispatcher::BootstrapItem::*;

        match seed {
            Udp(s) => UdpTransport::create(s, scope)
                                   .map(|m| DnsTransport(Composition::Udp(m)),
                                        |_| unreachable!()),
            Tcp(s) => TcpTransport::create(s, scope)
                                   .map(|m| DnsTransport(Composition::Tcp(m)),
                                        |_| unreachable!()),
        }
    }

    fn ready(self, events: EventSet, scope: &mut Scope<Self::Context>)
             -> Response<Self, Self::Seed> {
        use self::Composition::*;

        match self.0 {
            Dispatcher(m) => m.ready(events, scope)
                              .map(|m| DnsTransport(Dispatcher(m)), |x| x),
            Udp(m) => m.ready(events, scope)
                       .map(|m| DnsTransport(Udp(m)), |_| unreachable!()),
            Tcp(m) => m.ready(events, scope)
                       .map(|m| DnsTransport(Tcp(m)), |_| unreachable!()),
        }
    }

    fn spawned(self, scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        use self::Composition::*;

        match self.0 {
            Dispatcher(m) => m.spawned(scope)
                              .map(|m| DnsTransport(Dispatcher(m)), |x| x),
            Udp(m) => m.spawned(scope)
                       .map(|m| DnsTransport(Udp(m)), |_| unreachable!()),
            Tcp(m) => m.spawned(scope)
                       .map(|m| DnsTransport(Tcp(m)), |_| unreachable!()),
        }
    }

    fn timeout(self, scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        use self::Composition::*;

        match self.0 {
            Dispatcher(m) => m.timeout(scope)
                              .map(|m| DnsTransport(Dispatcher(m)), |x| x),
            Udp(m) => m.timeout(scope)
                       .map(|m| DnsTransport(Udp(m)), |_| unreachable!()),
            Tcp(m) => m.timeout(scope)
                       .map(|m| DnsTransport(Tcp(m)), |_| unreachable!()),
        }
    }

    fn wakeup(self, scope: &mut Scope<Self::Context>)
              -> Response<Self, Self::Seed> {
        use self::Composition::*;

        match self.0 {
            Dispatcher(m) => m.wakeup(scope)
                              .map(|m| DnsTransport(Dispatcher(m)), |x| x),
            Udp(m) => m.wakeup(scope)
                       .map(|m| DnsTransport(Udp(m)), |_| unreachable!()),
            Tcp(m) => m.wakeup(scope)
                       .map(|m| DnsTransport(Tcp(m)), |_| unreachable!()),
        }
    }
}


//------------ Composition --------------------------------------------------

/// The composition of all our rotor state machines.
///
/// This is only for hiding internals.
enum Composition<X> {
    Dispatcher(Dispatcher<X>),
    Udp(UdpTransport<X>),
    Tcp(TcpTransport<X>),
}


//------------ Resolver -----------------------------------------------------

/// The resolver.
#[derive(Clone)]
pub struct Resolver {
    requests: RotorSender<Query>,
}

impl Resolver {
    fn new(requests: RotorSender<Query>) -> Self {
        Resolver { requests: requests }
    }

    /// Spawns a new DNS transport in a new thread.
    ///
    /// Returns the `JoinHandle` for this new thread and a resolver.
    pub fn spawn(conf: ResolvConf)
                 -> io::Result<(thread::JoinHandle<()>, Resolver)> {
        let mut loop_creator = try!(rotor::Loop::new(&rotor::Config::new()));
        let mut res = None;
        loop_creator.add_machine_with(|scope| {
            let (transport, resolver) = DnsTransport::new(conf, scope);
            res = Some(resolver);
            Response::ok(transport)
        }).unwrap(); // Only NoSlabSpace can happen which is fatal ...
        let child = thread::spawn(move || {
            loop_creator.run(()).ok();
        });
        Ok((child, res.unwrap()))
    }

    /// Processes a task synchronously, ie., waits for an answer.
    pub fn sync_task<T: Task>(&self, task: T)
                              -> Result<<T::Runner as TaskRunner>::Success> {
        let mut machine = try!(ResolverMachine::new(&self, task, None));
        loop {
            match machine.step() {
                Progress::Continue(m) => machine = m,
                Progress::Success(s) => return Ok(s),
                Progress::Error(e) => return Err(e)
            }
        }
    }

    /// Processes a task asynchronously by returning a machine.
    pub fn task<T: Task, X>(&self, task: T, scope: &mut Scope<X>)
                            -> Result<ResolverMachine<T>> {
        ResolverMachine::new(self, task, Some(scope.notifier()))
    }
}


//------------ ResolverMachine ----------------------------------------------

pub struct ResolverMachine<T: Task> {
    requests: RotorSender<Query>,
    receiver: RotorReceiver<Query>,
    runner: T::Runner,
}

impl<T: Task> ResolverMachine<T> {
    fn new(resolver: &Resolver, task: T, notifier: Option<Notifier>)
           -> Result<Self> {
        let requests = resolver.requests.clone();
        let receiver = RotorReceiver::new(notifier);
        let mut res = Ok(());
        let runner = task.start(|qname, qtype, qclass| {
            let message = match MessageBuf::query_from_question(qname, qtype,
                                                                qclass) {
                Ok(message) => message,
                Err(err) => { res = Err(err); return }
            };
            let query = Query::new(message, receiver.sender());
            requests.send(query).unwrap(); // XXX Handle error.
        });
        if let Err(err) = res {
            return Err(err.into());
        }
        Ok(ResolverMachine { requests: requests, receiver: receiver,
                             runner: runner })
    }

    pub fn wakeup(self) -> Progress<Self, <T::Runner as TaskRunner>::Success> {
        let query = match self.receiver.try_recv() {
            Ok(query) => query,
            Err(TryRecvError::Empty) => return Progress::Continue(self),
            Err(TryRecvError::Disconnected) => {
                return Progress::Error(Error::Timeout) // XXX Hmm.
            }
        };
        self.process(query)
    }

    fn step(self) -> Progress<Self, <T::Runner as TaskRunner>::Success> {
        let query = match self.receiver.recv() {
            Ok(query) => query,
            Err(..) => return Progress::Error(Error::Timeout),
        };
        self.process(query)
    }

    fn process(self, query: Query)
               -> Progress<Self, <T::Runner as TaskRunner>::Success> {
        match query.unravel() {
            Progress::Continue(request) => {
                let query = Query::new(request, self.receiver.sender());
                self.requests.send(query).unwrap(); // XXX
                Progress::Continue(self)
            }
            Progress::Success(response) => self.progress(response),
            Progress::Error((request, error)) => self.error(request, error),
        }
    }

    fn progress(self, response: MessageBuf)
                -> Progress<Self, <T::Runner as TaskRunner>::Success> {
        let (runner, receiver, requests) = (self.runner, self.receiver,
                                          self.requests);
        let mut res = Ok(());
        let progress = runner.progress(response, |qname, qtype, qclass| {
                let message = match MessageBuf::query_from_question(qname,
                                                                    qtype,
                                                                    qclass) {
                    Ok(message) => message,
                    Err(err) => { res = Err(err); return }
                };
                let query = Query::new(message, receiver.sender());
                requests.send(query).unwrap(); // XXX Handle error.
        });
        if let Err(err) = res {
            return Progress::Error(err.into())
        }
        match progress {
            Progress::Continue(runner) => {
                Progress::Continue(ResolverMachine { receiver: receiver,
                                                     requests: requests,
                                                     runner: runner })
            }
            Progress::Success(success) => Progress::Success(success),
            Progress::Error(err) => Progress::Error(err),
        }
    }

    fn error(self, request: MessageBuf, error: Error)
                -> Progress<Self, <T::Runner as TaskRunner>::Success> {
        let (runner, receiver, requests) = (self.runner, self.receiver,
                                          self.requests);
        let mut res = Ok(());
        let progress = runner.error(&request.first_question().unwrap(), error,
                                    |qname, qtype, qclass| {
                let message = match MessageBuf::query_from_question(qname,
                                                                    qtype,
                                                                    qclass) {
                    Ok(message) => message,
                    Err(err) => { res = Err(err); return }
                };
                let query = Query::new(message, receiver.sender());
                requests.send(query).unwrap(); // XXX Handle error.
        });
        if let Err(err) = res {
            return Progress::Error(err.into())
        }
        match progress {
            Progress::Continue(runner) => {
                Progress::Continue(ResolverMachine { receiver: receiver,
                                                     requests: requests,
                                                     runner: runner })
            }
            Progress::Success(success) => Progress::Success(success),
            Progress::Error(err) => Progress::Error(err),
        }
    }
}

