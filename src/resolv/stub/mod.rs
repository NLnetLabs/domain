//! A DNS Resolver using rotor.

mod conn;
mod dispatcher;
mod query;
mod stream;
mod sync;
mod tcp;
mod timeout;
mod udp;

use rotor::{EventSet, GenericScope, Machine, Response, Scope, Void};
use resolv::conf::ResolvConf;
use self::dispatcher::{BootstrapItem, Dispatcher};
use self::query::Query;
use self::sync::RotorSender;
use self::tcp::TcpTransport;
use self::udp::UdpTransport;


//------------ DnsTransport -------------------------------------------------

/// The rotor state machine for the DNS transport.
pub struct DnsTransport<X>(Composition<X>);

impl<X> DnsTransport<X> {
    pub fn new_sync<S: GenericScope>(conf: ResolvConf, scope: &mut S)
                                -> (Self, Resolver) {
        let dispatcher = Dispatcher::new(conf, scope);
        let resolver = Resolver::new(dispatcher.query_sender());
        (DnsTransport(Composition::Dispatcher(dispatcher)),
         resolver)
    }
}


impl<X> Machine for DnsTransport<X> {
    type Context = X;
    type Seed = BootstrapItem;

    fn create(seed: Self::Seed, scope: &mut Scope<Self::Context>)
              -> Response<Self, Void> {
        use self::dispatcher::BootstrapItem::*;

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

}

