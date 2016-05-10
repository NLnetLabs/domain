//! The query dispatcher for the rotor-based resolver.

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::mpsc;
use rotor::{EventSet, GenericScope, Machine, Response, Scope, Void};
use resolv::conf::ResolvConf;
use resolv::error::Error;
use super::conn::{ConnCommand, ConnTransportSeed};
use super::query::Query;
use super::sync::{RotorReceiver, RotorSender, SharedNotifier, channel};
use super::udp::{UdpCommand, UdpTransportSeed};


//------------ Dispatcher ---------------------------------------------------

/// The dispatcher of queries. Holds the whole thing together.
pub struct Dispatcher<X> {
    /// The current configuration.
    conf: ResolvConf,

    /// The query queue.
    ///
    /// Resolvers will place their queries here. If this queue disconnects,
    /// the dispatcher will close.
    queries: mpsc::Receiver<Query>,

    /// The failed query queue.
    ///
    /// Transports will return failed queries into here. We need a
    /// separate queue for this since we need to be able to spawn new
    /// transports and, subsequently, need to hold a sender to clone in
    /// this case. Because of that, the queue will never disconnect.
    failed: RotorReceiver<Query>,

    /// Are we in bootstrap state?
    bootstrap: Option<DispatcherBootstrap>,

    /// All our datagram servers in order.
    dgram_servers: Vec<Server>,

    /// Index of the datagram server to use as first server.
    dgram_start: usize,

    /// All our stream servers in order.
    stream_servers: Vec<Server>,

    /// Index of the stream server to use as first server.
    stream_start: usize,

    /// Marker for X.
    phantom: PhantomData<X>,
}


/// "Public" Interface
///
impl<X> Dispatcher<X> {
    /// Creates a new dispatcher from the given configuration.
    pub fn new<S: GenericScope>(conf: ResolvConf, scope: &mut S)
                                -> (Self, RotorSender<Query>) {
        let (tx, rx) = channel(Some(scope.notifier()));
        let mut res = Dispatcher {
            conf: conf,
            queries: rx,
            failed: RotorReceiver::new(Some(scope.notifier())),
            bootstrap: None,
            dgram_servers: Vec::new(),
            dgram_start: 0,
            stream_servers: Vec::new(),
            stream_start: 0,
            phantom: PhantomData,
        };
        res.configure();
        scope.notifier().wakeup().unwrap();
        (res, tx)
    }

    /*
    /// Reconfigure the dispatcher.
    ///
    /// Closes and removes all current servers, updates the configuration and
    /// then recreates new servers. This could probably be smarter by keeping
    /// servers that we already have. But then we’d need to possibly tell
    /// them about the changed config and all becomes complex. So let’s be
    /// lazy. It ain’t that expensive, anyway.
    pub fn reconfigure(&mut self, conf: ResolvConf) {
        self.close();
        self.conf = conf;
        self.configure();
    }
    */
}


///  Internal Helpers
///
impl<X> Dispatcher<X> {
    /// Close all underlying transports.
    fn close(&mut self) {
        for server in self.dgram_servers.drain(..) {
            server.close()
        }
        for server in self.stream_servers.drain(..) {
            server.close()
        }
    }

    /// Reconfigures the dispatcher to the current config
    ///
    /// Goes through the server list and creates a UDP and TCP server for
    /// each of them.
    fn configure(&mut self) {
        let mut bs = DispatcherBootstrap::new();
        let (udp4, udp4_tx) = UdpTransportSeed::new(self.conf.clone(),
                                                    self.failed.sender(),
                                                    false);
        let mut use_udp4 = false;
        let (udp6, udp6_tx) = UdpTransportSeed::new(self.conf.clone(),
                                                    self.failed.sender(),
                                                    true);
        let mut use_udp6 = false;
        for addr in self.conf.servers.iter() {
            let (tcp, tcp_tx) = ConnTransportSeed::new(self.conf.clone(),
                                                       addr.clone(),
                                                       self.failed.sender());
            self.stream_servers.push(Server::Other(tcp_tx.clone(),
                                                   tcp.notifier()));
            let server = match addr {
                &SocketAddr::V4(_) => {
                    use_udp4 = true;
                    Server::Udp(udp4_tx.clone(), addr.clone(),
                                udp4.notifier())
                }
                &SocketAddr::V6(_) => {
                    use_udp6 = true;
                    Server::Udp(udp6_tx.clone(), addr.clone(),
                                udp6.notifier())
                }
            };
            self.dgram_servers.push(server);
            bs.push_tcp(tcp)
        }
        if use_udp4 { bs.push_udp(udp4); }
        if use_udp6 { bs.push_udp(udp6); }
        self.bootstrap = Some(bs)
    }

    /// Dispatch a query.
    fn dispatch(&mut self, mut query: Query) {
        if query.has_started() {
            if query.is_truncated() {
                if !query.is_dgram() || self.conf.options.ign_tc {
                    query.send()
                }
                else {
                    let start = self.next_stream();
                    query.start(false, start);
                    self.stream_servers[start].query(query)
                }
            }
            else if let &Some(_) = query.response() { 
                query.send()
            }
            else if query.is_dgram() {
                if let Some(index) = query.next(self.dgram_servers.len()) {
                    self.dgram_servers[index].query(query);
                }
                else {
                    let onwards = query.new_attempt(self.conf.attempts);
                    if onwards {
                        let start = self.next_dgram();
                        query.restart(start);
                        self.dgram_servers[start].query(query);
                    }
                    else {
                        query.set_response(Err(Error::Timeout));
                        query.send();
                    }
                }
            }
            else {
                if let Some(index) = query.next(self.stream_servers.len()) {
                    self.stream_servers[index].query(query)
                }
                else {
                    let onwards = query.new_attempt(self.conf.attempts);
                    if onwards {
                        let start = self.next_stream();
                        query.restart(start);
                        self.stream_servers[start].query(query);
                    }
                    else {
                        query.set_response(Err(Error::Timeout));
                        query.send();
                    }
                }
            }
        }
        else {
            if self.conf.options.use_vc {
                let start = self.next_stream();
                query.start(false, start);
                self.stream_servers[start].query(query);
            }
            else {
                let start = self.next_dgram();
                query.start(true, start);
                self.dgram_servers[start].query(query);
            }
        }
    }

    /// Get dgram server to start with.
    fn next_dgram(&mut self) -> usize {
        if self.conf.options.rotate {
            self.dgram_start = (self.dgram_start + 1)
                                    % self.dgram_servers.len();
            self.dgram_start
        }
        else {
            0
        }
    }

    /// Get stream start index.
    fn next_stream(&mut self) -> usize {
        if self.conf.options.rotate {
            self.stream_start = (self.stream_start + 1)
                                    % self.stream_servers.len();
            self.stream_start
        }
        else {
            0
        }
    }
}


impl<X> Machine for Dispatcher<X> {
    type Context = X;
    type Seed = BootstrapItem;

    fn create(_seed: Self::Seed, _scope: &mut Scope<Self::Context>)
              -> Response<Self, Void> {
        unreachable!();
    }

    fn ready(self, _events: EventSet, _scope: &mut Scope<Self::Context>)
             -> Response<Self, Self::Seed> {
        unreachable!();
    }

    fn spawned(self, _scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        Response::ok(self)
    }

    fn timeout(self, _scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        unreachable!();
    }

    fn wakeup(mut self, scope: &mut Scope<Self::Context>)
              -> Response<Self, Self::Seed> {
        if let Some(Some(item)) = self.bootstrap.as_mut().map(|x| x.pop()) {
            let _ = scope.notifier().wakeup();
            Response::spawn(self, item)
        }
        else {
            loop {
                match self.queries.try_recv() {
                    Ok(query) => self.dispatch(query),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.close();
                        return Response::done();
                    }
                }
            }
            loop {
                match self.failed.try_recv() {
                    Ok(query) => self.dispatch(query),
                    _ => break,
                }
            }
            return Response::ok(self);
        }
    }
}



//------------ DispatcherBootstrap ------------------------------------------

/// A type containing the state of the dispatcher bootstrap.
///
/// Since we can only create one state machine per event, we need to
/// repeatedly wake ourselves up during bootstrap to create one machine
/// after another. This type contains a list of all the transports we need
/// to create.
struct DispatcherBootstrap(Vec<BootstrapItem>);

pub enum BootstrapItem {
    Udp(UdpTransportSeed),
    Tcp(ConnTransportSeed)
}

impl DispatcherBootstrap {
    fn new() -> Self {
        DispatcherBootstrap(Vec::new())
    }

    fn push(&mut self, item: BootstrapItem) {
        self.0.push(item)
    }

    fn push_udp(&mut self, seed: UdpTransportSeed) {
        self.push(BootstrapItem::Udp(seed))
    }

    fn push_tcp(&mut self, seed: ConnTransportSeed) {
        self.push(BootstrapItem::Tcp(seed))
    }

    fn pop(&mut self) -> Option<BootstrapItem> {
        self.0.pop()
    }
}


//------------ Server -------------------------------------------------------

/// A DNS server representation.
///
/// This type represents one of the configured DNS servers spoken to with
/// a specific protocol.
enum Server {
    /// A server reachable via (unencrypted) UDP.
    ///
    /// Contains the queue, the server address, and the notifier for
    /// waking up the state machine.
    Udp(mpsc::Sender<UdpCommand>, SocketAddr, SharedNotifier),

    /// An server on any other transport.
    ///
    /// Contains the queue and the notifier for waking up the state machine.
    Other(mpsc::Sender<ConnCommand>, SharedNotifier),
}

impl Server {
    /// Send a query to the server.
    fn query(&self, query: Query) {
        match self {
            &Server::Udp(ref sender, ref addr, ref notifier) => {
                sender.send(UdpCommand::Query(query, addr.clone())).unwrap();
                notifier.wakeup();
            }
            &Server::Other(ref sender, ref notifier) => {
                sender.send(ConnCommand::Query(query)).unwrap();
                notifier.wakeup();
            }
        }
    }

    /// Close the transport.
    fn close(self) {
        match self {
            Server::Udp(sender, _, notifier) => {
                if let Ok(_) = sender.send(UdpCommand::Close) {
                    notifier.wakeup();
                }

            }
            Server::Other(sender, notifier) => {
                if let Ok(_) = sender.send(ConnCommand::Close) {
                    notifier.wakeup();
                }
            }
        }
    }
}

