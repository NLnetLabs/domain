//! The UDP transport for the rotor-based DNS transport.

use std::collections::HashMap;
use std::io;
use std::marker::PhantomData;
use std::net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc;
use rand::random;
use rotor::{EventSet, Machine, PollOpt, Response, Scope, Void};
use rotor::mio::udp::UdpSocket;
use bits::message::{Message, MessageBuf};
use resolv::conf::ResolvConf;
use super::sync::{RotorSender, SharedNotifier};
use super::query::Query;
use super::timeout::TimeoutQueue;


//------------ UdpTransportSeed ---------------------------------------------

/// The seed for a UDP transport.
pub struct UdpTransportSeed {
    /// Configuration
    conf: ResolvConf,

    /// The receiving end of the command queue.
    commands: mpsc::Receiver<UdpCommand>,

    /// A sending end of the query queue.
    queries: RotorSender<Query>,

    /// A place to put a notifier.
    notifier: SharedNotifier,

    /// Are we going to be for IPv6?
    ipv6: bool,
}

impl UdpTransportSeed {
    pub fn new(conf: ResolvConf, queries: RotorSender<Query>, ipv6: bool)
               -> (UdpTransportSeed, mpsc::Sender<UdpCommand>) {
        let (tx, rx) = mpsc::channel();
        (UdpTransportSeed { conf: conf, commands: rx, queries: queries,
                            notifier: SharedNotifier::new(), ipv6: ipv6 },
         tx)
    }

    pub fn notifier(&self) -> SharedNotifier {
        self.notifier.clone()
    }
}


//------------ UdpCommand ---------------------------------------------------

/// A command for the UDP transport.
pub enum UdpCommand {
    /// Perform the given query.
    Query(Query, SocketAddr),

    /// Close the transport.
    Close
}


//------------ UdpQuery -----------------------------------------------------

/// A query that is currently being asked to a UDP server.
struct UdpQuery {
    query: Query,
    addr: SocketAddr,
}

impl UdpQuery {
    fn new(query: Query, addr: SocketAddr) -> UdpQuery {
        UdpQuery { query: query, addr: addr }
    }

    fn id(&self) -> u16 {
        self.query.request().header().id()
    }

    fn is_answer(&self, msg: &Message, addr: &SocketAddr) -> bool {
        self.addr == *addr && msg.is_answer(self.query.request())
    }
}


//------------ UdpTransport -------------------------------------------------

/// A rotor state machine for a UDP transport.
pub struct UdpTransport<X> {
    /// The socket for sending and receiving.
    ///
    /// This is an option since we’ll stick around even if opening the socket
    /// fails. In this case we'll just return an error to each and every
    /// query.
    sock: Option<UdpSocket>,

    /// All my pending queries.
    queries: HashMap<u16, UdpQuery>,

    /// The timeouts for the pending queries represented by their ID.
    timeouts: TimeoutQueue<u16>,

    /// The receiving end of the command queue.
    commands: mpsc::Receiver<UdpCommand>,

    /// The sending end of the dispatcher’s query queue.
    ///
    /// All failed queries go back there.
    failed: RotorSender<Query>,

    /// The configuration.
    conf: ResolvConf,
    max_size: usize,

    /// Are we closing?
    closing: bool,

    /// The Context Phantom.
    phantom: PhantomData<X>,
}

/// # Creation
///
impl<X> UdpTransport<X> {
    /// Creates a new transport from a seed and a scope.
    pub fn new(seed: UdpTransportSeed, scope: &mut Scope<X>) -> Self {
        let addr = if seed.ipv6 { IpAddr::V6(Ipv6Addr::new(0,0,0,0,0,0,0,0)) }
                   else { IpAddr::V4(Ipv4Addr::new(0,0,0,0)) };
        seed.notifier.set(scope.notifier());
        let res = UdpTransport {
            sock: UdpSocket::bound(&SocketAddr::new(addr, 0)).ok(),
            queries: HashMap::new(),
            timeouts: TimeoutQueue::new(),
            commands: seed.commands,
            failed: seed.queries,
            conf: seed.conf,
            max_size: 1280, // XXX Hardcoded pending conf reorganisation
            closing: false,
            phantom: PhantomData
        };
        if let Some(ref sock) = res.sock {
            scope.register(sock, EventSet::readable(),
                           PollOpt::level()).unwrap();
        }
        res
    }
}

/// # Processing
///
impl<X> UdpTransport<X> {
    /// Processes all commands in the command queues.
    fn command(&mut self, scope: &mut Scope<X>) {
        loop {
            let command = match self.commands.try_recv() {
                Ok(command) => command,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.close(scope);
                    break;
                }
                Err(mpsc::TryRecvError::Empty) => break,
            };
            match command {
                UdpCommand::Query(query, addr)
                    => self.send_query(query, addr, scope),
                UdpCommand::Close
                    => self.close(scope),
            }
        }
    }

    /// Processes `UdpCommand::Query`.
    fn send_query(&mut self, mut query: Query, addr: SocketAddr,
                  scope: &mut Scope<X>) {
        if self.sock.is_none() {
            self.failed.send(query).ok();
        }
        else {
            let mut id = random();
            while self.queries.contains_key(&id) {
                id = random()
            }
            query.request_mut().header_mut().set_id(id);
            match self.sock.as_ref().unwrap().send_to(query.request_data(),
                                                      &addr) {
                Ok(_) => {
                    self.queries.insert(id, UdpQuery::new(query, addr));
                    self.timeouts.push(scope.now() + self.conf.timeout, id);
                }
                Err(_) => {
                    // XXX Log or report back.
                    self.failed.send(query).ok();
                }
            }
        }
    }

    /// Processes `UdpCommand::Close`.
    fn close(&mut self, _scope: &mut Scope<X>) {
        if !self.closing {
            loop {
                match self.commands.try_recv() {
                    Ok(UdpCommand::Query(query, _)) => {
                        self.failed.send(query).ok();
                    }
                    Ok(_) => (),
                    Err(_) => break,
                }
            }
            let (_, rx) = mpsc::channel();
            self.commands = rx;
            self.closing = true;
        }
    }

    /// Receives incoming data.
    fn recv(&mut self) {
        while self.sock.is_some() {
            let mut buf = vec![0u8; self.max_size];
            let (len, addr) = match self.sock.as_ref().unwrap()
                                             .recv_from(&mut buf) {
                Ok(Some((len, addr))) => (len, addr),
                Ok(None) => break,
                Err(ref err) if err.kind() == io::ErrorKind::Interrupted
                    => continue,
                Err(_) => break, // XXX Do something! OH MY GOD!!!
            };
            buf.resize(len, 0);
            let message = match MessageBuf::from_vec(buf) {
                Ok(message) => message,
                Err(_) => continue, // XXX Log
            };
            let mut query = match self.queries.remove(&message.header().id()) {
                Some(query) => query,
                None => continue, // XXX Log
            };
            if !query.is_answer(&message, &addr) {
                self.queries.insert(query.id(), query);
                continue; // XXX Log
            }
            query.query.set_response(Ok(message));
            query.query.send()
        }
    }

    /// Processes expired queries.
    fn expire(&mut self, scope: &mut Scope<X>) {
        while let Some(id) = self.timeouts.pop_expired(scope.now()) {
            self.failed.send(self.queries.remove(&id).unwrap().query).ok();
        }
    }

    /// Returns an ok response.
    fn ok(mut self) -> Response<Self, UdpTransportSeed> {
        {
            let (timeouts, queries) = (&mut self.timeouts, &self.queries);
            timeouts.clean_head(|x| !queries.contains_key(&x));
        }
        if self.closing && self.queries.is_empty() {
            Response::done()
        }
        else {
            match self.timeouts.next_timeout() {
                None => Response::ok(self),
                Some(timeout) => {
                    Response::ok(self).deadline(timeout)
                }
            }
        }
    }
}


//--- Machine

impl<X> Machine for UdpTransport<X> {
    type Context = X;
    type Seed = UdpTransportSeed;

    fn create(seed: Self::Seed, scope: &mut Scope<Self::Context>)
              -> Response<Self, Void> {
        Response::ok(UdpTransport::new(seed, scope))
    }

    fn ready(mut self, _events: EventSet, scope: &mut Scope<Self::Context>)
             -> Response<Self, Self::Seed> {
        self.recv();
        self.expire(scope);
        self.ok()
    }

    fn spawned(self, _scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        unreachable!();
    }

    fn timeout(mut self, scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        self.expire(scope);
        self.ok()
    }

    fn wakeup(mut self, scope: &mut Scope<Self::Context>)
              -> Response<Self, Self::Seed> {
        self.command(scope);
        self.ok()
    }
}

