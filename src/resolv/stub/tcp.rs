//! The TCP transport for the rotor-based DNS transport.

use std::io;
use std::marker::PhantomData;
use std::net::SocketAddr;
use rotor::{EventSet, Machine, PollOpt, Response, Scope, Time, Void};
use rotor::mio::tcp::TcpStream;
use super::conn::ConnTransportSeed;
use super::stream::{StreamReader, StreamTransportInfo};


//------------ TcpTransport -------------------------------------------------

/// A rotor state machine for a TCP transport.
pub struct TcpTransport<X>(State<X>);


impl<X> TcpTransport<X> {
    pub fn new(seed: ConnTransportSeed, scope: &mut Scope<X>) -> Self {
        seed.notifier.set(scope.notifier());
        Idle::new(StreamTransportInfo::new(seed))
    }
}


//--- Machine

impl<X> Machine for TcpTransport<X> {
    type Context = X;
    type Seed = ConnTransportSeed;

    fn create(seed: Self::Seed, scope: &mut Scope<Self::Context>)
              -> Response<Self, Void> {
        Response::ok(TcpTransport::new(seed, scope))
    }

    fn ready(self, events: EventSet, scope: &mut Scope<Self::Context>)
             -> Response<Self, Self::Seed> {
        match self.0 {
            State::Idle(idle) => idle.ready(events, scope),
            State::Connecting(connecting) => connecting.ready(events, scope),
            State::Connected(connected) => connected.ready(events, scope),
            State::Empty(empty) => empty.ready(events, scope),
            State::Closing(closing) => closing.ready(events, scope),
            State::Failed(failed) => failed.ready(events, scope),
        }
    }

    fn spawned(self, _scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        unreachable!();
    }

    fn timeout(self, scope: &mut Scope<Self::Context>)
               -> Response<Self, Self::Seed> {
        match self.0 {
            State::Idle(idle) => idle.timeout(scope),
            State::Connecting(connecting) => connecting.timeout(scope),
            State::Connected(connected) => connected.timeout(scope),
            State::Empty(empty) => empty.timeout(scope),
            State::Closing(closing) => closing.timeout(scope),
            State::Failed(failed) => failed.timeout(scope),
        }
    }

    fn wakeup(self, scope: &mut Scope<Self::Context>)
              -> Response<Self, Self::Seed> {
        match self.0 {
            State::Idle(idle) => idle.wakeup(scope),
            State::Connecting(connecting) => connecting.wakeup(scope),
            State::Connected(connected) => connected.wakeup(scope),
            State::Empty(empty) => empty.wakeup(scope),
            State::Closing(closing) => closing.wakeup(scope),
            State::Failed(failed) => failed.wakeup(scope),
        }
    }
}


//------------ State --------------------------------------------------------

/// The actual state machine.
///
/// We only wrap this up so we don’t need to pub the various inner types.
enum State<X> {
    /// We don’t have a connection but we could.
    Idle(Idle<X>),

    /// We are currently connecting.
    Connecting(Connecting<X>),

    /// We are connected and ready to send and receive.
    Connected(Connected<X>),

    /// We are connected but all our queues are empty.
    Empty(Empty<X>),

    /// We’ve been asked to finish up.
    Closing(Closing<X>),

    /// We’ve gone kaputt.
    Failed(Failed<X>),
}


//------------ Idle ---------------------------------------------------------

/// Idle state.
///
/// In this state, we have no pending queries and no socket. If we are woken
/// up, we go and connect, thereby transitioning into connecting state.
struct Idle<X> {
    info: StreamTransportInfo,
    phantom: PhantomData<X>,
}

impl<X> Idle<X> {
    fn new(info: StreamTransportInfo) -> TcpTransport<X> {
        TcpTransport(State::Idle(Idle { info: info, phantom: PhantomData }))
    }

    fn ready(self, _events: EventSet, _scope: &mut Scope<X>)
             -> Response<TcpTransport<X>, ConnTransportSeed> {
        unreachable!()
    }

    fn timeout(self, _scope: &mut Scope<X>)
               -> Response<TcpTransport<X>, ConnTransportSeed> {
        unreachable!()
    }

    fn wakeup(mut self, scope: &mut Scope<X>)
              -> Response<TcpTransport<X>, ConnTransportSeed> {
        let close = self.info.process_commands();
        if self.info.can_write() {
            Response::ok(Connecting::new(self.info, scope))
        }
        else if close {
            Response::done()
        }
        else {
            Response::ok(self.into())
        }
    }
}

impl<X> From<Idle<X>> for TcpTransport<X> {
    fn from(idle: Idle<X>) -> Self { TcpTransport(State::Idle(idle)) }
}


//------------ Connecting ---------------------------------------------------

/// Connecting state.
///
/// During connecting state we have a socket which is currently connecting.
/// Upon becoming ready, we transition into connected state and let that
/// state process the ready event.
struct Connecting<X> {
    sock: TcpStream,
    info: StreamTransportInfo,
    phantom: PhantomData<X>,
}

impl<X> Connecting<X> {
    fn new(info: StreamTransportInfo, scope: &mut Scope<X>)
           -> TcpTransport<X> {
        let sock = match Connecting::try_connect(&info.addr(), scope) {
            Ok(sock) => sock,
            Err(_) => return Failed::new(info),
        };
        TcpTransport(
            State::Connecting(
                Connecting {
                    sock: sock,
                    info: info,
                    phantom: PhantomData,
                }
            )
        )
    }

    fn try_connect(addr: &SocketAddr, scope: &mut Scope<X>)
                   -> io::Result<TcpStream> {
        let sock = try!(TcpStream::connect(addr));
        try!(scope.register(&sock, EventSet::writable(),
                            PollOpt::edge() | PollOpt::oneshot()));
        Ok(sock)
    }

    fn ready(self, events: EventSet, scope: &mut Scope<X>)
             -> Response<TcpTransport<X>, ConnTransportSeed> {
        Connected::new(self.sock, self.info).ready(events, scope)
    }

    fn timeout(self, _scope: &mut Scope<X>)
               -> Response<TcpTransport<X>, ConnTransportSeed> {
        unreachable!()
    }

    fn wakeup(self, _scope: &mut Scope<X>)
              -> Response<TcpTransport<X>, ConnTransportSeed> {
        Response::ok(TcpTransport(State::Connecting(self)))
    }
}


//------------ Connected ----------------------------------------------------

/// Connected state.
///
/// This is where we actually do some work.
struct Connected<X> {
    sock: TcpStream,
    reader: StreamReader,
    info: StreamTransportInfo,
    phantom: PhantomData<X>,
}

impl<X> Connected<X> {
    fn new(sock: TcpStream, info: StreamTransportInfo) -> TcpTransport<X> {
        TcpTransport(
            State::Connected(
                Connected {
                    sock: sock,
                    reader: StreamReader::new(),
                    info: info,
                    phantom: PhantomData,
                }
            )
        )
    }

    fn ok(self) -> Response<TcpTransport<X>, ConnTransportSeed> {
        Response::ok(TcpTransport(State::Connected(self)))
    }

    fn failed(self, scope: &mut Scope<X>)
              -> Response<TcpTransport<X>, ConnTransportSeed> {
        scope.deregister(&self.sock).ok();
        Response::ok(Failed::new(self.info))
    }

    fn ready(mut self, events: EventSet, scope: &mut Scope<X>)
             -> Response<TcpTransport<X>, ConnTransportSeed> {
        if events.is_readable() {
            match self.reader.read(&mut self.sock) {
                Ok(Some(message)) => self.info.process_response(message),
                Ok(None) => (),
                Err(_) => return self.failed(scope),
            }
        }
        if events.is_writable() {
            match self.info.write(&mut self.sock, scope.now()) {
                Ok(()) => (),
                Err(_) => return self.failed(scope),
            }
        }
        self.wakeup(scope)
    }

    fn wakeup(mut self, scope: &mut Scope<X>)
              -> Response<TcpTransport<X>, ConnTransportSeed> {
        if self.info.process_commands() {
            Response::ok(Closing::new(self.sock, self.reader, self.info))
        }
        else {
            self.timeout(scope)
        }
    }

    fn timeout(mut self, scope: &mut Scope<X>)
               -> Response<TcpTransport<X>, ConnTransportSeed> {
        self.info.process_timeouts(scope.now());
        if self.info.can_read() || self.info.can_write() {
            let events = { 
                if self.info.can_read() {
                    if self.info.can_write() {
                        EventSet::readable() | EventSet::writable()
                    }
                    else { EventSet::readable() }
                }
                else { EventSet::writable() }
            };
            match scope.reregister(&self.sock, events,
                                   PollOpt::edge() | PollOpt::oneshot()) {
                Ok(()) => (),
                Err(..) => return Response::ok(Failed::new(self.info))
            }
            match self.info.next_timeout() {
                Some(timeout) => self.ok().deadline(timeout),
                None => self.ok()
            }
        }
        else {
            Empty::new(self.sock, self.info, scope).ok()
        }
    }
}


//------------ Empty --------------------------------------------------------

/// Empty state.
///
/// We have a working connection but nothing to do. We wait for the
/// idle_timeout to pass. If we are woken up by then, we return into
/// connected state. Otherwise we go to idle state, thereby dropping our
/// connection.
struct Empty<X> {
    sock: TcpStream,
    info: StreamTransportInfo,
    idle_timeout: Time,
    phantom: PhantomData<X>,
}

impl<X> Empty<X> {
    fn new(sock: TcpStream, info: StreamTransportInfo, scope: &mut Scope<X>)
           -> Self {
        let timeout = scope.now() + info.conf().idle_timeout;
        Empty { sock: sock, info: info, idle_timeout: timeout,
                phantom: PhantomData }
    }

    fn ok(self) -> Response<TcpTransport<X>, ConnTransportSeed> {
        let timeout = self.idle_timeout;
        Response::ok(TcpTransport(State::Empty(self))).deadline(timeout)
    }

    fn ready(self, _events: EventSet, _scope: &mut Scope<X>)
             -> Response<TcpTransport<X>, ConnTransportSeed> {
        unreachable!()
    }

    fn wakeup(self, scope: &mut Scope<X>)
              -> Response<TcpTransport<X>, ConnTransportSeed> {
        Connected::new(self.sock, self.info).wakeup(scope)
    }

    fn timeout(self, scope: &mut Scope<X>)
               -> Response<TcpTransport<X>, ConnTransportSeed> {
        if self.idle_timeout < scope.now() {
            Response::ok(Idle::new(self.info))
        }
        else {
            self.ok()
        }
    }
}



//------------ Closing ------------------------------------------------------

/// Closing state.
///
/// We have been told to close. We will keep reading until all pending
/// queries are either resolved or time out. We will refuse any new queries.
/// Once there are no more pending queries, we are done.
struct Closing<X> {
    sock: TcpStream,
    reader: StreamReader,
    info: StreamTransportInfo,
    phantom: PhantomData<X>,
}

impl<X> Closing<X> {
    fn new(sock: TcpStream, reader: StreamReader, info: StreamTransportInfo)
           -> TcpTransport<X> {
        let mut res = Closing { sock: sock, reader: reader, info: info,
                                phantom: PhantomData };
        res.info.reject_commands();
        TcpTransport(State::Closing(res))
    }

    fn ok(self) -> Response<TcpTransport<X>, ConnTransportSeed> {
        Response::ok(TcpTransport(State::Closing(self)))
    }

    fn failed(mut self, scope: &mut Scope<X>)
              -> Response<TcpTransport<X>, ConnTransportSeed> {
        self.info.flush_timeouts();
        scope.deregister(&self.sock).ok();
        Response::done()
    }

    fn ready(mut self, events: EventSet, scope: &mut Scope<X>)
             -> Response<TcpTransport<X>, ConnTransportSeed> {
        if events.is_readable() {
            match self.reader.read(&mut self.sock) {
                Ok(Some(message)) => self.info.process_response(message),
                Ok(None) => (),
                Err(_) => return self.failed(scope),
            }
        }
        self.wakeup(scope)
    }

    fn wakeup(mut self, scope: &mut Scope<X>)
              -> Response<TcpTransport<X>, ConnTransportSeed> {
        self.info.reject_commands();
        self.timeout(scope)
    }

    fn timeout(mut self, scope: &mut Scope<X>)
               -> Response<TcpTransport<X>, ConnTransportSeed> {
        self.info.process_timeouts(scope.now());
        if self.info.can_read() {
            match scope.reregister(&self.sock, EventSet::readable(),
                                   PollOpt::edge() | PollOpt::oneshot()) {
                Ok(()) => (),
                Err(..) =>  return self.failed(scope),
            }
            match self.info.next_timeout() {
                Some(timeout) => self.ok().deadline(timeout),
                None => self.ok()
            }
        }
        else {
            Response::done()
        }
    }
}


//------------ Failed -------------------------------------------------------

/// Failed state.
///
/// The connection has failed for whatever reason. We’re not doing anything
/// anymore until we are told to close.
struct Failed<X> {
    info: StreamTransportInfo,
    phantom: PhantomData<X>,
}

impl<X> Failed<X> {
    fn new(info: StreamTransportInfo) -> TcpTransport<X> {
        TcpTransport(
            State::Failed(
                Failed {
                    info: info, phantom: PhantomData
                }
            )
        )
    }

    fn ready(self, _events: EventSet, _scope: &mut Scope<X>)
             -> Response<TcpTransport<X>, ConnTransportSeed> {
        unreachable!()
    }

    fn wakeup(mut self, _scope: &mut Scope<X>)
              -> Response<TcpTransport<X>, ConnTransportSeed> {
        if self.info.reject_commands() {
            Response::done()
        }
        else {
            Response::ok(TcpTransport(State::Failed(self)))
        }
    }

    fn timeout(self, _scope: &mut Scope<X>)
               -> Response<TcpTransport<X>, ConnTransportSeed> {
        unreachable!()
    }
}
