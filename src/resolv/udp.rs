//! UDP message service.

use std::cell::RefCell;
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use futures::{Async, Future, Poll};
use futures::stream::Stream;
use futures::task::TaskRc;
use tokio_core::net::UdpSocket;
use tokio_core::reactor;
use ::bits::MessageBuf;
use super::conf::ServerConf;
use super::request::{ServiceHandle, ServiceRequest};
use super::service::{Service, ServiceMode};
use super::transport::{Read, Transport, Write};


//------------ udp_service ---------------------------------------------------

/// Create a new DNS service using UDP as the transport.
pub fn udp_service(reactor: reactor::Handle, conf: &ServerConf)
                   -> io::Result<Option<ServiceHandle>> {
    let mode = match ServiceMode::resolve(conf.udp, ServiceMode::Multiplex) {
        Some(mode) => mode,
        None => return Ok(None)
    };
    let transport = UdpTransport::new(conf.addr);
    Service::spawn(reactor, transport, mode, conf).map(Some)
}


//------------ UdpTransport --------------------------------------------------

/// The transport for UDP.
pub struct UdpTransport {
    addr: SocketAddr,
}

impl UdpTransport {
    /// Creates a new UDP transport.
    pub fn new(addr: SocketAddr) -> Self {
        UdpTransport{addr: addr}
    }
}


//--- Transport

impl Transport for UdpTransport {
    type Read = UdpReader;
    type Write = UdpWriter;
    type Future = UdpTransportNew;

    fn create(&self, reactor: &reactor::Handle) -> io::Result<Self::Future> {
        DnsUdpSocket::connect(self.addr, reactor)
                     .map(|sock| UdpTransportNew(Some(sock)))
    }
}


//------------ UdpTransportNew -----------------------------------------------

/// The future for creating a new UDP transport “connection.”
pub struct UdpTransportNew(Option<DnsUdpSocket>);

impl Future for UdpTransportNew {
    type Item = (UdpReader, UdpWriter);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match self.0.take() {
            Some(sock) => {
                let rc = TaskRc::new(RefCell::new(sock));
                Ok((UdpReader::new(rc.clone()), UdpWriter::new(rc)).into())
            }
            None => panic!("poll on resolved UdpTransportNew")
        }
    }
}


//------------ DnsUdpSocket --------------------------------------------------

/// A UDP socket for sending and receiving DNS messages.
///
/// This wraps the actual UDP socket and provides the real functions that then
/// are used by the two halfes.
struct DnsUdpSocket {
    sock: UdpSocket,
    remote: SocketAddr,
    msg_size: usize,
}

impl DnsUdpSocket {
    /// Creates a new value from its components.
    fn new(sock: UdpSocket, remote: SocketAddr) -> Self {
        // XXX Set msg_size to 512. This is correct without EDNS support
        //     but we’ll have to fix this later.
        DnsUdpSocket{sock: sock, remote: remote, msg_size: 512}
    }

    /// Creates a new value from the remote address.
    ///
    /// Binds a UDP socket to either the V4 or V6 unspecified address.
    fn connect(remote: SocketAddr, reactor: &reactor::Handle)
               -> io::Result<Self> {
        let local = match remote {
            SocketAddr::V4(_)
                => SocketAddr::new(IpAddr::V4(0.into()), 0),
            SocketAddr::V6(_)
                => SocketAddr::new(IpAddr::V6([0;16].into()), 0)
        };
        let sock = try!(UdpSocket::bind(&local, reactor));
        Ok(Self::new(sock, remote))
    }

    /// Polls for writing.
    ///
    /// Attempts to send the given request.
    fn poll_write(&self, request: &mut ServiceRequest)
                  -> Poll<(), io::Error> {
        let buf = request.dgram_bytes();
        let size = try_nb!(self.sock.send_to(buf, &self.remote));
        if size == buf.len() {
            Ok(().into())
        }
        else {
            // XXX Is this too drastic?
            Err(io::Error::new(io::ErrorKind::Other, "short write"))
        }
    }

    /// Polls for reading.
    ///
    /// Ready returns a new message or `None` if the socket got closed
    /// (which shouldn’t really happen).
    fn poll_read(&self) -> Poll<Option<MessageBuf>, io::Error> {
        loop {
            if let Async::NotReady = self.sock.poll_read() {
                return Ok(Async::NotReady)
            }
            let mut buf = vec![0u8; self.msg_size];
            let (size, addr) = try_nb!(self.sock.recv_from(&mut buf));
            if addr != self.remote { continue }
            buf.resize(size, 0);
            if let Ok(msg) = MessageBuf::from_vec(buf) {
                return Ok(Some(msg).into())
            }
        }
    }
}


//------------ UdpReader -----------------------------------------------------

/// The read half of a UDP socket.
pub struct UdpReader {
    handle: TaskRc<RefCell<DnsUdpSocket>>
}

impl UdpReader {
    fn new(handle: TaskRc<RefCell<DnsUdpSocket>>) -> Self {
        UdpReader{handle: handle}
    }
}


//--- Read

impl Read for UdpReader { }


//--- Stream

impl Stream for UdpReader {
    type Item = MessageBuf;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        self.handle.with(|sock| sock.borrow_mut().poll_read()) 
    }
}


//------------ UdpWriter -----------------------------------------------------

/// The write half of a UDP socket.
pub struct UdpWriter {
    handle: TaskRc<RefCell<DnsUdpSocket>>
}

impl UdpWriter {
    fn new(handle: TaskRc<RefCell<DnsUdpSocket>>) -> Self {
        UdpWriter{handle: handle}
    }
}


//--- Write

impl Write for UdpWriter {
    type Future = UdpWriteRequest;

    fn write(self, request: ServiceRequest) -> Self::Future {
        UdpWriteRequest {
            state: State::Writing {
                w: self,
                req: request
            }
        }
    }
}


//------------ UdpWriteRequest -----------------------------------------------

/// The write future for a UDP socket.
pub struct UdpWriteRequest {
    state: State
}

enum State {
    Writing {
        w: UdpWriter,
        req: ServiceRequest
    },
    Done
}


impl Future for UdpWriteRequest {
    type Item = (UdpWriter, ServiceRequest);
    type Error = (io::Error, ServiceRequest);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let res = match self.state {
            State::Writing{ref mut w, ref mut req} => {
                match w.handle.with(|w| w.borrow_mut().poll_write(req)) {
                    Ok(Async::NotReady) => return Ok(Async::NotReady),
                    Ok(Async::Ready(())) => Ok(()),
                    Err(err) => Err(err)
                }
            }
            State::Done => panic!("polling a resolved UdpWriteRequest")
        };
        match mem::replace(&mut self.state, State::Done) {
            State::Writing{w, req} => {
                match res {
                    Ok(()) => Ok(Async::Ready((w, req))),
                    Err(err) => Err((err, req))
                }
            }
            State::Done => panic!()
        }
    }
}

