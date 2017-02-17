/// TCP channel and transport.

use std::io;
use std::net::SocketAddr;
use futures::{Poll, StartSend};
use tokio_core::net::{TcpStream, TcpStreamNew};
use tokio_core::reactor;
use ::bits::MessageBuf;
use super::conf::ServerConf;
use super::channel::{Channel, ConnectStream, StreamChannel};
use super::request::{TransportHandle, TransportRequest};
use super::transport::{TransportMode, spawn_transport};


//------------ tcp_transport -------------------------------------------------

/// Spawns a new TCP transport for the given server config into a reactor.
///
/// Returns the transport handle for the TCP transport or `None` if TCP
/// was disabled for this server.
pub fn tcp_transport(reactor: &reactor::Handle, conf: &ServerConf)
                     -> Option<TransportHandle> {
    let mode = match TransportMode::resolve(conf.tcp,
                                         Some(TransportMode::SingleRequest)) {
        Some(mode) => mode,
        None => return None,
    };
    let channel = TcpChannel::new(conf.addr, reactor.clone());
    Some(spawn_transport(reactor, channel, mode, conf))
}


//------------ TcpChannel ----------------------------------------------------

/// A channel using TCP as the transport protocol.
///
/// This is a simple wrapper around a `StreamChannel` using the `ConnectTCP`
/// connector defined below.
struct TcpChannel(StreamChannel<ConnectTcp>);

impl TcpChannel {
    /// Creates a new TCP channel using the given peer address and reactor.
    fn new(addr: SocketAddr, handle: reactor::Handle) -> Self {
        TcpChannel(StreamChannel::new(ConnectTcp{addr: addr, handle: handle}))
    }
}


//--- Channel

impl Channel for TcpChannel {
    fn start_send(&mut self, request: TransportRequest)
                  -> StartSend<TransportRequest, io::Error> {
        self.0.start_send(request)
    }
    
    fn poll_send(&mut self) -> Poll<Option<TransportRequest>, io::Error> {
        self.0.poll_send()
    }

    fn poll_recv(&mut self) -> Poll<MessageBuf, io::Error> {
        self.0.poll_recv()
    }

    fn sleep(&mut self) -> Result<(), io::Error> {
        self.0.sleep()
    }
}


//------------ ConnectTcp ----------------------------------------------------

/// A connector for a TCP peer.
struct ConnectTcp {
    /// The address of the peer.
    addr: SocketAddr,

    /// A reactor handle for starting the connecting process on.
    handle: reactor::Handle,
}


//--- ConnectStream

impl ConnectStream for ConnectTcp {
    type Stream = TcpStream;
    type Future = TcpStreamNew;

    fn connect(&self) -> Self::Future {
        TcpStream::connect(&self.addr, &self.handle)
    }
}

