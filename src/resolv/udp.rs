/// UDP channel and transport.

use std::io;
use std::net::{IpAddr, SocketAddr};
use futures::{Async, AsyncSink, Poll, StartSend};
use tokio_core::net::UdpSocket;
use tokio_core::reactor;
use ::bits::MessageBuf;
use super::conf::ServerConf;
use super::request::{TransportHandle, TransportRequest};
use super::channel::Channel;
use super::transport::{TransportMode, spawn_transport};


//------------ udp_transport -------------------------------------------------

/// Spawns a new TCP transport for the given server config into a reactor.
///
/// Returns the transport handle for the TCP transport or `None` if TCP
/// was disabled for this server.
pub fn udp_transport(reactor: &reactor::Handle, conf: &ServerConf)
                     -> Option<TransportHandle> {
    let mode = match TransportMode::resolve(conf.udp,
                                         Some(TransportMode::Multiplex)) {
        Some(mode) => mode,
        None => return None,
    };
    let channel = UdpChannel::new(conf.addr, reactor.clone(), conf.recv_size);
    Some(spawn_transport(reactor, channel, mode, conf))
}


//------------ UdpChannel ----------------------------------------------------

/// A channel using UDP as the transport protocol.
///
/// Note that tokio_core currently does not support connecting UDP sockets so
/// we have to do some filtering on our side. This should probably be fixed.
struct UdpChannel {
    /// The address of the peer.
    peer: SocketAddr,

    /// A handle to reactor core to use for creating sockets.
    handle: reactor::Handle,

    /// The maximum size of an incoming message.
    recv_size: usize,

    /// The socket if we currently have one.
    sock: Option<UdpSocket>,

    /// The transport request we are currently trying to send, if any.
    wr: Option<TransportRequest>,
}

impl UdpChannel {
    /// Creates a new UDP channel.
    fn new(peer: SocketAddr, handle: reactor::Handle, recv_size: usize)
           -> Self {
        UdpChannel {
            peer: peer,
            handle: handle,
            recv_size: recv_size,
            sock: None,
            wr: None,
        }
    }
}


//--- Channel

impl Channel for UdpChannel {
    fn start_send(&mut self, request: TransportRequest)
                  -> StartSend<TransportRequest, io::Error> {
        if self.wr.is_some() {
            return Ok(AsyncSink::NotReady(request))
        }
        self.wr = Some(request);
        if self.sock.is_none() {
            let local = match self.peer {
                SocketAddr::V4(_)
                    => SocketAddr::new(IpAddr::V4(0.into()), 0),
                SocketAddr::V6(_)
                    => SocketAddr::new(IpAddr::V6([0;16].into()), 0)
            };
            self.sock = Some(UdpSocket::bind(&local, &self.handle)?);
        }
        Ok(AsyncSink::Ready)
    }

    fn poll_send(&mut self) -> Poll<Option<TransportRequest>, io::Error> {
        {
            let sock = match self.sock {
                Some(ref mut sock) => sock,
                None => return Ok(Async::Ready(None)),
            };
            let wr = match self.wr {
                Some(ref mut wr) => wr,
                None => return Ok(Async::Ready(None)),
            };
            let mut msg = wr.message();
            let buf = msg.dgram_bytes();
            let size = try_nb!(sock.send_to(buf, &self.peer));
            if size != buf.len() {
                // XXX Is this too drastic?
               return Err(io::Error::new(io::ErrorKind::Other, "short write"))
            }
        }
        Ok(Async::Ready(self.wr.take()))
    }

    fn poll_recv(&mut self) -> Poll<MessageBuf, io::Error> {
        let sock = match self.sock {
            Some(ref mut sock) => sock,
            None => return Ok(Async::NotReady)
        };
        loop {
            if let Async::NotReady = sock.poll_read() {
                return Ok(Async::NotReady)
            }
            let mut buf = vec![0u8; self.recv_size];
            let (size, addr) = try_nb!(sock.recv_from(&mut buf));
            if addr != self.peer {
                continue
            }
            buf.resize(size, 0);
            if let Ok(msg) = MessageBuf::from_vec(buf) {
                return Ok(Async::Ready(msg))
            }
        }
    }

    fn sleep(&mut self) -> Result<(), io::Error> {
        self.sock = None;
        self.wr = None;
        Ok(())
    }
}
