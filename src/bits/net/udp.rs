//! Sending and receiving via UDP.

use std::{io, mem};
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use futures::Async;
use futures::stream::Stream;
use tokio_core::reactor;
use tokio_core::net::UdpSocket;
use ::bits::{ComposeMode, MessageBuf};
use super::Flow;
use super::mpsc::{Receiver, Sender, channel};


//------------ UdpServer -----------------------------------------------------

pub struct UdpServer {
    sock: UdpSocket,
    flows: HashMap<SocketAddr, Sender<MessageBuf>>,
    pending: VecDeque<(Sender<MessageBuf>, UdpServerFlow)>,
    write_sender: Sender<(Vec<u8>, SocketAddr)>,
    write_queue: Receiver<(Vec<u8>, SocketAddr)>,
    write_item: Option<(Vec<u8>, SocketAddr)>,
    read_buf: Vec<u8>,
    read_size: usize,
    write_size: usize,
}

impl UdpServer {
    pub fn new(sock: UdpSocket, read_size: usize, write_size: usize) -> Self {
        let (tx, rx) = channel();
        UdpServer {
            sock: sock,
            flows: HashMap::new(),
            pending: VecDeque::new(),
            write_sender: tx,
            write_queue: rx,
            write_item: None,
            read_buf: vec![0; read_size],
            read_size: read_size,
            write_size: write_size
        }
    }

    pub fn bind(addr: &SocketAddr, handle: &reactor::Handle, read_size: usize,
                write_size: usize) -> io::Result<Self> {
        UdpSocket::bind(addr, handle).map(|sock| {
            UdpServer::new(sock, read_size, write_size)
        })
    }
}

impl Stream for UdpServer {
    type Item = UdpServerFlow;
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<Option<UdpServerFlow>>> {
        try!(self.poll_write());
        try!(self.poll_read());
        if let Some((tx, flow)) = self.pending.pop_front() {
            self.flows.insert(flow.peer, tx);
            Ok(Async::Ready(Some(flow)))
        }
        else {
            Ok(Async::NotReady)
        }
    }
}

impl UdpServer {
    fn poll_write(&mut self) -> io::Result<Async<()>> {
        loop {
            if let Some((ref mut item, ref addr)) = self.write_item {
                try_nb!(self.sock.send_to(item, addr));
            }
            match self.write_queue.poll() {
                Ok(Async::Ready(Some(item))) => {
                    self.write_item = Some(item)
                }
                Ok(Async::NotReady) => {
                    self.write_item = None;
                    return Ok(Async::NotReady)
                }
                _ => unreachable!()
            }
        }
    }

    fn poll_read(&mut self) -> io::Result<Async<()>> {
        loop {
            let (size, peer) = try_nb!(self.sock.recv_from(&mut self.read_buf));
            let mut data = mem::replace(&mut self.read_buf,
                                        vec![0; self.read_size]);
            data.truncate(size);
            if let Ok(data) = MessageBuf::from_vec(data) {
                if let Err(data) = self.dispatch(data, peer) {
                    self.new_flow(data, peer);
                }
            }
        }
    }

    fn dispatch(&mut self, data: MessageBuf, peer: SocketAddr)
                -> Result<(), MessageBuf> {
        let data = if let Some(sender) = self.flows.get(&peer) {
            match sender.send(data) {
                Ok(()) => return Ok(()),
                Err(data) => data
            }
        }
        else {
            return Err(data)
        };
        self.flows.remove(&peer);
        Err(data)
    }

    fn new_flow(&mut self, data: MessageBuf, peer: SocketAddr) {
        let (flow, tx) = UdpServerFlow::new(peer, self.write_sender.clone(),
                                      self.write_size);
        tx.send(data).unwrap();
        self.pending.push_back((tx, flow));
    }
}


//------------ UdpServerFlow -------------------------------------------------

pub struct UdpServerFlow {
    peer: SocketAddr,
    write: Sender<(Vec<u8>, SocketAddr)>,
    write_size: usize,
    recv: Receiver<MessageBuf>,
}

impl UdpServerFlow {
    fn new(peer: SocketAddr, write: Sender<(Vec<u8>, SocketAddr)>,
           write_size: usize)
           -> (Self, Sender<MessageBuf>) {
        let (tx, rx) = channel();
        (UdpServerFlow{peer: peer, write: write, write_size: write_size, recv: rx},
         tx)
    }
}

impl Flow for UdpServerFlow {
    fn compose_mode(&self) -> ComposeMode {
        ComposeMode::Limited(self.write_size)
    }

    fn send(&mut self, msg: Vec<u8>) -> io::Result<()> {
        self.write.send((msg, self.peer)).map_err(|_| {
            io::Error::new(io::ErrorKind::ConnectionAborted,
                           "socket closed")
        })
    }

    fn flush(&mut self) -> io::Result<Async<()>> {
        Ok(Async::Ready(()))
    }

    fn recv(&mut self) -> io::Result<Async<Option<MessageBuf>>> {
        self.recv.poll().map_err(|_| unreachable!())
    }
}


//------------ UdpClientFlow -------------------------------------------------

pub struct UdpClientFlow {
    sock: UdpSocket,
    peer: SocketAddr,
    write: VecDeque<Vec<u8>>,
    read_buf: Vec<u8>,
    read_size: usize,
    write_size: usize,
}

impl UdpClientFlow {
    fn new(sock: UdpSocket, peer: SocketAddr, read_size: usize,
           write_size: usize) -> Self {
        UdpClientFlow {
            sock: sock, peer: peer,
            write: VecDeque::new(),
            read_buf: vec![0; read_size],
            read_size: read_size, write_size: write_size
        }
    }

    pub fn bind_and_connect(local: &SocketAddr, peer: &SocketAddr,
                            handle: &reactor::Handle, read_size: usize,
                            write_size: usize) -> io::Result<Self> {
        UdpSocket::bind(&local, handle).map(|sock| {
            UdpClientFlow::new(sock, *peer, read_size, write_size)
        })
    }

    pub fn connect(peer: &SocketAddr, handle: &reactor::Handle,
                   read_size: usize, write_size: usize) -> io::Result<Self> {
        let local = match *peer {
            SocketAddr::V4(_)
                => SocketAddr::new(IpAddr::V4(0.into()), 0),
            SocketAddr::V6(_)
                => SocketAddr::new(IpAddr::V6([0;16].into()), 0)
        };
        UdpClientFlow::bind_and_connect(&local, peer, handle, read_size,
                                        write_size)
    }
}

impl Flow for UdpClientFlow {
    fn compose_mode(&self) -> ComposeMode {
        ComposeMode::Limited(self.write_size)
    }

    fn send(&mut self, msg: Vec<u8>) -> io::Result<()> {
        self.write.push_back(msg);
        Ok(())
    }

    fn flush(&mut self) -> io::Result<Async<()>> {
        loop {
            match self.write.front() {
                Some(msg) => {
                    try_nb!(self.sock.send_to(&msg, &self.peer));
                }
                None => return Ok(Async::Ready(()))
            }
            self.write.pop_front();
        }
    }

    fn recv(&mut self) -> io::Result<Async<Option<MessageBuf>>> {
        loop {
            let (size, peer) = try_nb!(self.sock.recv_from(&mut self.read_buf));
            if peer != self.peer {
                // Quietly drop messages from the wrong peer.
                continue
            }
            let mut data = mem::replace(&mut self.read_buf,
                                        vec![0; self.read_size]);
            data.truncate(size);
            if let Ok(msg) = MessageBuf::from_vec(data) {
                return Ok(Async::Ready(Some(msg)))
            }
            // ... and drop short messages, too.
        }
    }
}
