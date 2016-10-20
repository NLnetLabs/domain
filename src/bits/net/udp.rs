//! Sending and receiving via UDP.

use std::{io, mem};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use futures::Async;
use futures::stream::Stream;
use tokio_core::reactor;
use tokio_core::net::UdpSocket;
use ::bits::{ComposeMode, MessageBuf};
use super::Flow;
use super::mpsc::{Receiver, Sender, channel};


//------------ UdpIncoming ---------------------------------------------------

pub struct UdpIncoming {
    sock: UdpSocket,
    flows: HashMap<SocketAddr, Sender<MessageBuf>>,
    pending: VecDeque<(Sender<MessageBuf>, UdpFlow)>,
    write_sender: Sender<(Vec<u8>, SocketAddr)>,
    write_queue: Receiver<(Vec<u8>, SocketAddr)>,
    write_item: Option<(Vec<u8>, SocketAddr)>,
    read_buf: Vec<u8>,
    read_size: usize,
    write_size: usize,
}

impl UdpIncoming {
    pub fn new(sock: UdpSocket, read_size: usize, write_size: usize) -> Self {
        let (tx, rx) = channel();
        UdpIncoming {
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
            UdpIncoming::new(sock, read_size, write_size)
        })
    }
}

impl Stream for UdpIncoming {
    type Item = UdpFlow;
    type Error = io::Error;

    fn poll(&mut self) -> io::Result<Async<Option<UdpFlow>>> {
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

impl UdpIncoming {
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
        let (flow, tx) = UdpFlow::new(peer, self.write_sender.clone(),
                                      self.write_size);
        tx.send(data).unwrap();
        self.pending.push_back((tx, flow));
    }
}


//------------ UdpFlow -------------------------------------------------------

pub struct UdpFlow {
    peer: SocketAddr,
    write: Sender<(Vec<u8>, SocketAddr)>,
    write_size: usize,
    recv: Receiver<MessageBuf>,
}

impl UdpFlow {
    fn new(peer: SocketAddr, write: Sender<(Vec<u8>, SocketAddr)>,
           write_size: usize)
           -> (Self, Sender<MessageBuf>) {
        let (tx, rx) = channel();
        (UdpFlow{peer: peer, write: write, write_size: write_size, recv: rx},
         tx)
    }
}

impl Flow for UdpFlow {
    fn compose_mode(&self) -> ComposeMode {
        ComposeMode::Limited(self.write_size)
    }

    fn send(&mut self, msg: Vec<u8>) -> io::Result<Async<()>> {
        self.write.send((msg, self.peer)).map(|_| Async::Ready(()))
                                         .map_err(|_| {
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

