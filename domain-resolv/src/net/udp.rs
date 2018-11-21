
use std::io;
use std::net::SocketAddr;
use domain_core::bits::query::{DgramQueryMessage, QueryMessage};
use domain_core::bits::message::Message;
use tokio::net::udp::{RecvDgram, SendDgram, UdpSocket};
use tokio::prelude::{Async, Future};
use ::resolver::Answer;
use super::util::DecoratedFuture;


//------------ Module Configuration ------------------------------------------

/// How many times do we try a new random port if we get ‘address in use.’
const RETRY_RANDOM_PORT: usize = 10;


//------------ UdpQuery ------------------------------------------------------

#[derive(Debug)]
pub enum UdpQuery {
    Send {
        send: SendDgram<DgramQueryMessage>,
        addr: SocketAddr,
        recv_size: usize,
    },
    Recv {
        recv: DecoratedFuture<RecvDgram<Vec<u8>>, QueryMessage>,
        addr: SocketAddr,
        recv_size: usize,
    },
    Error(Option<io::Error>),
    Done
}

impl UdpQuery {
    pub fn new(
        query: QueryMessage,
        addr: SocketAddr,
        recv_size: usize,
    ) -> Self {
        let sock = match Self::bind(addr.is_ipv4()) {
            Ok(sock) => sock,
            Err(err) => {
                return UdpQuery::Error(Some(err))
            }
        };
        if let Err(err) = sock.connect(&addr) {
            return UdpQuery::Error(Some(err))
        }
        UdpQuery::Send {
            send: sock.send_dgram(DgramQueryMessage::from(query), &addr),
            addr,
            recv_size
        }
    }

    /// Creates a bound UDP socket.
    ///
    /// We are supposed to pick a random local port for socket for extra
    /// protection. So we try just that here.
    fn bind(v4: bool) -> Result<UdpSocket, io::Error> {
        let mut i = 0;
        loop {
            let local = if v4 { ([0u8; 4], 0).into() }
                        else { ([0u16; 8], 0).into() };
            match UdpSocket::bind(&local) {
                Ok(sock) => return Ok(sock),
                Err(err) => {
                    if i == RETRY_RANDOM_PORT {
                        return Err(err);
                    }
                    else {
                        i += 1
                    }
                }
            }
        }
    }
}

impl Future for UdpQuery {
    type Item = Answer;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        let (next, res) = match *self {
            UdpQuery::Send { ref mut send, addr, recv_size } => {
                let (sock, query) = try_ready!(send.poll());
                (
                    UdpQuery::Recv {
                        recv: DecoratedFuture::new(
                            sock.recv_dgram(vec![0; recv_size]),
                            query.unwrap()
                        ),
                        addr, recv_size
                    },
                    Ok(Async::NotReady)
                )
            }
            UdpQuery::Recv { ref mut recv, addr, recv_size } => {
                let ((sock, mut buf, len, recv_addr), query)
                    = try_ready!(recv.poll());
                buf.truncate(len);
                if let Ok(answer) = Message::from_bytes(buf.into()) {
                    if addr == recv_addr && answer.is_answer(&query) {
                        (UdpQuery::Done, Ok(Async::Ready(answer.into())))
                    }
                    else {
                        (
                            UdpQuery::Recv {
                                // XXX We should reuse the buffer.
                                recv: DecoratedFuture::new(
                                    sock.recv_dgram(vec![0; recv_size]),
                                    query
                                ),
                                addr, recv_size
                            },
                            Ok(Async::NotReady)
                        )
                    }
                }
                else {
                    (
                        UdpQuery::Done,
                        Err(io::Error::new(io::ErrorKind::Other, "short buf"))
                    )
                }
            }
            UdpQuery::Error(ref mut err) => {
                if let Some(err) = err.take() {
                    (UdpQuery::Done, Err(err))
                }
                else {
                    panic!("polled resolved future")
                }
            }
            UdpQuery::Done => panic!("polling a resolved future"),
        };
        *self = next;
        match res {
            Ok(Async::NotReady) => self.poll(),
            _ => res
        }
    }
}

