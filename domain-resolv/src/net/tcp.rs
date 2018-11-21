
use std::io;
use std::net::SocketAddr;
use domain_core::bits::message::Message;
use domain_core::bits::query::{QueryMessage, StreamQueryMessage};
use tokio::io::{read_exact, write_all, ReadExact, WriteAll};
use tokio::net::tcp::{ConnectFuture, TcpStream};
use tokio::prelude::{Async, Future};
use ::resolver::Answer;
use super::util::DecoratedFuture;

#[derive(Debug)]
pub enum TcpQuery {
    Connect(DecoratedFuture<ConnectFuture, QueryMessage>),
    Send(WriteAll<TcpStream, StreamQueryMessage>),
    RecvPrelude(DecoratedFuture<ReadExact<TcpStream, [u8; 2]>, QueryMessage>),
    RecvMessage(DecoratedFuture<ReadExact<TcpStream, Vec<u8>>, QueryMessage>),
    Error(Option<io::Error>),
    Done
}

impl TcpQuery {
    pub fn new(
        query: QueryMessage,
        addr: SocketAddr,
    ) -> Self {
        TcpQuery::Connect(DecoratedFuture::new(
            TcpStream::connect(&addr), query
        ))
    }
}

impl Future for TcpQuery {
    type Item = Answer;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        let (next, res) = match *self {
            TcpQuery::Connect(ref mut fut) =>  {
                let (sock, query) = try_ready!(fut.poll());
                (
                    TcpQuery::Send(write_all(sock, query.into())),
                    Ok(Async::NotReady)
                )
            }
            TcpQuery::Send(ref mut write) => {
                let (sock, query) = try_ready!(write.poll());
                (
                    TcpQuery::RecvPrelude(DecoratedFuture::new(
                        read_exact(sock, [0u8; 2]), query.unwrap()
                    )),
                    Ok(Async::NotReady)
                )
            }
            TcpQuery::RecvPrelude(ref mut fut) => {
                let ((sock, buf), query) = try_ready!(fut.poll());
                let len = (buf[0] as usize) << 8 | buf[1] as usize;
                (
                    TcpQuery::RecvMessage(DecoratedFuture::new(
                        read_exact(sock, vec![0; len]), query
                    )),
                    Ok(Async::NotReady)
                )
            }
            TcpQuery::RecvMessage(ref mut fut) => {
                let ((sock, buf), query) = try_ready!(fut.poll());
                if let Ok(answer) = Message::from_bytes(buf.into()) {
                    if answer.is_answer(&query) {
                        (TcpQuery::Done, Ok(Async::Ready(answer.into())))
                    }
                    else {
                        (
                            TcpQuery::RecvPrelude(DecoratedFuture::new(
                                read_exact(sock, [0; 2]), query
                            )),
                            Ok(Async::NotReady)
                        )
                    }
                }
                else {
                    (
                        TcpQuery::Done,
                        Err(io::Error::new(io::ErrorKind::Other, "short buf"))
                    )
                }
            }
            TcpQuery::Error(ref mut err) => {
                if let Some(err) = err.take() {
                    (TcpQuery::Done, Err(err))
                }
                else {
                    panic!("polled resolved future")
                }
            }
            TcpQuery::Done => panic!("polled resolved future"),
        };
        *self = next;
        res
    }
}

