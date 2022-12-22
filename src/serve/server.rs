//! A DNS server.
//!
//! Warning: This is incomplete exploratory proof-of-concept code only
//! at this point.
//!
//! A simple [`Server`] hard-coded to listen on UDP port 1853 on 127.0.0.1
//! with minimal functionality and error-handling etc.
//!
//! Supplies an async "stream" of requests via [`get_request()`] which yields
//! [`Request`] objects one at a time. One can then use the [`reply()`]
//! function on the request object to send a reply to the caller.
//!
//! TODO: support TCP and TLS, either consistent with how [`StubResolver`] and
//! [`ServerInfo`] do it already, or alter the design to separate impls rather
//! than a single impl covering all supported transports. Also consider how
//! memory should be used, can we be more zero-copy, is using Bytes the right
//! thing to do. We assume that the only async runtime that we will support is
//! Tokio.
use std::{io, net::SocketAddr};

use bytes::{Buf, Bytes, BytesMut};

use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::base::Message;

// --- UDP transport based server implementation -----------------------------

pub struct UdpServer {
    socket: Arc<tokio::net::UdpSocket>,
    buf: BytesMut,
}

pub struct UdpRequest {
    query_message: Message<Bytes>,
    source_address: SocketAddr,
    socket: Arc<tokio::net::UdpSocket>,
}

impl UdpServer {
    pub fn new() -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:1853")?;
        let socket = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
        let buf = BytesMut::zeroed(1024);
        Ok(Self { socket, buf })
    }

    pub async fn get_request(&mut self) -> io::Result<UdpRequest> {
        let (len, addr) = self.socket.recv_from(&mut self.buf).await?;
        let msg = Message::from_octets(self.buf.copy_to_bytes(len))
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        let req = UdpRequest::new(msg, addr, self.socket.clone());
        Ok(req)
    }
}

impl UdpRequest {
    pub fn new(
        msg: Message<Bytes>,
        addr: SocketAddr,
        socket: Arc<tokio::net::UdpSocket>,
    ) -> Self {
        Self {
            query_message: msg,
            source_address: addr,
            socket,
        }
    }

    pub async fn reply<T>(&self, msg: Message<T>) -> io::Result<()>
    where
        T: AsRef<[u8]>,
    {
        self.socket
            .send_to(msg.as_slice(), self.source_address)
            .await?;
        Ok(())
    }

    pub fn query_message(&self) -> &Message<Bytes> {
        &self.query_message
    }

    pub fn source_address(&self) -> SocketAddr {
        self.source_address
    }
}

// --- TCP transport based server implementation -----------------------------

pub struct TcpServer;

pub struct TcpRequest {
    query_message: Message<Bytes>,
    source_address: SocketAddr,
}

impl std::fmt::Debug for TcpRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpRequest").finish()
    }
}

impl TcpServer {
    pub fn new() -> io::Result<Self> {
        Ok(Self {})
    }

    pub async fn get_request(
        &mut self,
        msg_handler: fn(TcpRequest) -> io::Result<Message<Bytes>>,
    ) -> io::Result<TcpRequest> {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:1853").await?;

        loop {
            match listener.accept().await {
                Ok((mut stream, addr)) => {
                    eprintln!("Connection received");
                    tokio::task::spawn(async move {
                        eprintln!("Reader started");
                        let mut len_buf = [0u8; 2];
                        let mut buf = BytesMut::zeroed(1024);
                        loop {
                            eprintln!("Waiting for message bytes");
                            match stream.read(&mut len_buf).await {
                                Ok(len) if len >= 2 => {
                                    let msg_len = u16::from_be_bytes(len_buf);
                                    buf.resize(msg_len as usize, 0);
                                    stream.read(&mut buf).await.unwrap();
                                    if let Ok(msg) = Message::from_octets(
                                        buf.copy_to_bytes(msg_len as usize),
                                    ) {
                                        eprintln!(
                                            "Sufficient bytes received"
                                        );
                                        let req = TcpRequest::new(msg, addr);
                                        let msg = msg_handler(req).unwrap();
                                        let slice = msg.as_slice();
                                        eprintln!(
                                            "Writing {} bytes",
                                            slice.len()
                                        );
                                        stream
                                            .write_all(
                                                &u16::try_from(slice.len())
                                                    .unwrap()
                                                    .to_be_bytes(),
                                            )
                                            .await
                                            .unwrap();
                                        stream
                                            .write_all(slice)
                                            .await
                                            .unwrap();
                                        eprintln!("Reply sent");
                                    } else {
                                        eprintln!(
                                            "Insufficient bytes received"
                                        );
                                    }
                                }
                                Ok(_) => {
                                    eprintln!("Zero byte message received. Aborting.");
                                    break;
                                }
                                Err(err) => {
                                    eprintln!("Error while waiting for message bytes: {}", err);
                                }
                            }
                        }
                        eprintln!("Ending reader task");
                    });
                }

                Err(_) => todo!(),
            }
        }
    }
}

impl TcpRequest {
    pub fn new(msg: Message<Bytes>, addr: SocketAddr) -> Self {
        Self {
            query_message: msg,
            source_address: addr,
        }
    }

    pub fn query_message(&self) -> &Message<Bytes> {
        &self.query_message
    }

    pub fn source_address(&self) -> SocketAddr {
        self.source_address
    }

    pub async fn reply<T>(&self, _msg: Message<T>) -> io::Result<()>
    where
        T: AsRef<[u8]>,
    {
        todo!()
    }
}

// --- Tests -----------------------------------------------------------------

#[cfg(test)]
mod test {
    use crate::{
        base::{
            iana::{Class, Rcode},
            Dname, MessageBuilder,
        },
        rdata::A,
    };

    use super::*;

    // Helper fn to create a dummy response to send back to the client
    fn mk_answer(msg: &Message<Bytes>) -> Message<Bytes> {
        let res = MessageBuilder::new_bytes();
        let mut answer = res.start_answer(msg, Rcode::NoError).unwrap();
        answer
            .push((
                Dname::root_ref(),
                Class::In,
                86400,
                A::from_octets(192, 0, 2, 1),
            ))
            .unwrap();
        answer.into_message()
    }

    #[tokio::test(flavor = "multi_thread")]
    pub async fn udp_test() {
        // Create a new UDP DNS server hard-coded for now to listen on
        // 127.0.0.1:1853. Send a request with a command like:
        //
        //   dig @127.0.0.1 -p 1853 A nlnetlabs.nl
        let mut srv = UdpServer::new().unwrap();

        // Demonstrate answering requests in "background" tasks, i.e. without
        // blocking the main request accepting task. This is just a trivial
        // example, there are various ways to do this, for instance you could
        // pass the Request via a queue to an already running task rather than
        // spawn a new one.
        loop {
            srv.get_request().await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    pub async fn tcp_test() {
        //console_subscriber::init();

        // Create a new UDP DNS server hard-coded for now to listen on
        // 127.0.0.1:1853. Send a request with a command like:
        //
        //   dig @127.0.0.1 -p 1853 A nlnetlabs.nl
        let mut srv = TcpServer::new().unwrap();

        // Demonstrate answering requests in "background" tasks, i.e. without
        // blocking the main request accepting task. This is just a trivial
        // example, there are various ways to do this, for instance you could
        // pass the Request via a queue to an already running task rather than
        // spawn a new one.
        loop {
            eprintln!("Getting request...");
            srv.get_request(|req| Ok(mk_answer(&req.query_message())))
                .await
                .unwrap();
        }
    }
}
