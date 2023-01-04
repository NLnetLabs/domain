//! A DNS server.
//!
//! Warning: This is incomplete exploratory proof-of-concept code only
//! at this point.
//!
//! A simple [`Server`] hard-coded to listen on TCP/UDP port 1853 on 127.0.0.1
//! with minimal functionality and error-handling etc.
//!
//! The UDP server supplies an async "stream" of requests via [`get_request()`]
//! which yields [`UdpRequest`] objects one at a time. One can then use the
//! [`reply()`] function on the request object to send a reply to the caller.
//!
//! The TCP server takes a closure which will be invoked with a [`TcpRequest`]
//! object to handle each request received.
//!
//! TODO: support TCP+TLS, either consistent with how [`StubResolver`] and
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

pub struct TcpServer {
    shutdown_rx: tokio::sync::watch::Receiver<()>,
}

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
    pub fn new() -> io::Result<(Self, tokio::sync::watch::Sender<()>)> {
        let (tx, rx) = tokio::sync::watch::channel(());
        Ok((Self { shutdown_rx: rx }, tx))
    }

    pub async fn handle_requests(
        &mut self,
        msg_handler: fn(TcpRequest) -> io::Result<Message<Bytes>>,
    ) -> io::Result<()> {
        let listener =
            tokio::net::TcpListener::bind("127.0.0.1:1853").await?;

        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            let shutdown_rx = self.shutdown_rx.clone();
                            tokio::task::spawn(async move {
                                Self::handle_connection(stream, addr, msg_handler, shutdown_rx).await
                            });
                        }

                        Err(_) => todo!(),
                    }
                },

                _ = self.shutdown_rx.changed() => {
                    eprintln!("Exiting listener");
                    return Ok(());
                }
            }
        }
    }

    async fn handle_connection(
        mut stream: tokio::net::TcpStream,
        addr: SocketAddr,
        msg_handler: fn(TcpRequest) -> Result<Message<Bytes>, io::Error>,
        mut shutdown_rx: tokio::sync::watch::Receiver<()>,
    ) {
        let mut len_buf = [0u8; 2];
        let mut buf = BytesMut::zeroed(1024);
        loop {
            tokio::select! {
                res = stream.read(&mut len_buf) => {
                    match res {
                        // TCP wrapped DNS messages must start with a 2 byte length prefix
                        Ok(len) if len >= 2 => {
                            match read_request(len_buf, &mut buf, &mut stream).await {
                                Ok(msg) => {
                                    Self::handle_request(msg, addr, msg_handler, &mut stream)
                                        .await
                                }
                                Err(_err) => {
                                    todo!()
                                }
                            }
                        }
                        Ok(_) => {
                            todo!();
                        }
                        Err(_err) => {
                            todo!();
                        }
                    }
                },

                _ = shutdown_rx.changed() => {
                    eprintln!("Exiting connection handler");
                    return;
                }
            }
        }
    }

    async fn handle_request(
        msg: Message<Bytes>,
        addr: SocketAddr,
        msg_handler: fn(TcpRequest) -> Result<Message<Bytes>, io::Error>,
        stream: &mut tokio::net::TcpStream,
    ) {
        let req = TcpRequest::new(msg, addr);
        let msg = msg_handler(req).unwrap();
        // Prefix the TCP stream with the DNS message length.
        // TODO: Use .as_stream_slice() of StreamTarget to do this instead?
        let slice = msg.as_slice();
        stream
            .write_all(&u16::try_from(slice.len()).unwrap().to_be_bytes())
            .await
            .unwrap();
        stream.write_all(slice).await.unwrap();
    }
}

async fn read_request(
    len_buf: [u8; 2],
    buf: &mut BytesMut,
    stream: &mut tokio::net::TcpStream,
) -> Result<Message<Bytes>, crate::base::ShortBuf> {
    let msg_len = u16::from_be_bytes(len_buf);
    buf.resize(msg_len as usize, 0);
    stream.read(buf).await.unwrap();
    let res = Message::from_octets(buf.copy_to_bytes(msg_len as usize));
    res
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
}

// --- Tests -----------------------------------------------------------------

#[cfg(test)]
mod test {
    use core::str::FromStr;
    use std::net::UdpSocket;

    use std::vec::Vec;

    use tokio::net::TcpStream;

    use crate::{
        base::{
            iana::{Class, Rcode},
            Dname, MessageBuilder, Rtype, StaticCompressor, StreamTarget,
        },
        rdata::{AllRecordData, A},
    };

    use super::*;

    // Helper fn to create a dummy query to send to the server
    // Based on examples/client.rs
    fn mk_query() -> StreamTarget<Vec<u8>> {
        let mut msg = MessageBuilder::from_target(StaticCompressor::new(
            StreamTarget::new_vec(),
        ))
        .unwrap();
        msg.header_mut().set_rd(true);
        msg.header_mut().set_random_id();

        let mut msg = msg.question();
        msg.push((
            Dname::<Vec<u8>>::from_str("example.com.").unwrap(),
            Rtype::A,
        ))
        .unwrap();

        let mut msg = msg.additional();
        msg.opt(|opt| {
            opt.set_udp_payload_size(4096);
            Ok(())
        })
        .unwrap();

        msg.finish().into_target()
    }

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

    fn print_response(response: Message<Bytes>) {
        for question in response.question() {
            eprintln!("{}", question.unwrap());
        }
        for record in
            response.answer().unwrap().limit_to::<AllRecordData<_, _>>()
        {
            println!("{}", record.unwrap());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    pub async fn udp_test() {
        // Create a new UDP DNS server hard-coded for now to listen on
        // 127.0.0.1:1853.
        let mut srv = UdpServer::new().unwrap();

        // Demonstrate answering requests in "background" tasks, i.e. without
        // blocking the main request accepting task. This is just a trivial
        // example, there are various ways to do this, for instance you could
        // pass the Request via a queue to an already running task rather than
        // spawn a new one.
        tokio::task::spawn(async move {
            eprintln!("Listening...");
            let req = srv.get_request().await.unwrap();
            req.reply(mk_answer(&req.query_message())).await.unwrap();
        });

        // Send a request, similar to using a command like:
        //   dig @127.0.0.1 -p 1853 A nlnetlabs.nl
        eprintln!("Sending request...");
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let msg = mk_query();
        socket
            .send_to(msg.as_dgram_slice(), ("127.0.0.1", 1853))
            .unwrap();

        eprintln!("Awaiting response...");
        let mut buf = vec![0; 1232];
        socket.recv_from(&mut buf).unwrap();
        let response =
            Message::from_octets(Bytes::copy_from_slice(&buf)).unwrap();
        print_response(response);
    }

    #[tokio::test(flavor = "multi_thread")]
    pub async fn tcp_test() {
        //console_subscriber::init();

        // Create a new TCP DNS server hard-coded for now to listen on
        // 127.0.0.1:1853.
        let (mut srv, shutdown_tx) = TcpServer::new().unwrap();

        // Demonstrate answering requests in "background" tasks, i.e. without
        // blocking the main request accepting task. This is just a trivial
        // example, there are various ways to do this, for instance you could
        // pass the Request via a queue to an already running task rather than
        // spawn a new one.
        tokio::task::spawn(async move {
            srv.handle_requests(|req| {
                eprintln!("Handling request...");
                Ok(mk_answer(&req.query_message()))
            })
            .await
            .unwrap();
        });

        // Send the DNS query
        eprintln!("Sending request...");
        let msg = mk_query();
        let mut stream = TcpStream::connect("127.0.0.1:1853").await.unwrap();
        stream.write_all(msg.as_stream_slice()).await.unwrap();

        // Read the DNS server response
        eprintln!("Awaiting response...");
        let mut len_buf = [0u8; 2];
        let mut buf = BytesMut::zeroed(1024);
        let len = stream.read(&mut len_buf).await.unwrap();
        assert_eq!(len, 2);

        let response =
            read_request(len_buf, &mut buf, &mut stream).await.unwrap();

        // Shutdown the DNS server
        shutdown_tx.send(()).unwrap();

        // Dump the response
        print_response(response);
    }
}
