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

use crate::base::Message;

pub enum Server {
    Udp(UdpServer),
}

impl Server {
    pub async fn get_request(&mut self) -> io::Result<Request> {
        match self {
            Server::Udp(s) => s.get_request().await.map(|r| Request::Udp(r)),
        }
    }
}

pub enum Request {
    Udp(UdpRequest),
}

impl Request {
    pub async fn reply<T>(&self, msg: Message<T>) -> io::Result<()>
    where
        T: AsRef<[u8]>,
    {
        match self {
            Request::Udp(r) => r.reply(msg).await,
        }
    }

    pub fn query_message(&self) -> &Message<Bytes> {
        match self {
            Request::Udp(r) => r.query_message(),
        }
    }

    pub fn source_address(&self) -> SocketAddr {
        match self {
            Request::Udp(r) => r.source_address(),
        }
    }
}

pub struct UdpServer {
    socket: Arc<tokio::net::UdpSocket>,
    buf: BytesMut,
}

pub struct UdpRequest {
    query_message: Message<Bytes>,
    source_address: SocketAddr,
    socket: Arc<tokio::net::UdpSocket>,
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

impl UdpServer {
    pub fn new() -> io::Result<Self> {
        let socket = std::net::UdpSocket::bind("127.0.0.1:1853")?;
        let socket = Arc::new(tokio::net::UdpSocket::from_std(socket)?);
        let buf = BytesMut::zeroed(1024);
        Ok(Self { socket, buf })
    }

    // In theory this could be called from an async iterator so that one could
    // do:
    //
    //   for req in Server {
    //     ...
    //   }
    //
    // But Rust async iterators are not yet stable.
    async fn get_request(&mut self) -> io::Result<UdpRequest> {
        let (len, addr) = self.socket.recv_from(&mut self.buf).await?;
        let msg = Message::from_octets(self.buf.copy_to_bytes(len))
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;
        let req = UdpRequest::new(msg, addr, self.socket.clone());
        Ok(req)
    }
}

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
    fn mk_answer(req: &Request) -> Message<Bytes> {
        let res = MessageBuilder::new_bytes();
        let mut answer = res
            .start_answer(req.query_message(), Rcode::NoError)
            .unwrap();
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
    pub async fn test_something() {
        // Create a new UDP DNS server hard-coded for now to listen on
        // 127.0.0.1:1853. Send a request with a command like:
        //
        //   dig @127.0.0.1 -p 1853 A nlnetlabs.nl
        let mut srv = Server::Udp(UdpServer::new().unwrap());

        // Demonstrate answering requests in "background" tasks, i.e. without
        // blocking the main request accepting task. This is just a trivial
        // example, there are various ways to do this, for instance you could
        // pass the Request via a queue to an already running task rather than
        // spawn a new one.
        loop {
            let req = srv.get_request().await.unwrap();

            tokio::task::spawn(async move {
                let msg = mk_answer(&req);
                req.reply(msg).await.unwrap();
            });
        }

        // One can also reply using the Server rather than to the Request
        //srv.reply(msg, req.source_address()).await.unwrap();
    }
}
