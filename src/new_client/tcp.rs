//! Multiplexed TCP Client
//!
//! A [`TcpClient`] maintains a TCP connection. Each [`TcpClient::request`]
//! call sends a request over that connection and returns a future for the
//! response.
//!
//! If you require a long-lived connection with a server. You probably want
//! to use a multi TCP stream (to be implemented).
//!
//! Characteristics of this implementation:
//!
//! - Messages sent with this client should not contain TSIG records,
//!   because the message id will be modified, invalidating the signature.
//! - Each [`TcpClient`] spawns a background task for reading the incoming
//!   messages.
//! - The background task will abort when [`TcpClient`] is dropped.
//! - The ids assigned to each message will usually be low and may be reused.
//! - If the connection is found to be in a broken state. All requests will
//!   receive errors. A new [`TcpClient`] should be created at this point.
//! - `edns-tcp-keepalive` is ignored, because we simply keep the connection
//!   around for as long as we need it.
//!
//! # Relevant RFC excerpts
//!
//! RFC 1035, Section 4.2.2:
//!
//! > Messages sent over TCP connections use server port 53 (decimal). The
//! > message is prefixed with a two byte length field which gives the
//! > message length, excluding the two byte length field. This length field
//! > allows the low-level processing to assemble a complete message before
//! > beginning to parse it.
//!
//! RCF 7766, Section 6.2.1:
//!
//! > To amortise connection setup costs, both clients and servers SHOULD
//! > support connection reuse by sending multiple queries and responses over
//! > a single persistent TCP connection.
//! >
//! > When sending multiple queries over a TCP connection, clients MUST NOT
//! > reuse the DNS Message ID of an in-flight query on that connection in
//! > order to avoid Message ID collisions.
//!
//! RFC 7766, Section 6.2.1.1:
//!
//! > In order to achieve performance on par with UDP, DNS clients SHOULD
//! > pipeline their queries.  When a DNS client sends multiple queries to
//! > a server, it SHOULD NOT wait for an outstanding reply before sending
//! > the next query.
//!
//! > It is likely that DNS servers need to process pipelined queries
//! > concurrently and also send out-of-order responses over TCP in order
//! > to provide the level of performance possible with UDP transport.
//!
//! RFC 7766, Secton 6.2.3:
//!
//! > DNS clients SHOULD close the TCP connection of an idle session, unless
//! > an idle timeout has been established using some other signalling
//! > mechanism, for example, edns-tcp-keepalive.
//!
//! RFC 7858, Section 3.4:
//!
//! > In order to amortize TCP and TLS connection setup costs, clients and
//! > servers SHOULD NOT immediately close a connection after each response.
//! > Instead, clients and servers SHOULD reuse existing connections for
//! > subsequent queries as long as they have sufficient resources.
//!
//! RFC 7766, Section 8:
//!
//! > DNS clients and servers SHOULD pass the two-octet length field, and
//! > the message described by that length field, to the TCP layer at the
//! > same time (e.g., in a single "write" system call) to make it more
//! > likely that all the data will be transmitted in a single TCP segment.

use core::convert::Infallible;
use core::mem;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use slab::Slab;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::oneshot::{self, Sender};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::new_base::build::BuilderContext;
use crate::new_base::wire::{AsBytes, ParseBytesByRef};
use crate::new_base::Message;

use super::exchange::{Exchange, ParsedMessage};
use super::{Client, ClientError, SocketError};

/// Configuration for a stream transport connection.
#[derive(Clone, Debug)]
pub struct TcpConfig {
    /// Response timeout currently in effect.
    response_timeout: Duration,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            response_timeout: Duration::from_secs(19),
        }
    }
}

struct AbortJoinHandle<T>(JoinHandle<T>);

impl<T> Drop for AbortJoinHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub struct TcpClient {
    /// Ensure that the read loop lives as long as the client
    _read_loop: AbortJoinHandle<Infallible>,
    write: Mutex<WriteHalf<TcpStream>>,
    ids: Arc<Mutex<Slab<oneshot::Sender<Result<Vec<u8>, ClientError>>>>>,
    config: TcpConfig,
}

impl TcpClient {
    pub fn new(stream: TcpStream, config: TcpConfig) -> Self {
        let (read, write) = tokio::io::split(stream);
        let ids = Arc::new(Mutex::default());
        let read_loop =
            AbortJoinHandle(tokio::spawn(read_loop(read, ids.clone())));

        Self {
            _read_loop: read_loop,
            write: write.into(),
            ids,
            config,
        }
    }
}

impl Client for TcpClient {
    async fn request<'a>(
        &self,
        exchange: &mut Exchange<'a>,
    ) -> Result<(), ClientError> {
        // Multiple requests can be multiplexed over the same TcpStream.
        // Therefore, the requests are read by a background task and then
        // distributed. This background task will get dropped automatically
        // when the last client is dropped.
        //
        // The channels are stored in a slab. The indices generated by the
        // slab are used as message IDs.

        // We allocate the space for the maximum DNS message size and 2
        // additional bytes for the shim. We start writing the message with
        // an offset of 2.
        let mut buffer = vec![0u8; 65536 + 2];
        let mut context = BuilderContext::default();
        let mut request_builder = exchange
            .request
            .build(&mut context, &mut buffer[2..])
            .map_err(|_| ClientError::TruncatedRequest)?;

        let (tx, rx) = oneshot::channel();
        let message_id = {
            let mut ids = self.ids.lock().await;
            let message_id = ids.insert(tx);

            // Slab tries to keep ids as small as possible, so if we get an
            // id larger than u16::MAX, we're in trouble.
            match u16::try_from(message_id) {
                Ok(message_id) => message_id,
                Err(_) => {
                    let _ = ids.try_remove(message_id);
                    return Err(ClientError::TooManyRequests);
                }
            }
        };

        request_builder.header_mut().id.set(message_id);
        let request_len = request_builder.message().as_bytes().len();
        *buffer.first_chunk_mut().unwrap() =
            (request_len as u16).to_be_bytes();

        let buffer = &buffer[..request_len + 2];

        // Temporary scope to drop the lock on write early
        {
            let mut write = self.write.lock().await;
            write
                .write_all(buffer)
                .await
                .map_err(|e| SocketError::Send(e.kind()))?;
        }

        let res =
            tokio::time::timeout(self.config.response_timeout, rx).await;

        match res {
            // We have a message with our id, we parse it and return
            Ok(Ok(Ok(msg))) => self.return_answer(msg, exchange),
            // We have received an error
            Ok(Ok(Err(err))) => Err(err),
            // A receive error happened on the channel. This just shouldn't
            // happen if everything is working as expected.
            Ok(Err(_)) => Err(ClientError::Bug),
            // The future has timed out.
            //
            // In this case, we do not remove our id from the slab. This
            // allows us to distinguish between responses that are late and
            // responses that are invalid. In the first case, we just
            // continue. In the second case, we mark the connection as
            // broken.
            Err(_) => Err(ClientError::Socket(SocketError::Timeout)),
        }
    }
}

impl TcpClient {
    fn return_answer(
        &self,
        msg: Vec<u8>,
        exchange: &mut Exchange,
    ) -> Result<(), ClientError> {
        let Ok(msg) = Message::parse_bytes_by_ref(&msg) else {
            return Err(ClientError::GarbageResponse);
        };
        let Ok(parsed) = ParsedMessage::parse(msg, &mut exchange.alloc)
        else {
            return Err(ClientError::GarbageResponse);
        };

        exchange.response = parsed;
        return Ok(());
    }
}

/// Function to read messages for a TcpStream and dispatch them
async fn read_loop(
    reader: ReadHalf<TcpStream>,
    ids: Arc<Mutex<Slab<Sender<Result<Vec<u8>, ClientError>>>>>,
) -> Infallible {
    let error = read_loop_inner(reader, ids.clone()).await;

    // Loop to notify all connections of the broken state
    loop {
        let mut ids = ids.lock().await;
        for recv_tx in ids.drain() {
            let _ = recv_tx.send(Err(error.clone()));
        }
    }
}

async fn read_loop_inner(
    mut reader: ReadHalf<TcpStream>,
    ids: Arc<Mutex<Slab<Sender<Result<Vec<u8>, ClientError>>>>>,
) -> ClientError {
    let mut buf = Vec::new();

    loop {
        if let Err(err) = read_response(&mut buf, &mut reader).await {
            return ClientError::Socket(err);
        }

        // Read the id from the response. We do this without checking
        // anything else in the message.
        let Some(recv_id) = buf.first_chunk::<2>() else {
            return ClientError::Broken;
        };
        let recv_id = u16::from_be_bytes(*recv_id);

        // If we get a message with an id that's not in the slab, then the
        // other side of the connection is broken.
        let Some(recv_tx) = ids.lock().await.try_remove(recv_id as usize)
        else {
            return ClientError::Broken;
        };

        // Here, the receiver might have timed out (or dropped for
        // other reasons) after we have removed the id from the slab.
        // So, we ignore this error.
        let _ = recv_tx.send(Ok(mem::take(&mut buf)));
    }
}

async fn read_response(
    buf: &mut Vec<u8>,
    reader: &mut ReadHalf<TcpStream>,
) -> Result<(), SocketError> {
    // First read the shim
    let mut shim_buf = [0u8; 2];
    if let Err(err) = reader.read_exact(&mut shim_buf).await {
        return Err(SocketError::Receive(err.kind()));
    }
    let shim = u16::from_be_bytes(shim_buf) as usize;

    // Read a response
    *buf = vec![0u8; shim];
    if let Err(err) = reader.read_exact(buf).await {
        return Err(SocketError::Receive(err.kind()));
    }

    Ok(())
}
