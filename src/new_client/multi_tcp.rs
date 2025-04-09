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
use core::net::SocketAddr;
use std::boxed::Box;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use std::vec::Vec;

use futures_util::{stream, Stream, StreamExt};
use slab::Slab;
use tokio::io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{timeout, timeout_at, Instant};

use crate::new_base::wire::{BuildBytes, ParseBytesByRef, SizePrefixed, U16};
use crate::new_base::Message;
use crate::utils::CloneFrom;

use super::{Client, ClientError, SocketError};

#[derive(Clone, Debug)]
pub struct TcpConfig {
    /// Response timeout currently in effect.
    pub response_timeout: Duration,

    /// Time until the connection will close if there are no requests waiting
    /// for a response.
    ///
    /// Setting this to a low value might leads to the connection being closed
    /// before the first request is sent.
    ///
    /// Setting this to `None` will close the connection when the
    /// client and all requests are dropped.
    pub idle_timeout: Option<Duration>,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            response_timeout: Duration::from_secs(19),
            idle_timeout: None,
        }
    }
}

struct AbortJoinHandle<T>(JoinHandle<T>);

impl<T> Drop for AbortJoinHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Request {
    callback_send: oneshot::Sender<Result<Box<Message>, ClientError>>,
    message: Box<Message>,
}

pub struct TcpClient {
    /// Ensure that the read loop lives as long as the client
    _background: AbortJoinHandle<()>,
    config: TcpConfig,
    send: mpsc::Sender<Request>,
}

impl TcpClient {
    pub fn new(addr: SocketAddr) -> Self {
        Self::with_config(addr, Default::default())
    }

    pub fn with_config(addr: SocketAddr, config: TcpConfig) -> Self {
        // The buffer size is chosen arbitrarily.
        let (send, recv) = mpsc::channel(100);

        let background = Background::new(addr, config.clone(), recv);
        let background = AbortJoinHandle(tokio::spawn(background.run()));

        Self {
            _background: background,
            config,
            send,
        }
    }
}

impl Client for TcpClient {
    async fn request(
        &self,
        request: super::ExtendedMessageBuilder<'_, '_>,
    ) -> Result<Box<Message>, ClientError> {
        let message = request.build().unwrap();
        let message = CloneFrom::clone_from(message);

        let (callback_send, callback_recv) = oneshot::channel();
        self.send
            .send(Request {
                callback_send,
                message,
            })
            .await
            .unwrap();

        callback_recv.await.unwrap()
    }
}

enum Waiting {
    AwaitingReponse {
        timeout_at: Instant,
        callback_send: oneshot::Sender<Result<Box<Message>, ClientError>>,
    },
    TimedOut,
}

struct Background {
    addr: SocketAddr,
    config: TcpConfig,
    requests: mpsc::Receiver<Request>,
}

impl Background {
    fn new(
        addr: SocketAddr,
        config: TcpConfig,
        requests: mpsc::Receiver<Request>,
    ) -> Self {
        Self {
            addr,
            config,
            requests,
            current_requests: Slab::new(),
        }
    }

    async fn run(mut self) {
        // This loop just waits for the next request to come in because we
        // don't have a connection open.
        loop {
            let Some(req) = self.next_request().await else {
                return;
            };
            let Ok(mut connection) = self.connect().await else {
                req.callback_send.send(Err(ClientError::Broken));
                continue;
            };
            if let Err(_) = connection.send_request(req).await {
                // Consider this connection broken and make a new one
                continue;
            }

            connection.run().await
        }
    }

    async fn next_request(&mut self) -> Option<Request> {
        self.requests.recv().await
    }

    async fn connect<'a>(
        &'a mut self,
    ) -> io::Result<
        Connection<'a, impl Stream<Item = Result<Box<Message>, ClientError>>>,
    > {
        let stream = TcpStream::connect(self.addr).await?;
        let (read_half, write_half) = split(stream);
        let read_stream = read_stream(read_half);
        Ok(Connection {
            stream: write_half,
            background: self,
            read_stream,
        })
    }
}

struct Connection<
    'a,
    S: Stream<Item = Result<Box<Message>, ClientError>> + Unpin,
> {
    stream: WriteHalf<TcpStream>,
    background: &'a mut Background,
    read_stream: S,
    current_requests: Slab<Waiting>,
}

impl<S: Stream<Item = Result<Box<Message>, ClientError>> + Unpin>
    Connection<'_, S>
{
    async fn send_request(
        &mut self,
        mut req: Request,
    ) -> Result<(), ClientError> {
        let timeout_at =
            Instant::now() + self.background.config.response_timeout;
        let id = self.current_requests.insert(Waiting::AwaitingReponse {
            timeout_at,
            callback_send: req.callback_send,
        });

        let Ok(id) = u16::try_from(id) else {
            return Err(ClientError::TooManyRequests);
        };
        req.message.header.id.set(id);

        // We allocate the space for the maximum DNS message size and 2
        // additional bytes for the shim.
        let mut buffer = vec![0u8; 65535 + 2];

        // XXX: remove unwraps
        let request = SizePrefixed::<U16, _>::new(req.message);
        let _ = request.build_bytes(&mut buffer).unwrap();

        let size = u16::from_be_bytes(*buffer.first_chunk::<2>().unwrap());
        buffer.truncate(2 + size as usize);

        let res = self
            .stream
            .write_all(&buffer)
            .await
            .map_err(|e| SocketError::Send(e.kind()));

        Ok(res?)
    }

    fn earliest_timeout(&self) -> Option<(usize, Instant)> {
        self.current_requests
            .iter()
            .filter_map(|(idx, w)| match w {
                Waiting::AwaitingReponse { timeout_at, .. } => {
                    Some((idx, *timeout_at))
                }
                Waiting::TimedOut => None,
            })
            .min_by_key(|(_, instant)| *instant)
    }

    async fn run(&mut self) {
        let error = loop {
            if let Some((idx, earliest_timeout)) = self.earliest_timeout() {
                let fut =
                    timeout_at(earliest_timeout, self.read_stream.next());
                let Ok(res) = fut.await else {
                    let r = &mut self.current_requests[idx];
                    if let Waiting::AwaitingReponse {
                        timeout_at,
                        callback_send,
                    } = r
                    {
                        callback_send.send(Err(ClientError::TimedOut));
                        *r = Waiting::TimedOut;
                    }
                    continue;
                };
                match res {
                    // We got a response, send it to the waiting client.
                    Some(Ok(res)) => {
                        let id = res.header.id;

                        // If we don't know the id we got, the other side is sending garbage,
                        // so close the connection.
                        let Some(r) = self
                            .current_requests
                            .try_remove(id.get() as usize)
                        else {
                            break ClientError::Broken;
                        };
                        if let Waiting::AwaitingReponse {
                            callback_send,
                            ..
                        } = r
                        {
                            callback_send.send(Ok(res));
                        }
                    }
                    Some(Err(e)) => {
                        break e;
                    }
                    None => {
                        break ClientError::Closed;
                    }
                }
            } else if let Some(idle_timeout) =
                self.background.config.idle_timeout
            {
                match timeout(idle_timeout, self.background.next_request())
                    .await
                {
                    Ok(Some(req)) => {
                        if let Err(e) = self.send_request(req).await {
                            break e;
                        }
                    }
                    // We didn't get another request for some reason, this
                    // probably means every client is dropped, so we just
                    // close.
                    Ok(None) => {
                        break ClientError::Closed;
                    }
                    // We hit idle timeout, close the connection
                    Err(_) => break ClientError::Closed,
                }
            } else {
                match self.background.next_request().await {
                    Some(req) => {
                        if let Err(e) = self.send_request(req).await {
                            break e;
                        }
                    }
                    None => {
                        break ClientError::Closed;
                    }
                }
            }
        };
    }
}

fn read_stream(
    reader: ReadHalf<TcpStream>,
) -> impl Stream<Item = Result<Box<Message>, ClientError>> {
    stream::unfold(Some(reader), |reader| async {
        let Some(mut reader) = reader else {
            return None;
        };

        let res: Result<Box<Message>, ClientError> = loop {
            // First read the shim
            let mut shim_buf = [0u8; 2];
            if let Err(err) = reader.read_exact(&mut shim_buf).await {
                break Err(ClientError::from(SocketError::Receive(
                    err.kind(),
                )));
            }
            let shim = u16::from_be_bytes(shim_buf) as usize;

            // Read a response
            let mut buf = vec![0u8; shim];
            if let Err(err) = reader.read_exact(&mut buf).await {
                break Err(SocketError::Receive(err.kind()).into());
            }

            let Ok(msg) = Message::parse_bytes_by_ref(&buf) else {
                break Err(ClientError::GarbageResponse);
            };

            break Ok(CloneFrom::clone_from(msg));
        };

        let reader = if res.is_ok() { Some(reader) } else { None };

        Some((res, reader))
    })
}
