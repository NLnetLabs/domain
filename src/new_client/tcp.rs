use core::convert::Infallible;
use std::{sync::Arc, time::Duration, vec::Vec};

use slab::Slab;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{
        oneshot::{self, Sender},
        Mutex,
    },
    task::JoinHandle,
};

use crate::new_base::{
    build::BuilderContext,
    wire::{AsBytes, ParseBytesByRef},
    Message,
};

use super::{
    exchange::{Exchange, ParsedMessage},
    Client, ClientError, SocketError,
};

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

/// The inner structure for the TCP client, which gets wrapped in an [`Arc`]
struct TcpClientInner {
    /// Ensure that the read loop lives as long as the client
    _read_loop: AbortJoinHandle<Infallible>,
    write: Mutex<WriteHalf<TcpStream>>,
    ids: Arc<Mutex<Slab<oneshot::Sender<Result<Vec<u8>, ClientError>>>>>,
    config: TcpConfig,
}

#[derive(Clone)]
pub struct TcpClient {
    inner: Arc<TcpClientInner>,
}

impl TcpClient {
    pub fn new(stream: TcpStream, config: TcpConfig) -> Self {
        let (read, write) = tokio::io::split(stream);
        let ids = Arc::new(Mutex::default());
        let read_loop =
            AbortJoinHandle(tokio::spawn(read_loop(read, ids.clone())));

        Self {
            inner: Arc::new(TcpClientInner {
                _read_loop: read_loop,
                write: write.into(),
                ids,
                config,
            }),
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
            let mut ids = self.inner.ids.lock().await;
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
            let mut write = self.inner.write.lock().await;
            write
                .write_all(buffer)
                .await
                .map_err(|e| SocketError::Send(e.kind()))?;
        }

        let res =
            tokio::time::timeout(self.inner.config.response_timeout, rx)
                .await;

        match res {
            // We have a message with our id, we parse it and return
            Ok(Ok(Ok(msg))) => self.return_answer(msg, exchange),
            // We have received an error
            Ok(Ok(Err(err))) => Err(err),
            // A receive error happened on the channel. This just shouldn't
            // happen if everything is working as expected.
            Ok(Err(_)) => Err(ClientError::Bug),
            // The future has timed out.
            Err(_) => {
                // We ignore the error because the read loop might have
                // removed the id from the slab already.
                let _ = self
                    .inner
                    .ids
                    .lock()
                    .await
                    .try_remove(message_id as usize);
                Err(ClientError::Socket(SocketError::Timeout))
            }
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
    loop {
        // First read the shim
        let mut buf = [0u8; 2];
        if let Err(err) = reader.read_exact(&mut buf).await {
            return SocketError::Receive(err.kind()).into();
        }
        let shim = u16::from_be_bytes(buf) as usize;

        // Read a response
        let mut buf = vec![0u8; shim];
        if let Err(err) = reader.read_exact(&mut buf).await {
            return SocketError::Receive(err.kind()).into();
        }

        // Read the id from the response. We do this without checking
        // anything else in the message.
        let Some(recv_id) = buf.first_chunk::<2>() else {
            return ClientError::Broken;
        };
        let recv_id = u16::from_be_bytes(*recv_id);

        let Some(recv_tx) = ids.lock().await.try_remove(recv_id as usize)
        else {
            return ClientError::Broken;
        };

        // Here, the receiver might have timed out (or dropped for
        // other reasons) after we have removed the id from the slab.
        // So, we ignore this error.
        let _ = recv_tx.send(Ok(buf));
    }
}
