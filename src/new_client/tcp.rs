use core::net::SocketAddr;
use std::{sync::Arc, time::Duration, vec::Vec};

use futures_util::{
    future::{select, Either},
    pin_mut,
};
use slab::Slab;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{oneshot, Mutex},
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

    /// Default idle timeout.
    ///
    /// This value is used if the other side does not send a TcpKeepalive
    /// option.
    idle_timeout: Duration,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            response_timeout: Duration::from_secs(19),
            idle_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug)]
struct TcpClientInner {
    read: Mutex<ReadHalf<TcpStream>>,
    write: Mutex<WriteHalf<TcpStream>>,
    ids: Mutex<Slab<oneshot::Sender<Vec<u8>>>>,
    config: TcpConfig,
}

#[derive(Clone, Debug)]
pub struct TcpClient {
    inner: Arc<TcpClientInner>,
}

impl TcpClient {
    pub fn new(stream: TcpStream, config: TcpConfig) -> Self {
        let (read, write) = tokio::io::split(stream);
        Self {
            inner: Arc::new(TcpClientInner {
                read: read.into(),
                write: write.into(),
                ids: Default::default(),
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
            write.write_all(buffer).await.map_err(SocketError::Send)?;
        }

        let read_loop = self.read_loop(message_id);

        pin_mut!(rx);
        pin_mut!(read_loop);

        let res = tokio::time::timeout(
            self.inner.config.response_timeout,
            select(rx, read_loop),
        )
        .await;

        match res {
            Ok(Either::Left((Ok(msg), _)))
            | Ok(Either::Right((Ok(msg), _))) => {
                // We have a message with our id, we parse it and return
                self.return_answer(msg, exchange)
            }
            Ok(Either::Left((Err(_), _))) => {
                // This shouldn't happen because the sender should not have
                // been removed early. We don't panic because we do not want
                // to bring down the entire application.
                Err(ClientError::Bug)
            }
            Ok(Either::Right((Err(err), _))) => Err(err),
            Err(_) => {
                // The future has timed out.
                //
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
    async fn read_loop(&self, id: u16) -> Result<Vec<u8>, ClientError> {
        let mut read = self.inner.read.lock().await;

        loop {
            let mut buf = [0u8; 2];
            read.read_exact(&mut buf)
                .await
                .map_err(SocketError::Receive)?;
            let shim = u16::from_be_bytes(buf) as usize;

            let mut buf = vec![0u8; shim];
            read.read_exact(&mut buf)
                .await
                .map_err(SocketError::Receive)?;

            let Some(recv_id) = buf.first_chunk::<2>() else {
                // XXX: Is this a good idea?
                continue;
            };
            let recv_id = u16::from_be_bytes(*recv_id);

            let Some(recv_tx) =
                self.inner.ids.lock().await.try_remove(recv_id as usize)
            else {
                // The other side is sending garbage again.
                // XXX: We should mark the connection as broken. For now, we
                // continue.
                continue;
            };

            if recv_id == id {
                return Ok(buf);
            } else {
                // Here, the receiver might have timed out (or dropped for
                // other reasons) after we have removed the id from the slab.
                // So, we ignore this error.
                let _ = recv_tx.send(buf);
            }
        }
    }

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
            // The message turned out to be garbage, continue the loop
            // to ask the server again.
            return Err(ClientError::GarbageResponse);
        };

        exchange.response = parsed;
        return Ok(());
    }
}
