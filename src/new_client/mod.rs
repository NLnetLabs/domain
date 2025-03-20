use core::net::SocketAddr;
use core::time::Duration;
use std::io;
use std::vec::Vec;

use exchange::{Exchange, ParsedMessage};
use tokio::{net::UdpSocket, sync::Semaphore};
use tracing::trace;

use crate::new_base::{
    build::BuilderContext,
    wire::{AsBytes, ParseBytesByRef},
    Message,
};

pub mod exchange;

#[derive(Clone, Debug)]
pub struct UdpConfig {
    max_parallel: usize,
    read_timeout: Duration,
    max_retries: u8,
    udp_payload_size: Option<u16>,
    recv_size: usize,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            max_parallel: 100,
            read_timeout: Duration::from_secs(5),
            max_retries: 5,
            udp_payload_size: Some(1232),
            recv_size: 2000,
        }
    }
}

#[derive(Debug)]
pub struct UdpClient {
    addr: SocketAddr,
    config: UdpConfig,
    semaphore: Semaphore,
}

impl UdpClient {
    pub fn new(addr: SocketAddr, config: UdpConfig) -> Self {
        Self {
            addr,
            semaphore: Semaphore::new(config.max_parallel),
            config,
        }
    }
}

pub trait Client {
    async fn request<'a>(
        &self,
        exchange: &mut Exchange<'a>,
    ) -> Result<(), ClientError>;
}

impl Client for UdpClient {
    async fn request<'a>(
        &self,
        exchange: &mut Exchange<'a>,
    ) -> Result<(), ClientError> {
        let _permit = self.semaphore.acquire().await.unwrap();

        if let Some(size) = self.config.udp_payload_size {
            exchange.request.set_max_udp_payload_size(size);
        }

        let mut buffer = vec![0u8; 65536];
        let mut context = BuilderContext::default();
        let mut request_builder =
            exchange.request.build(&mut context, &mut buffer).unwrap();

        let mut response_buffer = vec![0u8; self.config.recv_size];
        for _ in 0..(1 + self.config.max_retries) {
            request_builder.header_mut().id.set(rand::random());
            let request_message = request_builder.message();

            let response_result = send_udp_request(
                &mut *response_buffer,
                request_message,
                self.addr,
                self.config.read_timeout,
            )
            .await;

            // If the response timed out, we can try again
            if let Err(SocketError::Timeout) = response_result {
                continue;
            };

            let response_message = response_result?;

            let Ok(parsed) =
                ParsedMessage::parse(response_message, &mut exchange.alloc)
            else {
                // The message turned out to be garbage, continue the loop
                // to ask the server again.
                continue;
            };

            exchange.response = parsed;
            return Ok(());
        }

        drop(_permit);

        Err(SocketError::Timeout.into())
    }
}

pub async fn send_udp_request<'a>(
    buffer: &'a mut [u8],
    request: &Message,
    addr: SocketAddr,
    timeout: Duration,
) -> Result<&'a Message, SocketError> {
    let sock = if addr.is_ipv4() {
        UdpSocket::bind(SocketAddr::from(([0u8; 4], 0)))
    } else {
        UdpSocket::bind(SocketAddr::from(([0u16; 8], 0)))
    }
    .await
    .unwrap();

    sock.connect(addr).await.map_err(SocketError::Connect);

    let bytes = request.as_bytes();
    let sent = sock.send(bytes).await.map_err(SocketError::Send)?;

    if sent != bytes.len() {
        // From the ErrorKind::WriteZero docs:
        // > This typically means that an operation could only succeed if it wrote a particular
        // > number of bytes but only a smaller number of bytes could be written.
        return Err(SocketError::Send(io::Error::from(
            io::ErrorKind::WriteZero,
        )));
    }

    tokio::time::timeout(timeout, async {
        loop {
            let len = sock.recv(buffer).await.map_err(SocketError::Receive)?;

            // TODO: Add more context to these trace calls
            trace!("Received {len} bytes of message");

            let message_buf = &buffer[..len];
            match Message::parse_bytes_by_ref(message_buf) {
                Ok(response)
                    if response.header.flags.is_response()
                        && response.header.id == request.header.id =>
                {
                    let message_buf = &buffer[..len];
                    // SAFETY: This is fine to unwrap unchecked because we just parsed it.
                    // We need this because we need a long lifetime on the message, but Rust
                    // currently cannot do this in a loop with branches. This should be fixed once
                    // Polonius is finally done.
                    return Ok(unsafe { Message::parse_bytes_by_ref(message_buf).unwrap_unchecked() })
                }
                Ok(_) => {
                    // Wrong answer, go back to receiving
                    trace!("Received message is not the answer we were waiting for, reading more");
                }
                Err(_) => {
                    // Just go back to receiving.
                    trace!("Received bytes were garbage, reading more");
                }
            }
        }
    }).await.unwrap_or(Err(SocketError::Timeout))
}

#[derive(Debug)]
pub enum SocketError {
    Connect(io::Error),
    Send(io::Error),
    Receive(io::Error),
    Timeout,
}

/// Error type for client transports.
#[derive(Debug)]
pub enum ClientError {
    /// An error happened in the datagram transport.
    Socket(SocketError),
}

impl From<SocketError> for ClientError {
    fn from(value: SocketError) -> Self {
        ClientError::Socket(value)
    }
}
