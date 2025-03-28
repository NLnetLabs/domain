//! UDP client
//!
//! This module implements the client side of DNS over UDP. A [`UdpClient`]
//! creates a UDP socket for every request.
//!
//! # Relevant RFC excerpts
//!
//! RFC 6891, section 6.2.3:
//!
//! > The requestor's UDP payload size (encoded in the RR CLASS field) is
//! > the number of octets of the largest UDP payload that can be
//! > reassembled and delivered in the requestor's network stack.  Note
//! > that path MTU, with or without fragmentation, could be smaller than
//! > this.
//! >
//! > Values lower than 512 MUST be treated as equal to 512.
//! >
//! > The requestor SHOULD place a value in this field that it can actually
//! > receive.  For example, if a requestor sits behind a firewall that
//! > will block fragmented IP packets, a requestor SHOULD NOT choose a
//! > value that will cause fragmentation.  Doing so will prevent large
//! > responses from being received and can cause fallback to occur.  This
//! > knowledge may be auto-detected by the implementation or provided by a
//! > human administrator.
//!
//! RFC 5452, section 9.2:
//!
//! > Resolver implementations MUST:
//! >
//! > o  Use an unpredictable source port for outgoing queries from the
//! >    range of available ports (53, or 1024 and above) that is as large
//! >    as possible and practicable;
//!
//! RFC 9715, section 3.2:
//!
//! > UDP requestors should limit the requestor's maximum UDP payload size to
//! > fit in the minimum of the interface MTU, the network MTU value
//! > configured by the network operators, and the RECOMMENDED maximum
//! > DNS/UDP payload size 1400. A smaller limit may be allowed. For more
//! > details, see Appendix A.
//!
//! RFC 9715, appendix A:
//!
//! > In order to avoid IP fragmentation, DNSFlagDay2020 proposes that UDP
//! > requestors set the requestor's payload size to 1232 and UDP responders
//! > compose UDP responses so they fit in 1232 octets. The size 1232 is
//! > based on an MTU of 1280, which is required by the IPv6 specification
//! > RFC8200, minus 48 octets for the IPv6 and UDP headers.

use core::net::SocketAddr;
use core::time::Duration;
use std::io;

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tracing::trace;

use crate::new_base::build::BuilderContext;
use crate::new_base::wire::{AsBytes, ParseBytesByRef};
use crate::new_base::Message;

use super::exchange::{Exchange, ParsedMessage};
use super::{Client, ClientError, SocketError};

#[derive(Clone, Debug)]
pub struct UdpConfig {
    pub max_parallel: usize,
    pub read_timeout: Duration,
    pub max_retries: u8,
    pub udp_payload_size: Option<u16>,
    pub recv_size: usize,
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

impl Client for UdpClient {
    async fn request<'a>(
        &self,
        exchange: &mut Exchange<'a>,
    ) -> Result<(), ClientError> {
        let _permit = self
            .semaphore
            .acquire()
            .await
            .expect("the semaphore is never closed and not exposed");

        if let Some(size) = self.config.udp_payload_size {
            exchange.request.set_max_udp_payload_size(size);
        }

        let mut buffer = vec![0u8; 65536];
        let mut context = BuilderContext::default();
        let mut request_builder = exchange
            .request
            .build(&mut context, &mut buffer)
            .map_err(|_| ClientError::TruncatedRequest)?;

        let mut response_buffer = vec![0u8; self.config.recv_size];
        for _ in 0..(1 + self.config.max_retries) {
            request_builder.header_mut().id.set(rand::random());
            let request_message = request_builder.message();

            // We create a new UDP socket for each retry, to follow
            // RFC 5452's recommendations of using unpredictable source port
            // numbers.
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
    let sock_addr = if addr.is_ipv4() {
        SocketAddr::from(([0u8; 4], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };

    let sock = UdpSocket::bind(sock_addr)
        .await
        .map_err(|e| SocketError::Bind(e.kind()))?;

    sock.connect(addr)
        .await
        .map_err(|e| SocketError::Connect(e.kind()))?;

    let bytes = request.as_bytes();
    let sent = sock
        .send(bytes)
        .await
        .map_err(|e| SocketError::Send(e.kind()))?;

    if sent != bytes.len() {
        // From the ErrorKind::WriteZero docs:
        // > This typically means that an operation could only succeed if it wrote a particular
        // > number of bytes but only a smaller number of bytes could be written.
        return Err(SocketError::Send(io::ErrorKind::WriteZero));
    }

    tokio::time::timeout(timeout, async {
        loop {
            let len = sock.recv(buffer).await.map_err(|e| SocketError::Receive(e.kind()))?;

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
