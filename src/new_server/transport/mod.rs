//! Network transports for DNS servers.

use core::net::SocketAddr;
use std::{io, sync::Arc, time::SystemTime, vec::Vec};

use bumpalo::Bump;
use tokio::net::UdpSocket;

use crate::{
    new_base::{
        wire::{AsBytes, ParseBytesByRef},
        Message,
    },
    new_server::exchange::Allocator,
};

use super::{exchange::ParsedMessage, Exchange, Service};

//----------- serve_udp() ----------------------------------------------------

/// Serve DNS requests over UDP.
///
/// A UDP socket will be bound to the given address and listened on for DNS
/// requests.  Requests will be handed to the given [`Service`] and responses
/// will be returned directly.  Each DNS request is handed off to a Tokio task
/// so they can respond asynchronously.
pub async fn serve_udp(
    addr: SocketAddr,
    service: impl Service + Send + 'static,
) -> io::Result<()> {
    /// Internal multi-threaded state.
    struct State<S: Service + Send + 'static> {
        /// The UDP socket serving DNS.
        socket: UdpSocket,

        /// The service implementing response logic.
        service: S,
    }

    impl<S: Service + Send + 'static> State<S> {
        /// Respond to a particular UDP request.
        async fn respond(self: Arc<Self>, buffer: Vec<u8>, peer: SocketAddr) {
            let Ok(message) = Message::parse_bytes_by_ref(&buffer) else {
                // This message is fundamentally invalid, just give up.
                return;
            };

            let mut allocator = Bump::new();
            let mut allocator = Allocator::new(&mut allocator);

            let Ok(request) = ParsedMessage::parse(message, &mut allocator)
            else {
                // This message is malformed; inform the peer and stop.
                let mut buffer = [0u8; 12];
                let response = Message::parse_bytes_by_mut(&mut buffer)
                    .expect("Any 12-byte or larger buffer is a 'Message'");
                response.header.id = message.header.id;
                response.header.flags = message.header.flags.respond(1);
                let response = response.slice_to(0);
                let _ = self.socket.send_to(response.as_bytes(), peer).await;
                return;
            };

            // Build a complete 'Exchange' around the request.
            let mut exchange = Exchange {
                alloc: allocator,
                reception: SystemTime::now(),
                request,
                response: ParsedMessage::default(),
                metadata: Vec::new(),
            };

            // Generate the appropriate response.
            self.service.respond(&mut exchange).await;

            // Build up the response message.
            let mut buffer = vec![0u8; 65536];
            let message =
                exchange.response.build(&mut buffer).unwrap_or_else(|_| {
                    todo!("how to handle truncation errors?")
                });

            // Send the response back to the peer.
            let _ = self.socket.send_to(message.as_bytes(), peer).await;
        }
    }

    // Generate internal state.
    let state = Arc::new(State {
        socket: UdpSocket::bind(addr).await?,
        service,
    });

    // Main loop: wait on new requests.
    loop {
        // Allocate a buffer for the request.
        let mut buffer = vec![0u8; 65536];

        // Receive a DNS request.
        let (size, peer) = state.socket.recv_from(&mut buffer).await?;
        buffer.truncate(size);

        // Spawn a Tokio task to respond to the request.
        tokio::task::spawn(state.clone().respond(buffer, peer));
    }
}
