use std::io;

use exchange::Exchange;

pub mod exchange;
pub mod tcp;
pub mod udp;

pub trait Client {
    async fn request<'a>(
        &self,
        exchange: &mut Exchange<'a>,
    ) -> Result<(), ClientError>;
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
    TruncatedRequest,

    GarbageResponse,

    /// An error happened in the datagram transport.
    Socket(SocketError),

    TooManyRequests,

    Bug,
}

impl From<SocketError> for ClientError {
    fn from(value: SocketError) -> Self {
        ClientError::Socket(value)
    }
}
