use std::io;

use exchange::Exchange;

pub mod exchange;
pub mod tcp;
pub mod udp;

pub trait Client {
    #[allow(async_fn_in_trait)]
    async fn request<'a>(
        &self,
        exchange: &mut Exchange<'a>,
    ) -> Result<(), ClientError>;
}

#[derive(Clone, Debug)]
pub enum SocketError {
    Bind(io::ErrorKind),
    Connect(io::ErrorKind),
    Send(io::ErrorKind),
    Receive(io::ErrorKind),
    Timeout,
}

/// Error type for client transports.
#[derive(Clone, Debug)]
pub enum ClientError {
    TruncatedRequest,

    GarbageResponse,

    /// An error happened in the datagram transport.
    Socket(SocketError),

    TooManyRequests,

    Bug,

    Broken,

    Closed,

    TimedOut,
}

impl From<SocketError> for ClientError {
    fn from(value: SocketError) -> Self {
        ClientError::Socket(value)
    }
}
