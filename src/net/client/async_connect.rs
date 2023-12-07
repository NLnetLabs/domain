//! Trait for asynchronously creating connections.

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};

/// This trait is for creating new network connections asynchronously.
///
/// The IO type is the type of the resulting connection object.
pub trait AsyncConnect {
    /// The next method is an asynchronous function that returns a
    /// new connection.
    ///
    /// This method is equivalent to async fn connect(&self) -> Result<IO, std::io::Error>;

    type Connection: AsyncRead + AsyncWrite + Send + Unpin;

    /// Associated type for the return type of next.
    type F: Future<Output = Result<Self::Connection, std::io::Error>> + Send;

    /// Get the next IO connection.
    fn connect(&self) -> Self::F;
}
