//! Trait for connection streams

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use std::future::Future;
use tokio::io::{AsyncRead, AsyncWrite};

/// This trait is for creating new network connections.
///
/// The IO type is the type of the resulting connection object.
pub trait ConnectionStream<IO: AsyncRead + AsyncWrite + Send + Unpin> {
    /// The next method is an asynchronous function that returns a
    /// new connection.
    ///
    /// This method is equivalent to async fn next(&self) -> Result<IO, std::io::Error>;

    /// Associated type for the return type of next.
    type F: Future<Output = Result<IO, std::io::Error>> + Send;

    /// Get the next IO connection.
    fn next(&self) -> Self::F;
}
