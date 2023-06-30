//! Trait for connection factories

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};

/// This trait is for creating new network connections.
///
/// The IO type is the type of the resulting connection object.
pub trait ConnFactory<IO: AsyncRead + AsyncWrite + Send + Unpin> {
    /// The next method is an asynchronous function that returns a
    /// new connection.
    ///
    /// This method is equivalent to async fn next(&self) -> Result<IO, std::io::Error>;
    fn next(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<IO, std::io::Error>> + Send + '_>>;
}
