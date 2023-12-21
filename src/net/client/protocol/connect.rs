//! Asynchronously establishing a connection.

use std::future::Future;
use std::io;

//------------ AsyncConnect --------------------------------------------------

/// Establish a connection asynchronously.
///
///
pub trait AsyncConnect {
    /// The type of an established connection.
    type Connection;

    /// The future establishing the connection.
    type Fut: Future<Output = Result<Self::Connection, io::Error>> + Send;

    /// Returns a future that establishing a connection.
    fn connect(&self) -> Self::Fut;
}
