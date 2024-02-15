//! Server related errors.

/// Errors raised by DNS servers.
#[derive(Debug)]
pub enum Error {
    /// An attempt to send a [`ServiceCommand`] to the server failed.
    ///
    /// [`ServiceCommand`]: crate::net::server::service::ServiceCommand
    CommandCouldNotBeSent,
}
