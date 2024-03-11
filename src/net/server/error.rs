//! Server related errors.

use std::fmt::Display;

/// Errors raised by DNS servers.
#[derive(Debug)]
pub enum Error {
    /// An attempt to send a [`ServerCommand`] to the server failed.
    ///
    /// [`ServerCommand`]: crate::net::server::service::ServerCommand
    CommandCouldNotBeSent,
}
