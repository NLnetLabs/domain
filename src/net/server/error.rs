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

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CommandCouldNotBeSent => {
                write!(f, "Command could not be sent")
            }
        }
    }
}
