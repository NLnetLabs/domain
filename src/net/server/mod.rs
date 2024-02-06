#![cfg_attr(
    not(feature = "unstable-server-transport"),
    doc = " The `unstable-server-transport` feature is necessary to enable this module."
)]
//! Asynchronous DNS serving.
//!
//! This module provides skeleton asynchronous server implementations based on
//! the [Tokio](https://tokio.rs/) async runtime. In combination with an
//! appropriate network interface, optional [`MiddlewareChain`] and your own
//! [`Service`] implementation they can be used to run a standards compliant
//! DNS server that answers requests based on the business logic you specify.
//! 
//! # Architecture
//! 
//! A layered stack of components is responsible for handling incoming
//! requests and outgoing responses:
//! 
//! ```text
//!    --> network source                         - reads bytes from the client
//!           --> server                          - deserializes requests
//!              --> (optional) middleware chain  - pre-processes requests
//!                  --> service                  - processes requests &
//!                  <--                            generates responses
//!              <-- (optional) middleware chain  - post-processes responses
//!           <-- server                          - serializes responses
//!    <-- network source                      - writes bytes to the client
//! ````
//! 
//! # Usage
//! 
//! The [`Server`] trait defines the interface common to all server
//! implementations. Using a [`Server`] follows the pattern:
//! 
//!   - Create an appropriate network source (more on this below).
//!   - Construct a server instance with [`new()`] using the network
//!     interface.
//!   - Tune the server behaviour via builder functions such as
//!     [`with_middleware()`].
//!   - [`run()`] the server.
//!   - [`shutdown()`] the server, explicitly or on [`drop()`].
//! 
//! # A note about async
//! 
//! The server functionality provided by this module is based on async
//! functions. Async functions are not supported in traits by the minimum
//! supported version of Rust targeted by this crate at the time of writing.
//! As such async functions that ideally would be part of the [`Server`]
//! trait, such as [`run()`], are not actually defined in the [`Server`] trait
//! but instead exist only in the concrete implementations.
//!
//! # Network transports
//!
//! While DNS servers historically communicated primarily via datagram based
//! network transport protocols, using stream based network transport
//! protocols only for zone transfers, modern DNS servers increasingly need to
//! support stream based network transport protocols, e.g. to handle messages
//! that exceed the maximum size supported by datagram protocols.
//! 
//! This module provides support for both datagram and stream based network
//! transport protocols via the [`DgramServer`] and [`StreamServer`] types
//! respectively.
//!
//! # Datagram (e.g. UDP) servers
//!
//! [`DgramServer`] can communicate via any "network source" type that
//! implements the [`AsyncDgramSock`] trait, with an implementation provided
//! for [`tokio::net::UdpSocket`].
//!
//! The type alias [`UdpServer`] is provided for convenience for
//! implementations baed on [`tokio::net::UdpSocket`].
//!
//! # Stream (e.g. TCP) servers
//!
//! [`StreamServer`] can communicate via any type that implements the
//! [`AsyncAccept`] trait, and whose associated stream type implements the
//! [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`] traits, with an
//! implementation provided for [`tokio::net::TcpListener`] and associated
//! stream type [`tokio::net::TcpStream`].
//!
//! The type alias [`TcpServer`] is provided for convenience for
//! implementations based on [`tokio::net::TcpListener`].
//!
//! # Service behaviour
//!
//! The interpretation of DNS requests and construction of DNS responses is
//! delegated to a user supplied implementation of the [`Service`] trait.
//!
//! # Memory allocation
//!
//! The allocation of buffers, e.g. for receiving DNS messages, is delegated
//! to an implementation of the [`BufSource`] trait, giving you some control
//! over the memory allocation strategy in use.
//! 
//! # Dynamic reconfiguration
//! 
//! Servers in principle support the ability to dynamically reconfigure
//! themselves in response to [`ServiceCommand::Reconfigure`] while running,
//! though the actual degree of support for this is server implementation
//! dependent.
//!
//! [`new()`]: traits::server::Server::new()
//! [`with_middleware()`]: traits::server::Server::with_middleware()
//! [`run()`]: servers::dgram::server::DgramServer::run()
//! [`shutdown()`]: traits::server::Server::shutdown()
//! [`AsyncAccept`]: sock::AsyncAccept
//! [`AsyncDgramSock`]: sock::AsyncDgramSock
//! [`BufSource`]: buf::BufSource
//! [`DgramServer`]: dgram::DgramServer
//! [`MiddlewareChain`]: middleware::MiddlewareChain
//! [`Server`]: traits::server::Server
//! [`Service`]: service::Service
//! [`ServiceCommand::Reconfigure`]:
//!     traits::service::ServiceCommand::Reconfigure
//! [`StreamServer`]: stream::StreamServer
//! [`TcpServer`]: servers::TcpServer
//! [`UdpServer`]: servers::UdpServer
//! [`tokio::io::AsyncRead`]:
//!     https://docs.rs/tokio/latest/tokio/io/trait.AsyncRead.html
//! [`tokio::io::AsyncWrite`]:
//!     https://docs.rs/tokio/latest/tokio/io/trait.AsyncWrite.html
//! [`tokio::net::TcpListener`]:
//!     https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html
//! [`tokio::net::TcpStream`]:
//!     https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html
//! [`tokio::net::UdpSocket`]:
//!     https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html

// TODO: Re-read https://datatracker.ietf.org/doc/html/rfc9210.

#![cfg(feature = "unstable-server-transport")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-server-transport")))]
// #![warn(missing_docs)]

pub mod buf;
pub mod error;
pub mod metrics;
pub mod middleware;
pub mod servers;
pub mod traits;
pub mod util;

#[cfg(test)]
pub mod tests;
