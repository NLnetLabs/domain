#![cfg_attr(
    not(feature = "unstable-server-transport"),
    doc = " The `unstable-server-transport` feature is necessary to enable this module."
)]
//! Asynchronous DNS serving.
//!
//! This module provides skeleton asynchronous [server] implementations based
//! on the [Tokio](https://tokio.rs/) async runtime. In combination with an
//! appropriate network source, optional [`MiddlewareChain`] and your own
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
//!    <-- network source                         - writes bytes to the client
//! ````
//!
//! # Usage
//!
//! [Server] implementations implement a common interface. To use a server
//! implementation:
//!
//!   - Create an appropriate network source (more on this below).
//!   - Construct a server instance with `new()` passing the network source.
//!   - Tune the server behaviour via builder functions such as
//!     `with_middleware()`.
//!   - `run()` the [server].
//!   - `shutdown()` the server, explicitly or on [`drop()`].
//!
//! # Core concepts
//!
//! ## Network transports
//!
//! Historically DNS servers communicated primarily via datagram based
//! connection-less network transport protocols, and used stream based
//! connection-oriented network transport protocols only for zone transfers.
//!
//! Modern DNS servers increasingly need to support stream based
//! connection-oriented network transport protocols for additional response
//! capacity and connection security.
//!
//! This module provides support for both datagram and stream based network
//! transport protocols via the [`DgramServer`] and [`StreamServer`] types
//! respectively.
//!
//! ## Datagram (e.g. UDP) servers
//!
//! [`DgramServer`] can communicate via any "network source" type that
//! implements the [`AsyncDgramSock`] trait, with an implementation provided
//! for [`tokio::net::UdpSocket`].
//!
//! The type alias [`UdpServer`] is provided for convenience for
//! implementations baed on [`tokio::net::UdpSocket`].
//!
//! ## Stream (e.g. TCP) servers
//!
//! [`StreamServer`] can communicate via any "network source" type that
//! implements the [`AsyncAccept`] trait, and whose associated stream type
//! implements the [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`]
//! traits, with an implementation provided for [`tokio::net::TcpListener`]
//! and associated stream type [`tokio::net::TcpStream`].
//!
//! The type alias [`TcpServer`] is provided for convenience for
//! implementations based on [`tokio::net::TcpListener`].
//!
//! ## Middleware
//!
//! Mandatory functionality and logic required by all standards compliant DNS
//! servers can be incorporated into your server by building a middleware
//! chain starting from [`MiddlewareBuilder::default()`].
//!
//! A selection of additional functionality relating to server behaviour and
//! DNS standards (as opposed to your own business logic) is provided which
//! you can incorporate into your DNS server via
//! [`MiddlewareBuilder::push()`]. See the various implementations of
//! [`MiddlewareProcessor`] for more information.
//!
//! ## Business logic
//!
//! With the basic work of handling DNS requests and responses taken care of,
//! the actual business logic that differentiates your DNS server from other
//! DNS servers is left for you to define by implementing the [`Service`]
//! trait.
//!
//! # Advanced
//!
//! ## Memory allocation
//!
//! The allocation of buffers, e.g. for receiving DNS messages, is delegated
//! to an implementation of the [`BufSource`] trait, giving you some control
//! over the memory allocation strategy in use.
//!
//! ## Dynamic reconfiguration
//!
//! Servers in principle support the ability to dynamically reconfigure
//! themselves in response to [`ServiceCommand::Reconfigure`] while running,
//! though the actual degree of support for this is server implementation
//! dependent.
//!
//! [`AsyncAccept`]: traits::sock::AsyncAccept
//! [`AsyncDgramSock`]: traits::sock::AsyncDgramSock
//! [`BufSource`]: buf::BufSource
//! [`DgramServer`]: servers::dgram::server::DgramServer
//! [`MiddlewareBuilder::default()`]:
//!     middleware::builder::MiddlewareBuilder::default()
//! [`MiddlewareBuilder::push()`]:
//!     middleware::builder::MiddlewareBuilder::push()
//! [`MiddlewareChain`]: middleware::chain::MiddlewareChain
//! [`MiddlewareProcessor`]: middleware::processor::MiddlewareProcessor
//! [Server]: servers
//! [`Service`]: traits::service::Service
//! [`ServiceCommand::Reconfigure`]:
//!     traits::service::ServiceCommand::Reconfigure
//! [`StreamServer`]: servers::stream::server::StreamServer
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
