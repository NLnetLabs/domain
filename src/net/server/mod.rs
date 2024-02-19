#![cfg_attr(
    not(feature = "unstable-server-transport"),
    doc = " The `unstable-server-transport` feature is necessary to enable this module."
)]
//! Receiving requests and sending responses.
//!
//! This module provides skeleton asynchronous server implementations based on
//! the [Tokio](https://tokio.rs/) async runtime. In combination with an
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
//! --> network source                      - reads bytes from the client
//!     --> server                          - deserializes requests
//!         --> (optional) middleware chain - pre-processes requests
//!             --> service                 - processes requests &
//!             <--                           generates responses
//!         <-- (optional) middleware chain - post-processes responses
//!     <-- server                          - serializes responses
//! <-- network source                      - writes bytes to the client
//! ````
//!
//! # Usage
//!
//! Servers are implemented by combining a server transport (see [dgram] and
//! [stream]), [`BufSource`], (optional) [`MiddlewareChain`] and [`Service`]
//! together.
//!
//! Whether using [`DgramServer`] or [`StreamServer`] the required steps are
//! the same.
//!
//!   - Create an appropriate network source (more on this below).
//!   - Construct a server transport with `new()` passing in the network
//!     source as an argument.
//!   - Tune the server behaviour via builder functions such as
//!     `with_middleware()`.
//!   - `run()` the server.
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
//! # Performance
//!
//! Both [`DgramServer`] and [`StreamServer`] invoke [`Service::call()`]
//! inside the Tokio task handling the request. For [`DgramServer`] this is
//! the main task that receives incoming messages. For [`StreamServer`] this
//! is a dedicated task per accepted connection.
//!
//! The initial work done by [`Service::call()`] should therefore complete as
//! quickly as possible, delegating as much of the work as it can to the
//! future(s) it returns. Until then it blocks the server from receiving new
//! messages, or in the case of [`StreamServer`], new messages for the
//! connection on which the current message was received.
//!
//! # Clone, Arc, and shared state
//!
//! Both [`DgramServer`] and [`StreamServer`] take ownership of the
//! [`Service`] impl passed to them.
//!
//! While this may work for some scenarios, real DNS server applications will
//! likely need to accept client requests over multiple transports, will
//! require multiple instances of [`DgramServer`] and [`StreamServer`], and
//! the [`Service`] impl will likely need to have its own state.
//!
//! In these more complex scenarios it becomes more important to understand
//! how the servers work with the [`Service`] impl and the [`Clone`] and
//! [`Arc`] traits.
//!
//! [`DgramServer`] uses a single copy of the [`Service`] impl that it
//! receives but [`StreamServer`] requires that [`Service`] be [`Clone`]
//! because it clones it for each new connection that it accepts.
//!
//! You have three choices for managing access to the internal state of your
//! [`Service`] impl:
//!
//! 1. `#[derive(Clone)]` for your [`Service`] impl. If your [`Service`] impl
//! has no state that needs to be shared amongst instances of itself then this
//! may be good enough for you.
//!
//! 2. Wrap your [`Service`] impl instance inside an [`Arc`]. This crate
//! implements the [`Service`] trait for `Arc<Service>` so you can pass an
//! `Arc<Service>` to both [`DgramServer`] and [`StreamServer`] and they will
//! [`Clone`] the [`Arc`] rather than the [`Service`] instance itself.
//!
//! 3. Implement [`Clone`] for your [`Service`] impl manually, giving you
//! complete control over the locking and interior mutability strategy.
//!
//! [`Arc`]: std::sync::Arc
//! [`AsyncAccept`]: sock::AsyncAccept
//! [`AsyncDgramSock`]: sock::AsyncDgramSock
//! [`BufSource`]: buf::BufSource
//! [`DgramServer`]: dgram::DgramServer
//! [`MiddlewareBuilder::default()`]:
//!     middleware::builder::MiddlewareBuilder::default()
//! [`MiddlewareBuilder::push()`]:
//!     middleware::builder::MiddlewareBuilder::push()
//! [`MiddlewareChain`]: middleware::chain::MiddlewareChain
//! [`MiddlewareProcessor`]: middleware::processor::MiddlewareProcessor
//! [`Service`]: service::Service
//! [`Service::call()`]: service::Service::call()
//! [`ServiceCommand::Reconfigure`]: service::ServiceCommand::Reconfigure
//! [`StreamServer`]: stream::StreamServer
//! [`TcpServer`]: stream::TcpServer
//! [`UdpServer`]: dgram::UdpServer
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

mod connection;

pub mod buf;
pub mod dgram;
pub mod error;
pub mod message;
pub mod metrics;
pub mod middleware;
pub mod service;
pub mod sock;
pub mod stream;
pub mod util;

#[cfg(test)]
pub mod tests;

/// A Rust module for importing the types needed to create a [`Service`].
///
/// [`Service`]: crate::net::server::service::Service
pub mod prelude {
    pub use crate::base::wire::Composer;
    pub use crate::base::Message;
    pub use crate::dep::octseq::FreezeBuilder;
    pub use crate::dep::octseq::Octets;
    pub use crate::dep::octseq::OctetsBuilder;
    pub use crate::net::server::message::ContextAwareMessage;
    pub use crate::net::server::service::CallResult;
    pub use crate::net::server::service::Service;
    pub use crate::net::server::service::ServiceCommand;
    pub use crate::net::server::service::ServiceError;
    pub use crate::net::server::service::ServiceResult;
    pub use crate::net::server::service::ServiceResultItem;
    pub use crate::net::server::service::Transaction;
    pub use crate::net::server::util::mk_builder_for_target;
    pub use crate::net::server::util::mk_service;
    pub use crate::net::server::util::MkServiceRequest;
    pub use crate::net::server::util::MkServiceResult;
    pub use std::fmt::Debug;
    pub use std::sync::Arc;
}
