#![cfg_attr(
    not(feature = "unstable-server-transport"),
    doc = " The `unstable-server-transport` feature is necessary to enable this module."
)]
//! Asynchronous DNS serving.
//!
//! TODO: Re-read https://datatracker.ietf.org/doc/html/rfc9210.
//!
//! This module provides the basis for implementing your own DNS server. It
//! handles the receiving of requests and sending of responses but does not
//! interpret or act upon the received or sent DNS messages. Instead you must
//! supply a [`Service`] impl that acts on received DNS requests and supplies
//! appropriate DNS responses.
//!
//! While DNS servers historically communicated primarily via datagram based
//! network transport protocols, using stream based network transport
//! protocols only for zone transfers, modern DNS servers increasingly need to
//! support stream based network transport protocols, e.g. to handle messages
//! that exceed the maximum size supported by datagram protocols. This module
//! provides support for both datagram and stream based network transport
//! protocols via the [`DgramServer`] and [`StreamServer`] types respectively.
//!
//! # Datagram (e.g. UDP) servers
//!
//! [`DgramServer`] can communicate via any type that implements the
//! [`AsyncDgramSock`] trait, with an implementation provided for
//! [`tokio::net::UdpSocket`].
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
//! The type alias [`TcpServer`] is! provided for convenience for
//! implementations based on [`tokio::net::TcpListener`].
//!
//! # Memory allocation
//!
//! The allocation of buffers for receiving DNS messages is delegated to an
//! implementation of the [`BufSource`] trait, giving you fine control over
//! the memory allocation strategy in use.
//!
//! # Service behaviour
//!
//! The interpretation of DNS requests and construction of DNS responses
//! is delegated to a user supplied implementation of the [`Service`] trait.
//!
//! # Usage
//!
//! Using a [`DgramServer`] and/or [`StreamServer`] involves passing your
//! [`Service`] implementation to the constructor and then invoking a `run` fn
//! to execute the server. By retaining a reference to the server one can
//! terminate it explicitly by a call to its 'shutdown' fn.
//!
//! [`AsyncAccept`]: sock::AsyncAccept
//! [`AsyncDgramSock`]: sock::AsyncDgramSock
//! [`BufSource`]: buf::BufSource
//! [`DgramServer`]: dgram::DgramServer
//! [`Service`]: service::Service
//! [`StreamServer`]: stream::StreamServer
//! [`tokio::io::AsyncRead`]: https://docs.rs/tokio/latest/tokio/io/trait.AsyncRead.html
//! [`tokio::io::AsyncWrite`]: https://docs.rs/tokio/latest/tokio/io/trait.AsyncWrite.html
//! [`tokio::net::TcpListener`]: https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html
//! [`tokio::net::TcpStream`]: https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html
//! [`tokio::net::UdpSocket`]: https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html

#![cfg(feature = "serve")]
#![cfg_attr(docsrs, doc(cfg(feature = "serve")))]

use tokio::net::{TcpListener, UdpSocket};

use crate::base::Message;
use buf::BufSource;

pub type UdpServer<Buf, Svc> = dgram::DgramServer<
    UdpSocket,
    Buf,
    Svc,
    Message<<Buf as BufSource>::Output>,
>;
pub type TcpServer<Buf, Svc> = stream::StreamServer<
    TcpListener,
    Buf,
    Svc,
    Message<<Buf as BufSource>::Output>,
>;

pub mod buf;
pub mod dgram;
pub mod server;
pub mod service;
pub mod sock;
pub mod stream;
