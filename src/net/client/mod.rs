#![cfg_attr(
    not(feature = "unstable-client-transport"),
    doc = " The `unstable-client-transport` feature is necessary to enable this module."
)]
//! Sending requests and receiving responses.
//!
//! This module provides DNS transport protocols that allow sending a DNS
//! request and receiving the corresponding reply.
//!
//! Currently the following transport protocols are supported:
//! * [dgram] DNS over a datagram protocol, typically UDP.
//! * [stream] DNS over an octet stream protocol, typically TCP or TLS.
//!   Only a single connection is supported.
//!   The transport works as long as the connection continues to exist.
//! * [multi_stream] This is a layer on top of [stream] where new connections
//!   are established as old connections are closed (or fail).
//! * [dgram_stream] This is a combination of [dgram] and [multi_stream].
//!   This is typically needed because a request over UDP can receive
//!   a truncated response, which should be retried over TCP.
//! * [redundant] This transport multiplexes requests over a collection of
//!   transport connections. The [redundant] transport favors the connection
//!   with the lowest response time. Any of the other transports can be added
//!   as upstream transports.
//! * [load_balancer] This transport distributes requests over a collecton of
//!   transport connections. The [load_balancer] transport favors connections
//!   with the shortest outstanding request queue. Any of the other transports
//!   can be added as upstream transports.
#![cfg_attr(feature = "unstable-client-cache", doc = "* [cache]:")]
#![cfg_attr(not(feature = "unstable-client-cache",), doc = "* cache:")]
//!   This is a simple message cache provided as a pass through
//!   transport. The cache works with any of the other transports.
#![cfg_attr(feature = "tsig", doc = "* [tsig]:")]
#![cfg_attr(not(feature = "tsig",), doc = "* tsig:")]
//!   This is a TSIG request signer and response verifier provided as a
//!   pass through transport. The tsig transport works with any upstream
//!   transports so long as they don't modify the message once signed nor
//!   modify the response before it can be verified.
#![cfg_attr(
    all(
        feature = "unstable-validator",
        any(feature = "ring", feature = "openssl")
    ),
    doc = "* [validator]:"
)]
#![cfg_attr(
    not(all(
        feature = "unstable-validator",
        any(feature = "ring", feature = "openssl")
    )),
    doc = "* validator:"
)]
//!   This is a DNSSEC validator provided as a pass through transport.
//!   The validator works with any of the other transports.
//!
//! Sending a request and receiving the reply consists of four steps:
//! 1) Creating a request message,
//! 2) Creating a DNS transport,
//! 3) Sending the request, and
//! 4) Receiving the reply or replies.
//!
//! The first and second step are independent and can happen in any order.
//! The third step uses the resuts of the first and second step.
//! Finally, the fourth step uses the result of the third step.

//! # Creating a request message
//!
//! The DNS transport protocols expect a request message that implements the
//! [ComposeRequest][request::ComposeRequest] trait.
//! This trait allows transports to add ENDS(0) options, set flags, etc.
//! The [RequestMessage][request::RequestMessage] type implements this trait.
//! The [new][request::RequestMessage::new] method of RequestMessage creates
//! a new RequestMessage object based an existing messsage (that implements
//! ```Into<Message<Octs>>```).
//!
//! For example:
//! ```rust
//! # use domain::base::{Name, MessageBuilder, Rtype};
//! # use domain::net::client::request::RequestMessage;
//! let mut msg = MessageBuilder::new_vec();
//! msg.header_mut().set_rd(true);
//! let mut msg = msg.question();
//! msg.push(
//!     (Name::vec_from_str("example.com").unwrap(), Rtype::AAAA)
//! ).unwrap();
//! let req = RequestMessage::new(msg);
//! ```

//! # Creating a DNS transport
//!
//! Creating a DNS transport typically involves creating a configuration
//! object, creating the underlying network connection, creating the
//! DNS transport and running a ```run``` method as a separate task. This
//! is illustrated in the following example:
//! ```rust
//! # use domain::net::client::multi_stream;
//! # use domain::net::client::protocol::TcpConnect;
//! # use domain::net::client::request::SendRequest;
//! # use std::net::{IpAddr, SocketAddr};
//! # use std::str::FromStr;
//! # use std::time::Duration;
//! # async fn _test() {
//! # let server_addr = SocketAddr::new(IpAddr::from_str("::1").unwrap(), 53);
//! let mut multi_stream_config = multi_stream::Config::default();
//! multi_stream_config.stream_mut().set_response_timeout(
//!     Duration::from_millis(100),
//! );
//! let tcp_connect = TcpConnect::new(server_addr);
//! let (tcp_conn, transport) = multi_stream::Connection::with_config(
//!     tcp_connect, multi_stream_config
//! );
//! tokio::spawn(transport.run());
//! # let req = domain::net::client::request::RequestMessage::new(
//! #     domain::base::MessageBuilder::new_vec()
//! # ).unwrap();
//! # let mut request = tcp_conn.send_request(req);
//! # }
//! ```
//! # Sending the request
//!
//! A connection implements the [SendRequest][request::SendRequest] trait.
//! This trait provides a single method,
//! [send_request][request::SendRequest::send_request] and returns an object
//! that provides the response.
//!
//! For example:
//! ```no_run
//! # use domain::net::client::request::{RequestMessageMulti, SendRequest};
//! # use std::net::{IpAddr, SocketAddr};
//! # use std::str::FromStr;
//! # async fn _test() {
//! # let (tls_conn, _) = domain::net::client::stream::Connection::<_, RequestMessageMulti<Vec<u8>>>::new(
//! #     domain::net::client::protocol::TcpConnect::new(
//! #         SocketAddr::new(IpAddr::from_str("::1").unwrap(), 53)
//! #     )
//! # );
//! # let req = domain::net::client::request::RequestMessage::new(
//! #     domain::base::MessageBuilder::new_vec()
//! # ).unwrap();
//! let mut request = tls_conn.send_request(req);
//! # }
//! ```
//! where ```tls_conn``` is a transport connection for DNS over TLS.

//! # Receiving the response
//!
//! The [send_request][request::SendRequest::send_request] method returns an
//! object that implements the [GetResponse][request::GetResponse] trait.
//! This trait provides a single method,
//! [get_response][request::GetResponse::get_response], which returns the
//! DNS response message or an error. This method is intended to be
//! cancelation safe.
//!
//! For example:
//! ```no_run
//! # use crate::domain::net::client::request::{RequestMessageMulti, SendRequest};
//! # use std::net::{IpAddr, SocketAddr};
//! # use std::str::FromStr;
//! # async fn _test() {
//! # let (tls_conn, _) = domain::net::client::stream::Connection::<_, RequestMessageMulti<Vec<u8>>>::new(
//! #     domain::net::client::protocol::TcpConnect::new(
//! #         SocketAddr::new(IpAddr::from_str("::1").unwrap(), 53)
//! #     )
//! # );
//! # let req = domain::net::client::request::RequestMessage::new(
//! #     domain::base::MessageBuilder::new_vec()
//! # ).unwrap();
//! # let mut request = tls_conn.send_request(req);
//! let reply = request.get_response().await;
//! # }
//! ```
//!
//! <div class="warning">
//!
//! **Support for multiple responses:**
//!
//! [RequestMessage][request::RequestMessage] is designed for the most common
//! use case: single request, single response.
//!
//! However, zone transfers (e.g. using the `AXFR` or `IXFR` query types) can
//! result in multiple responses. Attempting to create a
//! [RequestMessage][request::RequestMessage] for such a query will result in
//! [Error::FormError][request::Error::FormError].
//!
//! For zone transfers you should use
//! [RequestMessageMulti][request::RequestMessageMulti] instead which can be
//! used like so:
//!
//! ```no_run
//! # use crate::domain::net::client::request::{RequestMessage, SendRequestMulti};
//! # use std::net::{IpAddr, SocketAddr};
//! # use std::str::FromStr;
//! # async fn _test() {
//! # let (conn, _) = domain::net::client::stream::Connection::<RequestMessage<Vec<u8>>, _>::new(
//! #     domain::net::client::protocol::TcpConnect::new(
//! #         SocketAddr::new(IpAddr::from_str("::1").unwrap(), 53)
//! #     )
//! # );
//! # let req = domain::net::client::request::RequestMessageMulti::new(
//! #     domain::base::MessageBuilder::new_vec()
//! # ).unwrap();
//! # let mut request = conn.send_request(req);
//! while let Ok(reply) = request.get_response().await {
//!     // ...
//! }
//! # }
//! ```
//!
//! </div>
//!

//! # Limitations
//!
//! The current implementation has the following limitations:
//! * The [dgram] transport does not support DNS Cookies
//!   ([`RFC 7873`](https://tools.ietf.org/html/rfc7873)
//!   Domain Name System (DNS) Cookies).
//! * The [multi_stream] transport does not support timeouts or other limits on
//!   the number of attempts to open a connection. The caller has to
//!   implement a timeout mechanism.
#![cfg_attr(
    feature = "unstable-client-cache",
    doc = "* The [cache] transport does not support:"
)]
#![cfg_attr(
    not(feature = "unstable-client-cache"),
    doc = "* The cache transport does not support:"
)]
//!   * Prefetching. In this context, prefetching means updating a cache entry
//!     before it expires.
//!   * [RFC 8767](https://tools.ietf.org/html/rfc8767)
//!     (Serving Stale Data to Improve DNS Resiliency)
//!   * [RFC 7871](https://tools.ietf.org/html/rfc7871)
//!     (Client Subnet in DNS Queries)
//!   * [RFC 8198](https://tools.ietf.org/html/rfc8198)
//!     (Aggressive Use of DNSSEC-Validated Cache)

//! # Example with various transport connections
//! ```no_run
#![doc = include_str!("../../../examples/client-transports.rs")]
//! ```

#![cfg(feature = "unstable-client-transport")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-client-transport")))]
#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

#[cfg(feature = "unstable-client-cache")]
pub mod cache;
pub mod dgram;
pub mod dgram_stream;
pub mod load_balancer;
pub mod multi_stream;
pub mod protocol;
pub mod redundant;
pub mod request;
pub mod stream;
pub mod tsig;
pub mod validator;
pub mod validator_test;
