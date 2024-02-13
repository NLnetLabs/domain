#![cfg_attr(
    not(feature = "unstable-client-transport"),
    doc = " The `unstable-client-transport` feature is necessary to enable this module."
)]
//! Sending requests and receiving responses.
//!
//! This module provides DNS transport protocols that allow sending a DNS
//! request and receiving the corresponding reply.
//!
//! Sending a request and receiving the reply consists of four steps:
//! 1) Creating a request message,
//! 2) Creating a DNS transport,
//! 3) Sending the request, and
//! 4) Receiving the reply.
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
//! The [new][request::RequestMessage::new] method of RequestMessage create
//! a new RequestMessage object based an existing messsage (that implements
//! ```Into<Message<Octs>>```).
//!
//! For example:
//! ```rust
//! # use domain::base::{Dname, MessageBuilder, Rtype};
//! # use domain::net::client::request::RequestMessage;
//! let mut msg = MessageBuilder::new_vec();
//! msg.header_mut().set_rd(true);
//! let mut msg = msg.question();
//! msg.push(
//!     (Dname::vec_from_str("example.com").unwrap(), Rtype::Aaaa)
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
//! # use std::time::Duration;
//! # async fn _test() {
//! # let server_addr = String::from("127.0.0.1:53");
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
//! # );
//! # let mut request = tcp_conn.send_request(req);
//! # }
//! ```
//! The currently implemented DNS transports have the following layering. At
//! the lowest layer are [dgram] and [stream]. The dgram transport is used for
//! DNS over UDP, the stream transport is used for DNS over a single TCP or
//! TLS connection. The transport works as long as the connection continuous
//! to exist.
//! The [multi_stream] transport is layered on top of stream, and creates new
//! TCP or TLS connections when old ones terminates.
//! Next, [dgram_stream] combines the dgram transport with the multi_stream
//! transport. This is typically needed because a request over UDP can receive
//! a truncated response, which should be retried over TCP.
//! Finally, the [redundant] transport can select the best transport out of
//! a collection of underlying transports.

//! # Sending the request
//!
//! A DNS transport implements the [SendRequest][request::SendRequest] trait.
//! This trait provides a single method,
//! [send_request][request::SendRequest::send_request] and returns an object
//! that provides the response.
//!
//! For example:
//! ```no_run
//! # use domain::net::client::request::SendRequest;
//! # async fn _test() {
//! # let (tls_conn, _) = domain::net::client::stream::Connection::new(
//! #     domain::net::client::protocol::TcpConnect::new(
//! #         String::from("127.0.0.1:53")
//! #     )
//! # );
//! # let req = domain::net::client::request::RequestMessage::new(
//! #     domain::base::MessageBuilder::new_vec()
//! # );
//! let mut request = tls_conn.send_request(req);
//! # }
//! ```
//! where ```tls_conn``` is a transport connection for DNS over TLS.

//! # Receiving the request
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
//! # use crate::domain::net::client::request::SendRequest;
//! # async fn _test() {
//! # let (tls_conn, _) = domain::net::client::stream::Connection::new(
//! #     domain::net::client::protocol::TcpConnect::new(
//! #         String::from("127.0.0.1:53")
//! #     )
//! # );
//! # let req = domain::net::client::request::RequestMessage::new(
//! #     domain::base::MessageBuilder::new_vec()
//! # );
//! # let mut request = tls_conn.send_request(req);
//! let reply = request.get_response().await;
//! # }
//! ```

//! # Example with various transport connections
//! ```no_run
#![doc = include_str!("../../../examples/client-transports.rs")]
//! ```

#![cfg(feature = "unstable-client-transport")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-client-transport")))]
#![warn(missing_docs)]

pub mod dgram;
pub mod dgram_stream;
pub mod multi_stream;
pub mod protocol;
pub mod redundant;
pub mod request;
pub mod stream;

use self::request::{GetResponse, RequestMessage, SendRequest};
use std::boxed::Box;
use std::vec::Vec;

impl SendRequest<RequestMessage<Vec<u8>>> for () {
    fn send_request(
        &self,
        _request_msg: RequestMessage<Vec<u8>>,
    ) -> Box<dyn GetResponse + Send> {
        todo!()
    }
}
