// Validator

#![cfg(feature = "unstable-validator")]

//! This module provides a DNSSEC validator as described in RFCs
//! [4033](https://www.rfc-editor.org/info/rfc4033),
//! [4034](https://www.rfc-editor.org/info/rfc4034),
//! [4035](https://www.rfc-editor.org/info/rfc4035),
//! [5155](https://www.rfc-editor.org/info/rfc5155), and
//! [6840](https://www.rfc-editor.org/info/rfc6840).
//! DNSSEC validation requires a trust anchor. A trust anchor can be
//! created using [anchor::TrustAnchors].
//! The trust anchor is then used, together with a
//! [net::client](crate::net::client)
//! transport and optionally a [context::Config] to create a DNSSEC
//! validation [context::ValidationContext].
//! The validation context provides the
//! method [validate_msg()](context::ValidationContext::validate_msg()) to
//! validate a reply message.
//!
//! # Caching
//! The validator has four caches:
//! 1) A `node` cache that caches the DNSSEC status and (if needed) DNSKEY
//!    records for a delegation.
//! 2) An `NSEC3` hash cache. This caches `NSEC3` hashes for names for
//!    specific parameters (algorithm and iteration count).
//! 3) An internal signature cache. This caches the result of signature
//!    verification for validating records need to determine the status of
//!    nodes.
//! 4) A user signature cache. This caches the result of signature
//!    verification for validating user data.
//!
//! # Limitations
//! * When invoked multiple times for the same name, for example a simulanous
//!   `A` and `AAAA` query, the validator will fetch `DS` and `DNSKEY`
//! record multiple times and will validate them in parallel.
//! * There is no prefetching. An expired cached node will be regenerated at
//!   next request that needs it.
//! * Currently `DS` and `DNSKEY` requests are issued sequentically. They
//!   can be issued (optimistically) in parallel to lower latency.
//! * There is currently no support for negative trust anchors.
//! * There is currently no support for generating a validation chain
//!   ([RFC 9102](https://www.rfc-editor.org/info/rfc9102)).
//! * There is currently no support for validating a chain.
//! * There is currently no support for the EDNS(0) CHAIN option
//!   ([RFC 7901](https://www.rfc-editor.org/info/rfc7901)).
//! * There is no support for fetch the IANA trust anchor over HTTP(S)
//!   ([RFC 7958](https://www.rfc-editor.org/info/rfc7958)).
//! * There is no support for automated updating of trust anchors
//!   ([RFC 5011](https://www.rfc-editor.org/info/rfc5011)).
//!
//! # Bugs
//! * The size of accepted `DS` and `DNSKEY` RRsets is not limited.
//!
//! # Example
//! ```no_run
//! # use domain::base::{MessageBuilder, Name, Rtype};
//! # use domain::net::client::dgram_stream;
//! # use domain::net::client::protocol::{TcpConnect, UdpConnect};
//! # use domain::net::client::request::{ComposeRequest, RequestMessage, SendRequest};
//! # use domain::validator::anchor::TrustAnchors;
//! # use domain::validator::context::{Config, ValidationContext};
//! # use std::net::{IpAddr, SocketAddr};
//! # use std::str::FromStr;
//! #
//! # async fn f() {
//! #     let server_addr = SocketAddr::new(IpAddr::from_str("::1").unwrap(), 53);
//! #
//! #     let udp_connect = UdpConnect::new(server_addr);
//! #     let tcp_connect = TcpConnect::new(server_addr);
//! #     let (udptcp_conn, transport) = dgram_stream::Connection::new(udp_connect, tcp_connect);
//! #
//! #     tokio::spawn(async move {
//! #         transport.run().await;
//! #         println!("UDP+TCP run exited");
//! #     });
//! #
//! #    let mut msg = MessageBuilder::new_vec();
//! #    msg.header_mut().set_rd(true);
//! #    let mut msg = msg.question();
//! #    msg.push((Name::vec_from_str("example.com").unwrap(), Rtype::AAAA))
//! #        .unwrap();
//!     let mut req = RequestMessage::new(msg);
//!     req.set_dnssec_ok(true);
//!
//!     // Send a query message.
//!     let mut request = udptcp_conn.send_request(req.clone());
//!
//!     // Get the reply
//!     println!("Wating for UDP+TCP reply");
//!     let mut reply = request.get_response().await.unwrap();
//!     println!("UDP+TCP reply: {reply:?}");
//!
//!     let ta = TrustAnchors::from_u8(b". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU= ;{id = 20326 (ksk), size = 2048b} ;;state=2 [  VALID  ] ;;count=0 ;;lastchange=1683463064 ;;Sun May  7 12:37:44 2023").unwrap();
//!     let mut conf = Config::new();
//!     conf.set_max_node_cache(10);
//!     conf.set_nsec3_iter_insecure(50);
//!     let vc = ValidationContext::with_config(ta, udptcp_conn, conf);
//!     let res = vc.validate_msg(&mut reply).await;
//!
//!     println!("Validation result: {res:?}");
//! # }
//! ```

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

pub mod anchor;
pub mod context;
mod group;
mod nsec;
mod utilities;
