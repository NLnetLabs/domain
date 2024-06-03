// Validator

#![cfg(feature = "unstable-validator")]

//! This module provides a DNSSEC validator.
//! DNSSEC validation requires a trust anchor. A trust anchor can be
//! created using [anchor::TrustAnchors].
//! The trust anchor is then used, together with a [crate::net::client]
//! transport and optionally a [context::Config] to create a DNSSEC
//! validation [context::ValidationContext].
//! The validation context then provides the
//! method [context::ValidationContext::validate_msg()] to validate a
//! reply message.
//!
//! Example:
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
//!     let reply = request.get_response().await.unwrap();
//!     println!("UDP+TCP reply: {reply:?}");
//!
//!     let ta = TrustAnchors::from_u8(b". 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU= ;{id = 20326 (ksk), size = 2048b} ;;state=2 [  VALID  ] ;;count=0 ;;lastchange=1683463064 ;;Sun May  7 12:37:44 2023").unwrap();
//!     let mut conf = Config::new();
//!     conf.set_max_node_cache(10);
//!     conf.set_nsec3_iter_insecure(50);
//!     let vc = ValidationContext::with_config(ta, udptcp_conn, conf);
//!     let res = vc.validate_msg(&reply).await;
//!
//!     println!("Validation result: {res:?}");
//! # }
//! ```

pub mod anchor;
pub mod context;
mod group;
mod nsec;
pub mod types;
mod utilities;
