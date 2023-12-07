//! DNS transport protocols
#![cfg(feature = "net")]
#![cfg_attr(docsrs, doc(cfg(feature = "net")))]

//! # Example with various transport connections
//! ```
#![doc = include_str!("../../../examples/client-transports.rs")]
//! ```

pub mod async_connect;
pub mod base_message_builder;
pub mod bmb;
pub mod error;
pub mod multi_stream;
pub mod octet_stream;
pub mod query;
pub mod redundant;
pub mod tcp_connect;
pub mod tls_connect;
pub mod udp;
pub mod udp_tcp;
