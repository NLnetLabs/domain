//! DNS transport protocols
#![cfg(feature = "net")]
#![cfg_attr(docsrs, doc(cfg(feature = "net")))]

//! # Example with various transport connections
//! ```
#![doc = include_str!("../../../examples/client-transports.rs")]
//! ```

pub mod base_message_builder;
pub mod bmb;
pub mod connection_stream;
pub mod error;
pub mod multi_stream;
pub mod octet_stream;
pub mod query;
pub mod redundant;
pub mod tcp_conn_stream;
pub mod tls_conn_stream;
pub mod udp;
pub mod udp_tcp;
