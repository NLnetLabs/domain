//! DNS transport protocols
#![cfg(feature = "net")]
#![cfg_attr(docsrs, doc(cfg(feature = "net")))]

//! # Example with various transport connections
//! ```
#![doc = include_str!("../../../examples/client-transports.rs")]
//! ```

pub mod error;
pub mod factory;
pub mod multi_stream;
pub mod octet_stream;
pub mod query;
pub mod redundant;
pub mod tcp_channel;
pub mod tcp_factory;
pub mod tcp_mutex;
pub mod tls_factory;
pub mod udp;
pub mod udp_tcp;
