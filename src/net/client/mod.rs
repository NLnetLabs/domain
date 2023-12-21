//! DNS transport protocols
#![cfg(feature = "net")]
#![cfg_attr(docsrs, doc(cfg(feature = "net")))]

//! # Example with various transport connections
//! ```
#![doc = include_str!("../../../examples/client-transports.rs")]
//! ```

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

pub mod multi_stream;
pub mod octet_stream;
pub mod protocol;
pub mod redundant;
pub mod request;
pub mod udp;
pub mod udp_tcp;
