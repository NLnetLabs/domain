//! Sending requests and receiving responses.

//! # Example with various transport connections
//! ```
#![doc = include_str!("../../../examples/client-transports.rs")]
//! ```

#![cfg(feature = "unstable-client-transport")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-client-transport")))]

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

pub mod dgram;
pub mod dgram_stream;
pub mod multi_stream;
pub mod octet_stream;
pub mod protocol;
pub mod redundant;
pub mod request;
