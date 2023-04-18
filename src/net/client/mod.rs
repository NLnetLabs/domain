//! DNS transport protocols
#![cfg(feature = "net")]
#![cfg_attr(docsrs, doc(cfg(feature = "net")))]

pub mod octet_stream;
pub mod tcp_mutex;
pub mod tcp_channel;
