//! Asynchronous DNS serving.
//!
//! Warning: This is incomplete exploratory proof-of-concept code only
//! at this point.
#![cfg(feature = "serve")]
#![cfg_attr(docsrs, doc(cfg(feature = "serve")))]

pub use self::server::{DgramServer as UdpServer, StreamServer as TcpServer};

pub mod server;
pub mod sock;
