//! Asynchronous DNS serving.
//!
//! Warning: This is incomplete exploratory proof-of-concept code only
//! at this point.
#![cfg(feature = "serve")]
#![cfg_attr(docsrs, doc(cfg(feature = "serve")))]

use tokio::net::{TcpListener, UdpSocket};

pub type UdpServer<Buf, Svc> = dgram::DgramServer<UdpSocket, Buf, Svc>;
pub type TcpServer<Buf, Svc> = stream::StreamServer<TcpListener, Buf, Svc>;

pub mod buf;
pub mod dgram;
pub mod server;
pub mod service;
pub mod sock;
pub mod stream;
