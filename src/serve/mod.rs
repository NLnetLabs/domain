//! Asynchronous DNS serving.
//!
//! Warning: This is incomplete exploratory proof-of-concept code only
//! at this point.
#![cfg(feature = "serve")]
#![cfg_attr(docsrs, doc(cfg(feature = "serve")))]

use tokio::net::{TcpListener, UdpSocket};

use self::server::{DgramServer, StreamServer};

pub type UdpServer<Buf, Svc> = DgramServer<UdpSocket, Buf, Svc>;
pub type TcpServer<Buf, Svc> = StreamServer<TcpListener, Buf, Svc>;

pub mod server;
pub mod sock;
