use std::net::UdpSocket;

use tokio::net::TcpListener;

use self::{dgram::server::DgramServer, stream::server::StreamServer};

use super::buf::VecBufSource;

pub mod dgram;
pub mod stream;

pub type UdpServer<Svc> = DgramServer<UdpSocket, VecBufSource, Svc>;
pub type TcpServer<Svc> = StreamServer<TcpListener, VecBufSource, Svc>;
