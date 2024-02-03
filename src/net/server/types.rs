use super::buf::VecBufSource;
use super::dgram::DgramServer;
use super::stream::StreamServer;
use tokio::net::{TcpListener, UdpSocket};

pub type UdpServer<Svc> = DgramServer<UdpSocket, VecBufSource, Svc>;

pub type TcpServer<Svc> = StreamServer<TcpListener, VecBufSource, Svc>;
