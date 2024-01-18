use super::buf::BufSource;
use super::dgram::DgramServer;
use super::stream::StreamServer;
use crate::base::Message;
use tokio::net::{TcpListener, UdpSocket};

pub type UdpServer<Buf, Svc> =
    DgramServer<UdpSocket, Buf, Svc, Message<<Buf as BufSource>::Output>>;

pub type TcpServer<Buf, Svc> =
    StreamServer<TcpListener, Buf, Svc, Message<<Buf as BufSource>::Output>>;
