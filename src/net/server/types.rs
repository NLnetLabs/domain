use super::buf::{BufSource, VecBufSource};
use super::dgram::DgramServer;
use super::stream::StreamServer;
use crate::base::Message;
use tokio::net::{TcpListener, UdpSocket};

pub type UdpServer<Svc> = DgramServer<
    UdpSocket,
    VecBufSource,
    Svc,
    Message<<VecBufSource as BufSource>::Output>,
>;

pub type TcpServer<Svc> = StreamServer<
    TcpListener,
    VecBufSource,
    Svc,
    Message<<VecBufSource as BufSource>::Output>,
>;
