//! Network socket abstractions.

use std::io;
use std::net::SocketAddr;
use std::ops::Deref;
use std::task::{Context, Poll};
use tokio::io::ReadBuf;
use tokio::net::{TcpListener, TcpStream, UdpSocket};


//------------ AsyncDgramSock ------------------------------------------------

/// Asynchronous sending of datagrams.
pub trait AsyncDgramSock {
    type Addr: Sized + Send + Sync + 'static;

    fn poll_send_to(
        &self,
        cx: &mut Context,
        data: &[u8],
        dest: &Self::Addr,
    ) -> Poll<Result<usize, io::Error>>;

    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<Self::Addr, io::Error>>;
}

impl AsyncDgramSock for UdpSocket {
    type Addr = SocketAddr;

    fn poll_send_to(
        &self,
        cx: &mut Context,
        data: &[u8],
        dest: &Self::Addr,
    ) -> Poll<Result<usize, io::Error>> {
        UdpSocket::poll_send_to(self.deref(), cx, data, *dest)
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<Self::Addr, io::Error>> {
        UdpSocket::poll_recv_from(self.deref(), cx, buf)
    }
}


//------------ AsyncAccept ---------------------------------------------------

pub trait AsyncAccept {
    type Addr: Sized + Send;
    type Stream;
    
    #[allow(clippy::type_complexity)]
    fn poll_accept(
        &self, cx: &mut Context
    ) -> Poll<Result<(Self::Stream, Self::Addr), io::Error>>;
}

impl AsyncAccept for TcpListener {
    type Addr = SocketAddr;
    type Stream = TcpStream;

    #[allow(clippy::type_complexity)]
    fn poll_accept(
        &self, cx: &mut Context
    ) -> Poll<Result<(Self::Stream, Self::Addr), io::Error>> {
        TcpListener::poll_accept(self, cx)
    }
}

