//! Network socket abstractions.

use futures::Future;
use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
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
    ) -> Poll<io::Result<usize>>;

    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Self::Addr>>;

    fn poll_peek_from(
        &self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<Self::Addr>>;
}

impl AsyncDgramSock for UdpSocket {
    type Addr = SocketAddr;

    fn poll_send_to(
        &self,
        cx: &mut Context,
        data: &[u8],
        dest: &Self::Addr,
    ) -> Poll<Result<usize, io::Error>> {
        UdpSocket::poll_send_to(self, cx, data, *dest)
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<Self::Addr, io::Error>> {
        UdpSocket::poll_recv_from(self, cx, buf)
    }

    fn poll_peek_from(
        &self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<Self::Addr, io::Error>> {
        UdpSocket::poll_peek_from(self, cx, buf)
    }
}

//------------ AsyncAccept ---------------------------------------------------

pub trait AsyncAccept {
    type Addr: Sized + Send;
    type Error: Send;
    type StreamType: AsyncRead + AsyncWrite + Send + Sync + 'static;
    type Stream: Future<Output = Result<Self::StreamType, Self::Error>> + Send;

    #[allow(clippy::type_complexity)]
    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, Self::Addr), io::Error>>;
}

impl AsyncAccept for TcpListener {
    type Addr = SocketAddr;
    type Error = io::Error;
    type StreamType = TcpStream;
    type Stream = futures::future::Ready<Result<Self::StreamType, io::Error>>;

    #[allow(clippy::type_complexity)]
    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Stream, Self::Addr), io::Error>> {
        TcpListener::poll_accept(self, cx).map(|res| {
            res.map(|(stream, addr)| {
                (futures::future::ready(Ok(stream)), addr)
            })
        })
    }
}
