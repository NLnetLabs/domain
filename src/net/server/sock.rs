//! Network socket abstractions.
use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

//------------ AsyncDgramSock ------------------------------------------------

/// Asynchronous datagram sending & receiving.
///
/// Must be implemented by "network source"s to be used with a [`DgramServer`].
///
/// [`DgramServer`]: crate::net::server::stream::DgramServer.
pub trait AsyncDgramSock {
    /// Attempts to send data on the socket to a given address.
    fn poll_send_to(
        &self,
        cx: &mut Context,
        data: &[u8],
        dest: &SocketAddr,
    ) -> Poll<io::Result<usize>>;

    /// Attempts to receive a single datagram on the socket.
    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>>;

    /// Receives data from the socket, without removing it from the input queue. On success, returns the sending address of the datagram.
    fn poll_peek_from(
        &self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>>;
}

impl AsyncDgramSock for UdpSocket {
    fn poll_send_to(
        &self,
        cx: &mut Context,
        data: &[u8],
        dest: &SocketAddr,
    ) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send_to(self, cx, data, *dest)
    }

    fn poll_recv_from(
        &self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        UdpSocket::poll_recv_from(self, cx, buf)
    }

    fn poll_peek_from(
        &self,
        cx: &mut Context,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<SocketAddr>> {
        UdpSocket::poll_peek_from(self, cx, buf)
    }
}

//------------ AsyncAccept ---------------------------------------------------

/// Asynchronous accepting of incoming connections.
///
/// Must be implemented by "network source"s to be used with a
/// [`StreamServer`].
///
/// [`StreamServer`]: crate::net::server::stream::StreamServer.
pub trait AsyncAccept {
    /// The type of error that the trait impl produces.
    type Error: Send;

    /// The type of stream that the trait impl consumes.
    type StreamType: AsyncRead + AsyncWrite + Send + Sync + 'static;

    /// The type of [`std::future::Future`] that the trait impl returns.
    type Future: std::future::Future<Output = Result<Self::StreamType, Self::Error>>
        + Send;

    /// Polls to accept a new incoming connection to this listener.
    ///
    /// If there is no connection to accept, Poll::Pending is returned.
    #[allow(clippy::type_complexity)]
    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<io::Result<(Self::Future, SocketAddr)>>;
}

impl AsyncAccept for TcpListener {
    type Error = io::Error;
    type StreamType = TcpStream;
    type Future = std::future::Ready<Result<Self::StreamType, io::Error>>;

    #[allow(clippy::type_complexity)]
    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<io::Result<(Self::Future, SocketAddr)>> {
        TcpListener::poll_accept(self, cx).map(|res| {
            // TODO: Should we support some sort of callback here to set
            // arbitrary socket options? E.g. TCP keep alive ala
            // https://stackoverflow.com/a/75697898 ? Or is it okay that this
            // is the plain implementation and users who want to set things
            // like TCP keep alive would need to provide their own impl? (just
            // as the serve example currently does).
            res.map(|(stream, addr)| (std::future::ready(Ok(stream)), addr))
        })
    }
}
