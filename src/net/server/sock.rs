//! Network socket abstractions.
use std::io;
use std::net::SocketAddr;
use std::task::{Context, Poll};

use std::boxed::Box;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::ReadBuf;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

//------------ AsyncDgramSock ------------------------------------------------

/// Asynchronous datagram sending & receiving.
///
/// Must be implemented by "network source"s to be used with a
/// [`DgramServer`].
///
/// When reading the server will wait until [`Self::readable`] succeeds and
/// then call `try_recv_buf_from()`.
///
/// # Design notes
///
/// When the underlying socket implementation is [`tokio::net::UdpSocket`]
/// this pattern scales better than using `poll_recv_from()` as the latter
/// causes the socket to be locked for exclusive access even if it was
/// [`Arc::clone`]d.
///
/// With the `readable()` then `try_recv_buf_from()` pattern one can
/// [`Arc::clone`] the socket and use it with multiple server instances at
/// once for greater throughput without any such locking occurring.
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

    /// Waits for the socket to become readable.
    ///
    /// The function may complete without the socket being readable. This is a
    /// false-positive and attempting a try_recv() will return with
    /// io::ErrorKind::WouldBlock.
    fn readable(
        &self,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_ + Send>>;

    /// Tries to receive a single datagram message on the socket. On success,
    /// returns the number of bytes read and the origin.
    ///
    /// When there is no pending data, Err(io::ErrorKind::WouldBlock) is
    /// returned. This can happen if there are multiple consumers of this
    /// socket and one of the other consumers read the data first.
    ///
    /// This function is usually paired with readable().
    fn try_recv_buf_from(
        &self,
        buf: &mut ReadBuf<'_>,
    ) -> io::Result<(usize, SocketAddr)>;
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

    fn readable(
        &self,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_ + Send>> {
        Box::pin(UdpSocket::readable(self))
    }

    fn try_recv_buf_from(
        &self,
        buf: &mut ReadBuf<'_>,
    ) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::try_recv_buf_from(self, buf)
    }
}

impl AsyncDgramSock for Arc<UdpSocket> {
    fn poll_send_to(
        &self,
        cx: &mut Context,
        data: &[u8],
        dest: &SocketAddr,
    ) -> Poll<io::Result<usize>> {
        UdpSocket::poll_send_to(self, cx, data, *dest)
    }

    fn readable(
        &self,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + '_ + Send>> {
        Box::pin(UdpSocket::readable(self))
    }

    fn try_recv_buf_from(
        &self,
        buf: &mut ReadBuf<'_>,
    ) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::try_recv_buf_from(self, buf)
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
    type Error;

    /// The type of stream that the trait impl consumes.
    type StreamType;

    /// The type of [`std::future::Future`] that the trait impl returns.
    type Future: std::future::Future<
        Output = Result<Self::StreamType, Self::Error>,
    >;

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
