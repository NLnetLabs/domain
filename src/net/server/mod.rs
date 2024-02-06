#![cfg_attr(
    not(feature = "unstable-server-transport"),
    doc = " The `unstable-server-transport` feature is necessary to enable this module."
)]
//! Asynchronous DNS serving.
//!
//! TODO: Re-read https://datatracker.ietf.org/doc/html/rfc9210.
//!
//! This module provides the basis for implementing your own DNS server. It
//! handles the receiving of requests and sending of responses but does not
//! interpret or act upon the received or sent DNS messages. Instead you must
//! supply a [`Service`] impl that acts on received DNS requests and supplies
//! appropriate DNS responses.
//!
//! While DNS servers historically communicated primarily via datagram based
//! network transport protocols, using stream based network transport
//! protocols only for zone transfers, modern DNS servers increasingly need to
//! support stream based network transport protocols, e.g. to handle messages
//! that exceed the maximum size supported by datagram protocols. This module
//! provides support for both datagram and stream based network transport
//! protocols via the [`DgramServer`] and [`StreamServer`] types respectively.
//!
//! # Datagram (e.g. UDP) servers
//!
//! [`DgramServer`] can communicate via any type that implements the
//! [`AsyncDgramSock`] trait, with an implementation provided for
//! [`tokio::net::UdpSocket`].
//!
//! The type alias [`UdpServer`] is provided for convenience for
//! implementations baed on [`tokio::net::UdpSocket`].
//!
//! # Stream (e.g. TCP) servers
//!
//! [`StreamServer`] can communicate via any type that implements the
//! [`AsyncAccept`] trait, and whose associated stream type implements the
//! [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`] traits, with an
//! implementation provided for [`tokio::net::TcpListener`] and associated
//! stream type [`tokio::net::TcpStream`].
//!
//! The type alias [`TcpServer`] is! provided for convenience for
//! implementations based on [`tokio::net::TcpListener`].
//!
//! # Memory allocation
//!
//! The allocation of buffers for receiving DNS messages is delegated to an
//! implementation of the [`BufSource`] trait, giving you fine control over
//! the memory allocation strategy in use.
//!
//! # Service behaviour
//!
//! The interpretation of DNS requests and construction of DNS responses
//! is delegated to a user supplied implementation of the [`Service`] trait.
//!
//! # Usage
//!
//! Using a [`DgramServer`] and/or [`StreamServer`] involves passing your
//! [`Service`] implementation to the constructor and then invoking a `run` fn
//! to execute the server. By retaining a reference to the server one can
//! terminate it explicitly by a call to its 'shutdown' fn.
//!
//! [`AsyncAccept`]: sock::AsyncAccept
//! [`AsyncDgramSock`]: sock::AsyncDgramSock
//! [`BufSource`]: buf::BufSource
//! [`DgramServer`]: dgram::DgramServer
//! [`Service`]: service::Service
//! [`StreamServer`]: stream::StreamServer
//! [`tokio::io::AsyncRead`]: https://docs.rs/tokio/latest/tokio/io/trait.AsyncRead.html
//! [`tokio::io::AsyncWrite`]: https://docs.rs/tokio/latest/tokio/io/trait.AsyncWrite.html
//! [`tokio::net::TcpListener`]: https://docs.rs/tokio/latest/tokio/net/struct.TcpListener.html
//! [`tokio::net::TcpStream`]: https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html
//! [`tokio::net::UdpSocket`]: https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html

#![cfg(feature = "unstable-server-transport")]
#![cfg_attr(docsrs, doc(cfg(feature = "unstable-server-transport")))]
// #![warn(missing_docs)]

pub mod buf;
pub mod connection;
pub mod dgram;
pub mod error;
pub mod metrics;
pub mod service;
pub mod sock;
pub mod stream;
pub mod types;

pub mod middleware;
#[cfg(test)]
pub mod tests;

use core::{ops::ControlFlow, sync::atomic::Ordering};
use std::{future::Future, net::SocketAddr, sync::Arc};

pub use types::*;

use crate::base::{wire::Composer, Message};

use self::{
    buf::BufSource,
    error::Error,
    metrics::ServerMetrics,
    middleware::chain::MiddlewareChain,
    service::{
        CallResult, Service, ServiceError, ServiceResult, ServiceResultItem,
        Transaction,
    },
};

//------------ ContextAwareMessage -------------------------------------------

pub struct ContextAwareMessage<T> {
    message: T,
    received_over_tcp: bool,
    client_addr: std::net::SocketAddr,
}

impl<T> ContextAwareMessage<T> {
    pub fn new(
        message: T,
        received_over_tcp: bool,
        client_addr: std::net::SocketAddr,
    ) -> Self {
        Self {
            message,
            received_over_tcp,
            client_addr,
        }
    }

    pub fn received_over_tcp(&self) -> bool {
        self.received_over_tcp
    }

    pub fn client_addr(&self) -> std::net::SocketAddr {
        self.client_addr
    }

    pub fn into_inner(self) -> T {
        self.message
    }
}

impl<T> core::ops::Deref for ContextAwareMessage<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.message
    }
}

impl<T> core::ops::DerefMut for ContextAwareMessage<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.message
    }
}

//------------ service() -----------------------------------------------------

pub fn mk_service<RequestOctets, Target, Error, SingleFut, T, Metadata>(
    msg_handler: T,
    metadata: Metadata,
) -> impl Service<RequestOctets, Error = Error, Target = Target, Single = SingleFut>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default + Send + Sync + 'static,
    Error: Send + Sync + 'static,
    SingleFut: Future<Output = ServiceResultItem<Target, Error>> + Send,
    Metadata: Clone,
    T: Fn(
        Arc<ContextAwareMessage<Message<RequestOctets>>>,
        Metadata,
    ) -> ServiceResult<Target, Error, SingleFut>,
{
    move |msg| msg_handler(msg, metadata.clone())
}

//----------- Server --------------------------------------------------------

pub trait Server<Source, Buf, Svc>
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    #[must_use]
    fn new(source: Source, buf: Arc<Buf>, service: Arc<Svc>) -> Self;

    #[must_use]
    fn with_middleware(
        self,
        middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
    ) -> Self;

    /// Get a reference to the source for this server.
    #[must_use]
    fn source(&self) -> Arc<Source>;

    /// Get a reference to the metrics for this server.
    #[must_use]
    fn metrics(&self) -> Arc<ServerMetrics>;

    /// Start the server.
    fn run(&self) -> impl Future<Output = ()> + Send
    where
        Svc::Single: Send;

    /// Stop the server.
    fn shutdown(&self) -> Result<(), Error>;
}

trait MessageProcessor<Buf, Svc>
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    type State: Send + 'static;

    async fn process_message(
        buf: <Buf as BufSource>::Output,
        addr: SocketAddr,
        state: Self::State,
        middleware_chain: Option<MiddlewareChain<Buf::Output, Svc::Target>>,
        svc: &Arc<Svc>,
        metrics: Arc<ServerMetrics>,
    ) -> Result<(), ServiceError<Svc::Error>>
    where
        Svc::Single: Send,
    {
        let (frozen_request, pp_res) = Self::preprocess_request(
            buf,
            addr,
            middleware_chain.as_ref(),
            &metrics,
        )?;

        let (txn, aborted_pp_idx) = match pp_res {
            ControlFlow::Continue(()) => {
                let txn = svc.call(frozen_request.clone())?;
                (txn, None)
            }
            ControlFlow::Break((txn, aborted_pp_idx)) => {
                (txn, Some(aborted_pp_idx))
            }
        };

        Self::postprocess_response(
            frozen_request,
            state,
            middleware_chain,
            txn,
            aborted_pp_idx,
            metrics,
        );

        Ok(())
    }

    #[allow(clippy::type_complexity)]
    fn preprocess_request(
        buf: <Buf as BufSource>::Output,
        addr: SocketAddr,
        middleware_chain: Option<&MiddlewareChain<Buf::Output, Svc::Target>>,
        metrics: &Arc<ServerMetrics>,
    ) -> Result<
        (
            Arc<ContextAwareMessage<Message<Buf::Output>>>,
            ControlFlow<(
                Transaction<
                    ServiceResultItem<Svc::Target, Svc::Error>,
                    Svc::Single,
                >,
                usize,
            )>,
        ),
        ServiceError<Svc::Error>,
    >
    where
        Svc::Single: Send,
    {
        let request = Message::from_octets(buf)
            .map_err(|_| ServiceError::Other("short message".into()))?;

        let mut request = ContextAwareMessage::new(request, true, addr);

        metrics
            .num_inflight_requests
            .fetch_add(1, Ordering::Relaxed);

        let pp_res = if let Some(middleware_chain) = middleware_chain {
            middleware_chain
                .preprocess::<Svc::Error, Svc::Single>(&mut request)
        } else {
            ControlFlow::Continue(())
        };

        let frozen_request = Arc::new(request);

        Ok((frozen_request, pp_res))
    }

    #[allow(clippy::type_complexity)]
    fn postprocess_response(
        msg: Arc<ContextAwareMessage<Message<Buf::Output>>>,
        state: Self::State,
        middleware_chain: Option<MiddlewareChain<Buf::Output, Svc::Target>>,
        mut txn: Transaction<
            ServiceResultItem<Svc::Target, Svc::Error>,
            Svc::Single,
        >,
        last_processor_id: Option<usize>,
        metrics: Arc<ServerMetrics>,
    ) where
        Svc::Single: Send,
    {
        tokio::spawn(async move {
            while let Some(Ok(mut call_result)) = txn.next().await {
                if let Some(middleware_chain) = &middleware_chain {
                    middleware_chain.postprocess(
                        &msg,
                        &mut call_result.response,
                        last_processor_id,
                    );
                }

                Self::handle_finalized_response(
                    call_result,
                    msg.client_addr(),
                    &state,
                    &metrics,
                )
                .await;
            }

            metrics
                .num_inflight_requests
                .fetch_sub(1, Ordering::Relaxed);
        });
    }

    fn handle_finalized_response(
        call_result: CallResult<Svc::Target>,
        addr: SocketAddr,
        state: &Self::State,
        metrics: &Arc<ServerMetrics>,
    ) -> impl Future<Output = ()> + Send;
}
