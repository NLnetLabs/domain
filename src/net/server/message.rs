//! Support for working with DNS messages in servers.
use core::ops::ControlFlow;
use core::sync::atomic::Ordering;
use core::time::Duration;

use std::net::SocketAddr;
use std::sync::Arc;

use octseq::Octets;
use tokio::time::Instant;
use tracing::Level;
use tracing::{enabled, error, info_span, warn};

use crate::base::Message;
use crate::net::server::buf::BufSource;
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::middleware::chain::MiddlewareChain;

use super::service::{CallResult, Service, ServiceError, Transaction};
use super::util::start_reply;

//------------ Request -------------------------------------------

#[derive(Debug, Copy, Clone)]
pub struct UdpSpecificTransportContext {
    pub max_response_size_hint: Option<u16>,
}

#[derive(Debug, Copy, Clone)]
pub struct NonUdpTransportContext {
    pub idle_timeout: Option<Duration>,
}

#[derive(Debug, Copy, Clone)]
pub enum TransportSpecificContext {
    Udp(UdpSpecificTransportContext),
    NonUdp(NonUdpTransportContext),
}

impl TransportSpecificContext {
    pub fn is_udp(&self) -> bool {
        matches!(self, Self::Udp(_))
    }

    pub fn is_non_udp(&self) -> bool {
        matches!(self, Self::NonUdp(_))
    }
}

/// A DNS message with additional properties describing its context.
///
/// DNS messages don't exist in isolation, they are received from somewhere or
/// created by something. This type wraps a message with additional context
/// about its origins so that decisions can be taken based not just on the
/// message itself but also on the circumstances surrounding its creation and
/// delivery.
#[derive(Debug)]
pub struct Request<T> {
    client_addr: std::net::SocketAddr,
    received_at: Instant,
    message: Arc<T>,
    transport_specific: TransportSpecificContext,
}

impl<T> Request<T> {
    pub fn new(
        client_addr: std::net::SocketAddr,
        received_at: Instant,
        message: T,
        transport_specific: TransportSpecificContext,
    ) -> Self {
        Self {
            client_addr,
            received_at,
            message: Arc::new(message),
            transport_specific,
        }
    }

    /// When was this message received?
    pub fn received_at(&self) -> Instant {
        self.received_at
    }

    /// Get the transport specific context
    pub fn transport(&self) -> &TransportSpecificContext {
        &self.transport_specific
    }

    /// From which IP address and port number was this message received?
    pub fn client_addr(&self) -> std::net::SocketAddr {
        self.client_addr
    }

    /// Read access to the inner message
    pub fn message(&self) -> &T {
        &self.message
    }
}

//--- Clone

impl<T> Clone for Request<T> {
    fn clone(&self) -> Self {
        Self {
            client_addr: self.client_addr,
            received_at: self.received_at,
            message: Arc::clone(&self.message),
            transport_specific: self.transport_specific,
        }
    }
}

//----------- MessageProcessor -----------------------------------------------

pub struct MessageDetails<Buf>
where
    Buf: BufSource,
{
    buf: Buf::Output,
    received_at: Instant,
    addr: SocketAddr,
}

impl<Buf> MessageDetails<Buf>
where
    Buf: BufSource,
{
    pub fn new(
        buf: Buf::Output,
        received_at: Instant,
        addr: SocketAddr,
    ) -> Self {
        Self {
            buf,
            received_at,
            addr,
        }
    }
}

/// Perform processing common to all messages being handled by a DNS server.
///
/// All messages received by a DNS server need to pass through the following
/// processing stages:
///
///   - Pre-processing.
///   - Service processing.
///   - Post-processing.
///
/// The strategy is common but some server specific aspects are delegated to
/// the server that implements this trait:
///
///   - Adding context to a request.
///   - Finalizing the handling of a response.
///
/// Servers implement this trait to benefit from the common processing
/// required while still handling aspects specific to the server themselves.
///
/// Processing starts at [`process_request()`].
///
/// [`process_request()`]: Self::process_request()
pub trait MessageProcessor<Buf, Svc>
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    type State: Clone + Send + Sync + 'static;

    /// Process a DNS request message.
    ///
    /// This function consumes the given message buffer and processes the
    /// contained message, if any, to completion, possibly resulting in a
    /// response being passed to [`Self::process_call_result()`].
    ///
    /// The request message is a given as a seqeuence of bytes in `buf`
    /// originating from client address `addr`.
    ///
    /// The [`MiddlewareChain`] and [`Service`] to be used to process the
    /// message are supplied in the `middleware_chain` and `svc` arguments
    /// respectively.
    ///
    /// Any server specific state to be used and/or updated as part of the
    /// processing should be supplied via the `state` argument whose type is
    /// defined by the implementing type.
    ///
    /// On error the result will be a [`ServiceError`].
    fn process_request(
        &self,
        msg_details: MessageDetails<Buf>,
        state: Self::State,
        middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
        svc: &Svc,
        metrics: Arc<ServerMetrics>,
    ) -> Result<(), ServiceError>
    where
        Svc::Future: Send,
    {
        let (request, pp_res) = self.preprocess_request(
            msg_details,
            &middleware_chain,
            &metrics,
        )?;

        let (txn, aborted_pp_idx) = match pp_res {
            ControlFlow::Continue(()) => {
                let request_for_svc = request.clone();

                let res = if enabled!(Level::INFO) {
                    let span = info_span!("svc-call",
                        msg_id = request_for_svc.message().header().id(),
                        client = %request_for_svc.client_addr(),
                    );
                    let _guard = span.enter();
                    svc.call(request_for_svc)
                } else {
                    svc.call(request_for_svc)
                };

                let request_for_error = &request;
                let txn = res.unwrap_or_else(|err| {
                    if matches!(err, ServiceError::InternalError) {
                        error!(
                            "Service error while processing request: {err}"
                        );
                    }

                    let mut response = start_reply(request_for_error);
                    response.header_mut().set_rcode(err.rcode());
                    let call_result = CallResult::new(response.additional());
                    Transaction::immediate(Ok(call_result))
                });

                (txn, None)
            }
            ControlFlow::Break((txn, aborted_pp_idx)) => {
                (txn, Some(aborted_pp_idx))
            }
        };

        self.postprocess_response(
            request,
            state,
            middleware_chain,
            txn,
            aborted_pp_idx,
            metrics,
        );

        Ok(())
    }

    /// Pre-process a request.
    ///
    /// Pre-processing involves parsing a [`Message`] from the byte buffer and
    /// pre-processing it via any supplied [`MiddlewareChain`].
    ///
    /// On success the result is an immutable request message and a
    /// [`ControlFlow`] decision about whether to continue with further
    /// processing or to break early with a possible response. If processing
    /// failed the result will be a [`ServiceError`].
    ///
    /// On break the result will be one ([`Transaction::single()`]) or more
    /// ([`Transaction::stream()`]) to post-process.
    #[allow(clippy::type_complexity)]
    fn preprocess_request(
        &self,
        MessageDetails {
            buf,
            received_at,
            addr,
        }: MessageDetails<Buf>,
        middleware_chain: &MiddlewareChain<Buf::Output, Svc::Target>,
        metrics: &Arc<ServerMetrics>,
    ) -> Result<
        (
            Request<Message<Buf::Output>>,
            ControlFlow<(
                Transaction<
                    Result<
                        CallResult<Buf::Output, Svc::Target>,
                        ServiceError,
                    >,
                    Svc::Future,
                >,
                usize,
            )>,
        ),
        ServiceError,
    >
    where
        Svc::Future: Send,
    {
        let message = Message::from_octets(buf).map_err(|err| {
            warn!("Failed while parsing request message: {err}");
            ServiceError::InternalError
        })?;

        let mut request =
            self.add_context_to_request(message, received_at, addr);

        let span = info_span!("pre-process",
            msg_id = request.message().header().id(),
            client = %request.client_addr(),
        );
        let _guard = span.enter();

        metrics
            .num_inflight_requests
            .fetch_add(1, Ordering::Relaxed);

        let pp_res = middleware_chain.preprocess(&mut request);

        Ok((request, pp_res))
    }

    /// Post-process a response in the context of its originating request.
    ///
    /// Each response is post-processed in its own Tokio task. Note that there
    /// is no guarantee about the order in which responses will be
    /// post-processed. If the order of a seqence of responses is important it
    /// should be provided as a [`Transaction::stream()`] rather than
    /// [`Transaction::single()`].
    ///
    /// Responses are first post-processed by the [`MiddlewareChain`]
    /// provided, if any, then passed to [`Self::process_call_result()`] for
    /// final processing.
    #[allow(clippy::type_complexity)]
    fn postprocess_response(
        &self,
        request: Request<Message<Buf::Output>>,
        state: Self::State,
        middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
        mut response_txn: Transaction<
            Result<CallResult<Buf::Output, Svc::Target>, ServiceError>,
            Svc::Future,
        >,
        last_processor_id: Option<usize>,
        metrics: Arc<ServerMetrics>,
    ) where
        Svc::Future: Send,
    {
        tokio::spawn(async move {
            let span = info_span!("post-process",
                msg_id = request.message().header().id(),
                client = %request.client_addr(),
            );
            let _guard = span.enter();

            // TODO: Handle Err results from txn.next().
            while let Some(Ok(mut call_result)) = response_txn.next().await {
                if let Some(response) = call_result.get_response_mut() {
                    middleware_chain.postprocess(
                        &request,
                        response,
                        last_processor_id,
                    );
                }

                let call_result = call_result.with_request(request.clone());

                Self::process_call_result(
                    call_result,
                    request.client_addr(),
                    state.clone(),
                    metrics.clone(),
                );
            }

            metrics
                .num_inflight_requests
                .fetch_sub(1, Ordering::Relaxed);
        });
    }

    /// Add context to a request.
    ///
    /// The server supplies this function to annotate the received message
    /// with additional information about its origins.
    fn add_context_to_request(
        &self,
        request: Message<Buf::Output>,
        received_at: Instant,
        addr: SocketAddr,
    ) -> Request<Message<Buf::Output>>;

    /// Finalize a response.
    ///
    /// The server supplies this function to handle the response as
    /// appropriate for the server, e.g. to write the response back to the
    /// originating client.
    ///
    /// The response is the form of a [`CallResult`].
    fn process_call_result(
        call_result: CallResult<Buf::Output, Svc::Target>,
        addr: SocketAddr,
        state: Self::State,
        metrics: Arc<ServerMetrics>,
    );
}
