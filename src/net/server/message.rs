//! Support for working with DNS messages in servers.
use core::ops::ControlFlow;
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

//------------ UdpTransportContext -------------------------------------------

/// Request context for a UDP transport.
#[derive(Debug, Copy, Clone)]
pub struct UdpTransportContext {
    /// Optional maximum response size.
    ///
    /// `None` if the server had no specific configuration regarding maximum
    /// allowed response size, `Some(n)` otherwise where `n` is the maximum
    /// number of bytes allowed for the response message.
    ///
    /// The [`EdnsMiddlewareProcessor`] may adjust this limit.
    ///
    /// The [`MandatoryMiddlewareProcessor`] enforces this limit.
    ///
    /// [`EdnsMiddlewareProcessor`]:
    ///     crate::net::server::middleware::processors::edns::EdnsMiddlewareProcessor
    /// [`MandatoryMiddlewareProcessor`]:
    ///     crate::net::server::middleware::processors::mandatory::MandatoryMiddlewareProcessor
    pub max_response_size_hint: Option<u16>,
}

//------------ NonUdpTransportContext ----------------------------------------

/// Request context for a non-UDP transport.
#[derive(Debug, Copy, Clone)]
pub struct NonUdpTransportContext {
    /// Optional indication of any idle timeout relevant to the request.
    ///
    /// A connection idle timeout such as the [RFC 7766 section 6.2.3] TCP
    /// idle timeout or edns-tcp-keepalive timeout [RFC 7828].
    ///
    /// This is provided by the server to indicate what the current timeout
    /// setting in effect is.
    ///
    /// The [`EdnsMiddlewareProcessor`] may report this timeout value back to
    /// clients capable of interpreting it.
    ///
    /// [RFC 7766 section 6.2.3]:
    ///     https://datatracker.ietf.org/doc/html/rfc7766#section-6.2.3
    /// [RFC 78828]: https://www.rfc-editor.org/rfc/rfc7828
    ///
    /// [`EdnsMiddlewareProcessor`]:
    ///     crate::net::server::middleware::processors::edns::EdnsMiddlewareProcessor
    pub idle_timeout: Option<Duration>,
}

//------------ TransportSpecificContext --------------------------------------

/// Transport dependent context.
///
/// Knowing the context of a request may be needed in order to process it
/// correctly. Some kinds of contextual information are only available for
/// certain transport types.
///
/// Context values may be adjusted by processors in the [`MiddlewareChain`]
/// and/or by the [`Service`] that receives the request, in order to influence
/// the behaviour of other processors, the service or the server.
#[derive(Debug, Copy, Clone)]
pub enum TransportSpecificContext {
    /// Context for a UDP transport.
    Udp(UdpTransportContext),

    /// Context for a non-UDP transport.
    NonUdp(NonUdpTransportContext),
}

impl TransportSpecificContext {
    /// Was the message received over a UDP transport?
    pub fn is_udp(&self) -> bool {
        matches!(self, Self::Udp(_))
    }

    /// Was the message received over a non-UDP transport?
    pub fn is_non_udp(&self) -> bool {
        matches!(self, Self::NonUdp(_))
    }
}

//------------ Request -------------------------------------------------------

/// A DNS message with additional properties describing its context.
///
/// DNS messages don't exist in isolation, they are received from somewhere or
/// created by something. This type wraps a message with additional context
/// about its origins so that decisions can be taken based not just on the
/// message itself but also on the circumstances surrounding its creation and
/// delivery.
#[derive(Debug)]
pub struct Request<T> {
    /// The network address of the connected client.
    client_addr: std::net::SocketAddr,

    /// The instant when the request was received.
    received_at: Instant,

    /// The message that was received.
    message: Arc<T>,

    /// Properties of the request specific to the server and transport
    /// protocol via which it was received.
    transport_specific: TransportSpecificContext,
}

impl<T> Request<T> {
    /// Creates a new request wrapper around a message along with its context.
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

    /// Get a reference to the transport specific context
    pub fn transport(&self) -> &TransportSpecificContext {
        &self.transport_specific
    }

    /// Get a mutable reference to the transport specific context
    pub fn transport_mut(&mut self) -> &mut TransportSpecificContext {
        &mut self.transport_specific
    }

    /// From which IP address and port number was this message received?
    pub fn client_addr(&self) -> std::net::SocketAddr {
        self.client_addr
    }

    /// Read access to the inner message
    pub fn message(&self) -> &Arc<T> {
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

//----------- CommonMessageFlow ----------------------------------------------

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
/// <div class="warning">
///
/// This trait exists as a convenient mechanism for sharing common code
/// between server implementations. The default function implementations
/// provided by this trait are not intended to be overridden by consumers of
/// this library.
///
/// </div>
///
/// [`process_request()`]: Self::process_request()
pub trait CommonMessageFlow<Buf, Svc>
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    /// Server-specific data that it chooses to pass along with the request in
    /// order that it may receive it when `process_call_result()` is
    /// invoked on the implementing server.
    type Meta: Clone + Send + Sync + 'static;

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
    #[allow(clippy::too_many_arguments)]
    fn process_request(
        &self,
        buf: Buf::Output,
        received_at: Instant,
        addr: SocketAddr,
        middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
        svc: &Svc,
        metrics: Arc<ServerMetrics>,
        meta: Self::Meta,
    ) -> Result<(), ServiceError>
    where
        Svc::Future: Send,
    {
        boomerang(
            self,
            buf,
            received_at,
            addr,
            middleware_chain,
            metrics,
            svc,
            meta,
        )
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
        state: Self::Meta,
        metrics: Arc<ServerMetrics>,
    );
}

/// Propogate a message through the [`MiddlewareChain`] to the [`Service`] and
/// flow the response in reverse back down the same path, a bit like throwing
/// a boomerang.
#[allow(clippy::too_many_arguments)]
fn boomerang<Buf, Svc, Server>(
    server: &Server,
    buf: <Buf as BufSource>::Output,
    received_at: Instant,
    addr: SocketAddr,
    middleware_chain: MiddlewareChain<
        <Buf as BufSource>::Output,
        <Svc as Service<<Buf as BufSource>::Output>>::Target,
    >,
    metrics: Arc<ServerMetrics>,
    svc: &Svc,
    meta: Server::Meta,
) -> Result<(), ServiceError>
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
    Server: CommonMessageFlow<Buf, Svc> + ?Sized,
{
    let (request, preprocessing_result) = do_middleware_preprocessing(
        server,
        buf,
        received_at,
        addr,
        &middleware_chain,
        &metrics,
    )?;

    let (txn, aborted_preprocessor_idx) =
        do_service_call::<Buf, Svc>(preprocessing_result, &request, svc);

    do_middleware_postprocessing::<Buf, Svc, Server>(
        request,
        meta,
        middleware_chain,
        txn,
        aborted_preprocessor_idx,
        metrics,
    );

    Ok(())
}

/// Pass a pre-processed request to the [`Service`] to handle.
///
/// If [`Service::call()`] returns an error this function will produce a DNS
/// ServFail error response. If the returned error is
/// [`ServiceError::InternalError`] it will also be logged.
#[allow(clippy::type_complexity)]
fn do_service_call<Buf, Svc>(
    preprocessing_result: ControlFlow<(
        Transaction<
            Result<CallResult<Buf::Output, Svc::Target>, ServiceError>,
            Svc::Future,
        >,
        usize,
    )>,
    request: &Request<Message<<Buf as BufSource>::Output>>,
    svc: &Svc,
) -> (
    Transaction<
        Result<CallResult<Buf::Output, Svc::Target>, ServiceError>,
        Svc::Future,
    >,
    Option<usize>,
)
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    match preprocessing_result {
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

            // Handle any error returned by the service.
            let request_for_error = request;
            let txn = res.unwrap_or_else(|err| {
                if matches!(err, ServiceError::InternalError) {
                    error!("Service error while processing request: {err}");
                }

                let mut response = start_reply(request_for_error);
                response.header_mut().set_rcode(err.rcode());
                let call_result = CallResult::new(response.additional());
                Transaction::immediate(Ok(call_result))
            });

            // Pass the transaction out for post-processing.
            (txn, None)
        }

        ControlFlow::Break((txn, aborted_preprocessor_idx)) => {
            (txn, Some(aborted_preprocessor_idx))
        }
    }
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
fn do_middleware_preprocessing<Buf, Svc, Server>(
    server: &Server,
    buf: Buf::Output,
    received_at: Instant,
    addr: SocketAddr,
    middleware_chain: &MiddlewareChain<Buf::Output, Svc::Target>,
    metrics: &Arc<ServerMetrics>,
) -> Result<
    (
        Request<Message<Buf::Output>>,
        ControlFlow<(
            Transaction<
                Result<CallResult<Buf::Output, Svc::Target>, ServiceError>,
                Svc::Future,
            >,
            usize,
        )>,
    ),
    ServiceError,
>
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
    Server: CommonMessageFlow<Buf, Svc> + ?Sized,
{
    let message = Message::from_octets(buf).map_err(|err| {
        warn!("Failed while parsing request message: {err}");
        ServiceError::InternalError
    })?;

    let mut request =
        server.add_context_to_request(message, received_at, addr);

    let span = info_span!("pre-process",
        msg_id = request.message().header().id(),
        client = %request.client_addr(),
    );
    let _guard = span.enter();

    metrics.inc_num_inflight_requests();

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
fn do_middleware_postprocessing<Buf, Svc, Server>(
    request: Request<Message<Buf::Output>>,
    meta: Server::Meta,
    middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
    mut response_txn: Transaction<
        Result<CallResult<Buf::Output, Svc::Target>, ServiceError>,
        Svc::Future,
    >,
    last_processor_id: Option<usize>,
    metrics: Arc<ServerMetrics>,
) where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
    Server: CommonMessageFlow<Buf, Svc> + ?Sized,
{
    tokio::spawn(async move {
        let span = info_span!("post-process",
            msg_id = request.message().header().id(),
            client = %request.client_addr(),
        );
        let _guard = span.enter();

        while let Some(Ok(mut call_result)) = response_txn.next().await {
            if let Some(response) = call_result.get_response_mut() {
                middleware_chain.postprocess(
                    &request,
                    response,
                    last_processor_id,
                );
            }

            let call_result = call_result.with_request(request.clone());

            Server::process_call_result(
                call_result,
                request.client_addr(),
                meta.clone(),
                metrics.clone(),
            );
        }

        metrics.dec_num_inflight_requests();
    });
}
