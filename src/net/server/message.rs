//! Support for working with DNS messages in servers.
use bytes::Bytes;
use core::ops::ControlFlow;
use core::time::Duration;

use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::vec::Vec;

use tokio::time::Instant;

use crate::base::opt::AllOptData;
use crate::base::Message;
use crate::base::Name;
//use crate::base::opt::OptRecord;
//use crate::base::opt::subnet::ClientSubnet;
//use crate::dep::octseq::OctetsFrom;
use crate::net::client::request::ComposeRequest;
use crate::net::client::request::RequestMessage;
use crate::net::server::buf::BufSource;
use crate::net::server::metrics::ServerMetrics;
use crate::net::server::middleware::chain::MiddlewareChain;

use super::service::{CallResult, Service, ServiceError, Transaction};
use super::util::start_reply;
use crate::base::wire::Composer;

//------------ UdpTransportContext -------------------------------------------

/// Request context for a UDP transport.
#[derive(Clone, Debug, Default)]
pub struct UdpTransportContext {
    /// Optional maximum response size hint.
    max_response_size_hint: Arc<Mutex<Option<u16>>>,
}

impl UdpTransportContext {
    /// Creates a new UDP specific transport context.
    pub fn new(max_response_size_hint: Option<u16>) -> Self {
        let max_response_size_hint =
            Arc::new(Mutex::new(max_response_size_hint));

        Self {
            max_response_size_hint,
        }
    }
}

impl UdpTransportContext {
    /// Optional maximum response size hint.
    ///
    /// `None` if the server had no specific configuration regarding maximum
    /// allowed response size, `Some(n)` otherwise where `n` is the maximum
    /// number of bytes allowed for the response message.
    ///
    /// The [`EdnsMiddlewareSvc`] may adjust this limit.
    ///
    /// The [`MandatoryMiddlewareSvc`] enforces this limit.
    ///
    /// [`EdnsMiddlewareSvc`]:
    ///     crate::net::server::middleware::edns::EdnsMiddlewareSvc
    /// [`MandatoryMiddlewareSvc`]:
    ///     crate::net::server::middleware::mandatory::MandatoryMiddlewareSvc
    pub fn max_response_size_hint(&self) -> Option<u16> {
        *self.max_response_size_hint.lock().unwrap()
    }

    /// Sets the maximum response hint.
    pub fn set_max_response_size_hint(
        &self,
        max_response_size_hint: Option<u16>,
    ) {
        *self.max_response_size_hint.lock().unwrap() = max_response_size_hint;
    }
}

//------------ NonUdpTransportContext ----------------------------------------

/// Request context for a non-UDP transport.
#[derive(Clone, Copy, Debug)]
pub struct NonUdpTransportContext {
    /// Optional indication of any idle timeout relevant to the request.
    idle_timeout: Option<Duration>,
}

impl NonUdpTransportContext {
    /// Creates a new non-UDP specific transport context.
    pub fn new(idle_timeout: Option<Duration>) -> Self {
        Self { idle_timeout }
    }
}

impl NonUdpTransportContext {
    /// Optional indication of any idle timeout relevant to the request.
    ///
    /// A connection idle timeout such as the [RFC 7766 section 6.2.3] TCP
    /// idle timeout or edns-tcp-keepalive timeout [RFC 7828].
    ///
    /// This is provided by the server to indicate what the current timeout
    /// setting in effect is.
    ///
    /// The [`EdnsMiddlewareSvc`] may report this timeout value back to
    /// clients capable of interpreting it.
    ///
    /// [RFC 7766 section 6.2.3]:
    ///     https://datatracker.ietf.org/doc/html/rfc7766#section-6.2.3
    /// [RFC 78828]: https://www.rfc-editor.org/rfc/rfc7828
    ///
    /// [`EdnsMiddlewareSvc`]:
    ///     crate::net::server::middleware::edns::EdnsMiddlewareSvc
    pub fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }
}

//------------ TransportSpecificContext --------------------------------------

/// Transport dependent context.
///
/// Knowing the context of a request may be needed in order to process it
/// correctly. Some kinds of contextual information are only available for
/// certain transport types.
///
/// Context values may be adjusted by processors in the middleware chain
/// and/or by the [`Service`] that receives the request, in order to influence
/// the behaviour of other processors, the service or the server.
///
/// [`Service`]: crate::net::server::service::Service
#[derive(Debug, Clone)]
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

//--- impl From<UdpTransportContext>

impl From<UdpTransportContext> for TransportSpecificContext {
    fn from(ctx: UdpTransportContext) -> Self {
        Self::Udp(ctx)
    }
}

//--- impl From<NonUdpTransportContext>

impl From<NonUdpTransportContext> for TransportSpecificContext {
    fn from(ctx: NonUdpTransportContext) -> Self {
        Self::NonUdp(ctx)
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
pub struct Request<Octs, Metadata = ()>
where
    Octs: AsRef<[u8]> + Send + Sync,
{
    /// The network address of the connected client.
    client_addr: std::net::SocketAddr,

    /// The instant when the request was received.
    received_at: Instant,

    /// The message that was received.
    message: Arc<Message<Octs>>,

    /// Properties of the request specific to the server and transport
    /// protocol via which it was received.
    transport_specific: TransportSpecificContext,

    /// The number of bytes to be reserved when generating a response to this
    /// request so that needed additional data can be added to to the
    /// generated response.
    ///
    /// Note: This is only a hint to code that considers this value, it is
    /// still possible to generate responses that ignore this value.
    num_reserved_bytes: u16,

    /// user defined metadata to associate with the request.
    ///
    /// For example this could be used to pass data from one [middleware]
    /// [`Service`] impl to another.
    ///
    /// [middleware]: crate::net::server::middleware
    /// [`Service`]: crate::net::server::service::Service
    metadata: Metadata,
}

impl<Octs, Metadata> Request<Octs, Metadata>
where
    Octs: AsRef<[u8]> + Send + Sync + Unpin,
{
    /// Creates a new request wrapper around a message along with its context.
    pub fn new(
        client_addr: std::net::SocketAddr,
        received_at: Instant,
        message: Message<Octs>,
        transport_specific: TransportSpecificContext,
        metadata: Metadata,
    ) -> Self {
        Self {
            client_addr,
            received_at,
            message: Arc::new(message),
            transport_specific,
            num_reserved_bytes: 0,
            metadata,
        }
    }

    /// When was this message received?
    pub fn received_at(&self) -> Instant {
        self.received_at
    }

    /// Get a reference to the transport specific context
    pub fn transport_ctx(&self) -> &TransportSpecificContext {
        &self.transport_specific
    }

    /// From which IP address and port number was this message received?
    pub fn client_addr(&self) -> std::net::SocketAddr {
        self.client_addr
    }

    /// Read access to the inner message
    pub fn message(&self) -> &Arc<Message<Octs>> {
        &self.message
    }

    /// Request that an additional number of bytes be reserved in the response
    /// to this message.
    pub fn reserve_bytes(&mut self, len: u16) {
        self.num_reserved_bytes += len;
        tracing::trace!(
            "Reserved {len} bytes: total now = {}",
            self.num_reserved_bytes
        );
    }

    /// The number of bytes to reserve when generating a response to this
    /// message.
    pub fn num_reserved_bytes(&self) -> u16 {
        self.num_reserved_bytes
    }

    /// Set user defined metadata to associate with this request.
    pub fn with_new_metadata<T>(self, new_metadata: T) -> Request<Octs, T> {
        Request::<Octs, T> {
            client_addr: self.client_addr,
            received_at: self.received_at,
            message: self.message,
            transport_specific: self.transport_specific,
            num_reserved_bytes: self.num_reserved_bytes,
            metadata: new_metadata,
        }
    }

    /// Get the user defined metadata associated with this request.
    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

//--- Clone

impl<Octs, Metadata> Clone for Request<Octs, Metadata>
where
    Octs: AsRef<[u8]> + Send + Sync + Unpin,
    Metadata: Clone,
{
    fn clone(&self) -> Self {
        Self {
            client_addr: self.client_addr,
            received_at: self.received_at,
            message: Arc::clone(&self.message),
            transport_specific: self.transport_specific.clone(),
            num_reserved_bytes: self.num_reserved_bytes,
            metadata: self.metadata.clone(),
        }
    }
}

//------------ RequestNG ------------------------------------------------------

/// A DNS message with additional properties describing its context.
///
/// DNS messages don't exist in isolation, they are received from somewhere or
/// created by something. This type wraps a message with additional context
/// about its origins so that decisions can be taken based not just on the
/// message itself but also on the circumstances surrounding its creation and
/// delivery.
#[derive(Debug)]
pub struct RequestNG<Octs: AsRef<[u8]>> {
    /// The network address of the connected client.
    client_addr: std::net::SocketAddr,

    /// The instant when the request was received.
    received_at: Instant,

    /// The message that was received.
    message: Arc<Message<Octs>>,

    /// Properties of the request specific to the server and transport
    /// protocol via which it was received.
    transport_specific: TransportSpecificContext,

    /// Options that should be used upstream in providing the service.
    opt: Vec<AllOptData<Bytes, Name<Bytes>>>,
}

impl<Octs: AsRef<[u8]>> RequestNG<Octs> {
    /// Creates a new request wrapper around a message along with its context.
    pub fn new(
        client_addr: std::net::SocketAddr,
        received_at: Instant,
        message: Message<Octs>,
        transport_specific: TransportSpecificContext,
    ) -> Self {
        Self {
            client_addr,
            received_at,
            message: Arc::new(message),
            transport_specific,
            opt: Vec::new(),
        }
    }

    pub fn from_request(request: Request<Octs>) -> Self
    where
        Octs: Octets,
    {
        let mut req = Self {
            client_addr: request.client_addr,
            received_at: request.received_at,
            message: request.message,
            transport_specific: request.transport_specific,
            opt: Vec::new(),
        };

        // Copy the ECS option from the message. This is just an example,
        // there should be a separate plugin that deals with ECS.

        // We want the ECS options in Bytes. No clue how to do this. Just
        // convert the message to Bytes and use that.
        let bytes = Bytes::copy_from_slice(req.message.as_slice());
        let bytes_msg = Message::from_octets(bytes).unwrap();
        if let Some(optrec) = bytes_msg.opt() {
            for opt in optrec.opt().iter::<AllOptData<_, _>>() {
                let opt = opt.unwrap();
                if let AllOptData::ClientSubnet(_ecs) = opt {
                    req.opt.push(opt);
                }
            }
        }

        req
    }

    pub fn to_request_message(&self) -> RequestMessage<Octs>
    where
        Octs: Clone + Debug + Octets + Send + Sync,
    {
        // We need to make a copy of message. Somehow we can't use the
        // message in the Arc directly.
        let msg =
            Message::from_octets(self.message.as_octets().clone()).unwrap();
        let mut reqmsg = RequestMessage::new(msg);

        // Copy DO bit
        if dnssec_ok(&self.message) {
            reqmsg.set_dnssec_ok(true);
        }

        // Copy options
        for opt in &self.opt {
            reqmsg.add_opt(opt).unwrap();
        }
        reqmsg
    }

    /// When was this message received?
    pub fn received_at(&self) -> Instant {
        self.received_at
    }

    /// Get a reference to the transport specific context
    pub fn transport_ctx(&self) -> &TransportSpecificContext {
        &self.transport_specific
    }

    /// From which IP address and port number was this message received?
    pub fn client_addr(&self) -> std::net::SocketAddr {
        self.client_addr
    }

    /// Read access to the inner message
    pub fn message(&self) -> &Arc<Message<Octs>> {
        &self.message
    }
}

//--- Clone

impl<Octs: AsRef<[u8]>> Clone for RequestNG<Octs> {
    fn clone(&self) -> Self {
        Self {
            client_addr: self.client_addr,
            received_at: self.received_at,
            message: Arc::clone(&self.message),
            transport_specific: self.transport_specific.clone(),
            opt: self.opt.clone(),
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
/// Processing starts at [`process_request`].
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
/// [`process_request`]: Self::process_request()
pub trait CommonMessageFlow<Buf, Svc>
where
    Buf: BufSource,
    Buf::Output: Octets + Send + Sync,
    Svc: Service<Buf::Output> + Send + Sync,
{
    /// Server-specific data that it chooses to pass along with the request in
    /// order that it may receive it when `process_call_result()` is
    /// invoked on the implementing server.
    type Meta: Clone + Send + Sync + 'static;

    /// Process a DNS request message.
    ///
    /// This function consumes the given message buffer and processes the
    /// contained message, if any, to completion, possibly resulting in a
    /// response being passed to [`Self::process_call_result`].
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
        Svc: 'static,
        Svc::Target: Send + Composer + Default,
        Svc::Future: Send,
        Buf::Output: 'static,
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
    ) -> Request<Buf::Output>;

    /// Finalize a response.
    ///
    /// The server supplies this function to handle the response as
    /// appropriate for the server, e.g. to write the response back to the
    /// originating client.
    ///
    /// The response is the form of a [`CallResult`].
    fn process_call_result(
        request: &Request<Buf::Output>,
        call_result: CallResult<Svc::Target>,
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
    Buf: BufSource,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
    Svc::Future: Send,
    Svc::Target: Send + Composer + Default,
    Server: CommonMessageFlow<Buf, Svc> + ?Sized,
{
    let message = Message::from_octets(buf).map_err(|err| {
        warn!("Failed while parsing request message: {err}");
        ServiceError::InternalError
    })?;

    let request = server.add_context_to_request(message, received_at, addr);

    let preprocessing_result = do_middleware_preprocessing::<Buf, Svc>(
        &request,
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
/// If [`Service::call`] returns an error this function will produce a DNS
/// ServFail error response. If the returned error is
/// [`ServiceError::InternalError`] it will also be logged.
#[allow(clippy::type_complexity)]
fn do_service_call<Buf, Svc>(
    preprocessing_result: ControlFlow<(
        Transaction<Svc::Target, Svc::Future>,
        usize,
    )>,
    request: &Request<<Buf as BufSource>::Output>,
    svc: &Svc,
) -> (Transaction<Svc::Target, Svc::Future>, Option<usize>)
where
    Buf: BufSource,
    Buf::Output: Octets,
    Svc: Service<Buf::Output>,
    Svc::Target: Composer + Default,
{
    match preprocessing_result {
        ControlFlow::Continue(()) => {
            let res = if enabled!(Level::INFO) {
                let span = info_span!("svc-call",
                    msg_id = request.message().header().id(),
                    client = %request.client_addr(),
                );
                let _guard = span.enter();
                svc.call(request.clone())
            } else {
                svc.call(request.clone())
            };

            // Handle any error returned by the service.
            let txn = res.unwrap_or_else(|err| {
                if matches!(err, ServiceError::InternalError) {
                    error!("Service error while processing request: {err}");
                }

                let mut response = start_reply(request);
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
/// [`ControlFlow`] decision about whether to continue with further processing
/// or to break early with a possible response. If processing failed the
/// result will be a [`ServiceError`].
///
/// On break the result will be one ([`Transaction::single`]) or more
/// ([`Transaction::stream`]) to post-process.
#[allow(clippy::type_complexity)]
fn do_middleware_preprocessing<Buf, Svc>(
    request: &Request<Buf::Output>,
    middleware_chain: &MiddlewareChain<Buf::Output, Svc::Target>,
    metrics: &Arc<ServerMetrics>,
) -> Result<
    ControlFlow<(Transaction<Svc::Target, Svc::Future>, usize)>,
    ServiceError,
>
where
    Buf: BufSource,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync,
    Svc::Future: Send,
    Svc::Target: Send + Composer + Default + 'static,
{
    let span = info_span!("pre-process",
        msg_id = request.message().header().id(),
        client = %request.client_addr(),
    );
    let _guard = span.enter();

    metrics.inc_num_inflight_requests();

    let pp_res = middleware_chain.preprocess(request);

    Ok(pp_res)
}

/// Post-process a response in the context of its originating request.
///
/// Each response is post-processed in its own Tokio task. Note that there is
/// no guarantee about the order in which responses will be post-processed. If
/// the order of a seqence of responses is important it should be provided as
/// a [`Transaction::stream`] rather than [`Transaction::single`].
///
/// Responses are first post-processed by the [`MiddlewareChain`] provided, if
/// any, then passed to [`Self::process_call_result`] for final processing.
fn do_middleware_postprocessing<Buf, Svc, Server>(
    request: Request<Buf::Output>,
    meta: Server::Meta,
    middleware_chain: MiddlewareChain<Buf::Output, Svc::Target>,
    mut response_txn: Transaction<Svc::Target, Svc::Future>,
    last_processor_id: Option<usize>,
    metrics: Arc<ServerMetrics>,
) where
    Buf: BufSource,
    Buf::Output: Octets + Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
    Svc::Future: Send,
    Svc::Target: Send + Composer + Default,
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

            Server::process_call_result(
                &request,
                call_result,
                meta.clone(),
                metrics.clone(),
            );
        }

        metrics.dec_num_inflight_requests();
    });
}

/// Return whether the DO flag is set. This should move to Message.
fn dnssec_ok<Octs: Octets>(msg: &Message<Octs>) -> bool {
    if let Some(opt) = msg.opt() {
        opt.dnssec_ok()
    } else {
        false
    }
}
