//! Support for working with DNS messages in servers.
use core::{ops::ControlFlow, sync::atomic::Ordering};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::info_span;

use crate::{
    base::{message::ShortMessage, Message},
    net::server::{
        buf::BufSource, metrics::ServerMetrics,
        middleware::chain::MiddlewareChain,
    },
};

use super::service::{
    CallResult, Service, ServiceError, ServiceResultItem, Transaction,
};

//------------ MsgProvider ---------------------------------------------------

/// A MsgProvider can determine the number of bytes of message data to expect
/// and then turn those bytes into a concrete message type.
pub trait MsgProvider<RequestOctets: AsRef<[u8]>> {
    /// The number of bytes that need to be read before it is possible to
    /// determine how many more bytes of message should follow. Not all
    /// message types require this, e.g. UDP DNS message length is determined
    /// by the size of the UDP message received, while for TCP DNS messages
    /// the number of bytes to expect is determined by the first two bytes
    /// received.
    const MIN_HDR_BYTES: usize;

    /// The concrete type of message that we produce from given message
    /// bytes.
    type Msg;

    /// The actual number of message bytes to follow given at least
    /// MIN_HDR_BYTES of message header.
    fn determine_msg_len(hdr_buf: &mut RequestOctets) -> usize;

    /// Convert a sequence of bytes to a concrete message.
    fn from_octets(octets: RequestOctets) -> Result<Self::Msg, ShortMessage>;
}

/// An implementation of MsgProvider for DNS [`Message`]s.
impl<RequestOctets: AsRef<[u8]>> MsgProvider<RequestOctets>
    for Message<RequestOctets>
{
    /// RFC 1035 section 4.2.2 "TCP Usage" says:
    ///     "The message is prefixed with a two byte length field which gives
    ///      the message length, excluding the two byte length field.  This
    ///      length field allows the low-level processing to assemble a
    ///      complete message before beginning to parse it."
    const MIN_HDR_BYTES: usize = 2;

    type Msg = Self;

    #[must_use]
    fn determine_msg_len(hdr_buf: &mut RequestOctets) -> usize {
        u16::from_be_bytes(hdr_buf.as_ref().try_into().unwrap()) as usize
    }

    fn from_octets(octets: RequestOctets) -> Result<Self, ShortMessage> {
        Self::from_octets(octets)
    }
}

//------------ ContextAwareMessage -------------------------------------------

/// A DNS message with additional properties describing its context.
///
/// DNS messages don't exist in isolation, they are received from somewhere or
/// created by something. This type wraps a message with additional context
/// about its origins so that decisions can be taken based not just on the
/// message itself but also on the circumstances surrounding its creation and
/// delivery.
#[derive(Debug)]
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

    /// Was this message received via a TCP transport?
    pub fn received_over_tcp(&self) -> bool {
        self.received_over_tcp
    }

    /// From which IP address and port number was this message received?
    pub fn client_addr(&self) -> std::net::SocketAddr {
        self.client_addr
    }

    /// Exchange this wrapper for the inner message that it wraps.
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

//----------- MessageProcessor -----------------------------------------------

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
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    type State: Clone + Send + Sync + 'static;

    /// Process a DNS request message.
    ///
    /// This function consumes the given message buffer and processes the
    /// contained message, if any, to completion, possibly resulting in a
    /// response being passed to [`handle_finalized_response()`].
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
    ///
    /// [`handle_finalized_response()`]: Self::handle_finalized_response()
    fn process_request(
        &self,
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
        let (frozen_request, pp_res) = self.preprocess_request(
            buf,
            addr,
            middleware_chain.as_ref(),
            &metrics,
        )?;

        let (txn, aborted_pp_idx) = match pp_res {
            ControlFlow::Continue(()) => {
                let span = info_span!("svc-call",
                    msg_id = frozen_request.header().id(),
                    client = %frozen_request.client_addr(),
                );
                let _guard = span.enter();
                let txn = svc.call(frozen_request.clone())?;
                (txn, None)
            }
            ControlFlow::Break((txn, aborted_pp_idx)) => {
                (txn, Some(aborted_pp_idx))
            }
        };

        self.postprocess_response(
            frozen_request,
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

        let mut request = self.add_context_to_request(request, addr);

        let span = info_span!("pre-process",
            msg_id = request.header().id(),
            client = %request.client_addr(),
        );
        let _guard = span.enter();

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

    /// Post-process a response in the context of its originating request.
    ///
    /// Each response is post-processed in its own Tokio task. Note that there
    /// is no guarantee about the order in which responses will be
    /// post-processed. If the order of a seqence of responses is important it
    /// should be provided as a [`Transaction::stream()`] rather than
    /// [`Transaction::single()`].
    ///
    /// Responses are first post-processed by the [`MiddlewareChain`]
    /// provided, if any, then passed to [`handle_finalized_response()`] for
    /// final processing.
    ///
    /// [`handle_finalized_response()`]: Self::handle_finalized_response()
    #[allow(clippy::type_complexity)]
    fn postprocess_response(
        &self,
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
            let span = info_span!("post-process",
                msg_id = msg.header().id(),
                client = %msg.client_addr(),
            );
            let _guard = span.enter();

            // TODO: Handle Err results from txn.next().
            while let Some(Ok(mut call_result)) = txn.next().await {
                if let Some(middleware_chain) = &middleware_chain {
                    middleware_chain.postprocess(
                        &msg,
                        &mut call_result.response,
                        last_processor_id,
                    );
                }

                let _ = Self::handle_finalized_response(
                    call_result,
                    msg.client_addr(),
                    state.clone(),
                    metrics.clone(),
                )
                .await;
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
        addr: SocketAddr,
    ) -> ContextAwareMessage<Message<Buf::Output>>;

    /// Finalize a response.
    ///
    /// The server supplies this function to handle the response as
    /// appropriate for the server, e.g. to write the response back to the
    /// originating client.
    ///
    /// The response is the form of a [`CallResult`].
    fn handle_finalized_response(
        call_result: CallResult<Svc::Target>,
        addr: SocketAddr,
        state: Self::State,
        metrics: Arc<ServerMetrics>,
    ) -> JoinHandle<()>;
}
