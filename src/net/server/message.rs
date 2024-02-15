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

//----------- MessageProcessor -----------------------------------------------

pub trait MessageProcessor<Buf, Svc>
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    type State: Clone + Send + Sync + 'static;

    fn process_message(
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

    fn add_context_to_request(
        &self,
        request: Message<Buf::Output>,
        addr: SocketAddr,
    ) -> ContextAwareMessage<Message<Buf::Output>>;

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

    fn handle_finalized_response(
        call_result: CallResult<Svc::Target>,
        addr: SocketAddr,
        state: Self::State,
        metrics: Arc<ServerMetrics>,
    ) -> JoinHandle<()>;
}
