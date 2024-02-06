use core::{ops::ControlFlow, sync::atomic::Ordering};
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::{
    base::Message,
    net::server::{
        buf::BufSource, metrics::ServerMetrics,
        middleware::chain::MiddlewareChain,
    },
};

use super::{
    message::ContextAwareMessage,
    service::{
        CallResult, Service, ServiceError, ServiceResultItem, Transaction,
    },
};

pub trait MessageProcessor<Buf, Svc>
where
    Buf: BufSource + Send + Sync + 'static,
    Buf::Output: Send + Sync + 'static,
    Svc: Service<Buf::Output> + Send + Sync + 'static,
{
    type State: Clone + Send + Sync + 'static;

    fn process_message(
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
