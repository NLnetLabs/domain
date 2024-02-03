use std::boxed::Box;
use std::future::ready;
use std::sync::Arc;
use std::vec::Vec;

use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};
use crate::net::server::service::{
    CallResult, ServiceResultItem, Transaction,
};
use crate::net::server::ContextAwareMessage;

use super::processor::MiddlewareProcessor;
use crate::base::message_builder::AdditionalBuilder;
use core::convert::AsRef;
use core::ops::{ControlFlow, RangeTo};
/// Middleware pre-processes requests and post-processes responses to
/// filter/reject/modify them according to policy and standards.
///
/// Middleware processing should happen immediately after receipt of a request
/// (to ensure the least resources are spent on processing malicious requests)
/// and immediately prior to writing responses back to the client (to ensure
/// that what is sent to the client is correct).
pub struct MiddlewareChain<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    processors: Arc<
        Vec<
            Box<dyn MiddlewareProcessor<RequestOctets, Target> + Sync + Send>,
        >,
    >,
}

impl<RequestOctets, Target> MiddlewareChain<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    #[must_use]
    pub fn new(
        processors: Vec<
            Box<dyn MiddlewareProcessor<RequestOctets, Target> + Send + Sync>,
        >,
    ) -> MiddlewareChain<RequestOctets, Target> {
        Self {
            processors: Arc::new(processors),
        }
    }
}

impl<RequestOctets, Target> MiddlewareChain<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default + Send + 'static,
{
    pub fn preprocess<E: Send + 'static>(
        &self,
        request: &mut ContextAwareMessage<Message<RequestOctets>>,
    ) -> ControlFlow<(Transaction<ServiceResultItem<Target, E>>, usize)> {
        for (i, p) in self.processors.iter().enumerate() {
            match p.preprocess(request) {
                ControlFlow::Continue(()) => {
                    // Pre-processing complete, move on to the next pre-processor.
                }

                ControlFlow::Break(response) => {
                    // Stop pre-processing, return the produced response
                    // (after first applying post-processors to it).
                    let item = Box::new(ready(Ok(CallResult::new(response))));
                    return ControlFlow::Break((
                        Transaction::single(item),
                        i,
                    ));
                }
            }
        }

        ControlFlow::Continue(())
    }

    pub fn postprocess(
        &self,
        request: &ContextAwareMessage<Message<RequestOctets>>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
        last_processor_idx: Option<usize>,
    ) {
        let processors = match last_processor_idx {
            Some(end) => &self.processors[RangeTo { end }],
            None => &self.processors[..],
        };

        processors
            .iter()
            .rev()
            .for_each(|p| p.postprocess(request, response));
    }
}

impl<RequestOctets, Target> Clone for MiddlewareChain<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    fn clone(&self) -> Self {
        Self {
            processors: self.processors.clone(),
        }
    }
}
