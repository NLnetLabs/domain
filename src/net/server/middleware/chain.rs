use std::boxed::Box;
use std::sync::Arc;
use std::vec::Vec;

use crate::base::wire::Composer;
use crate::base::{Message, MessageBuilder, StreamTarget};
use crate::net::server::service::CallResult;
use crate::net::server::ContextAwareMessage;

use super::processor::MiddlewareProcessor;

/// Middleware pre-processes requests and post-processes responses to
/// filter/reject/modify them according to policy and standards.
///
/// Middleware processing should happen immediately after receipt of a request
/// (to ensure the least resources are spent on processing malicious requests)
/// and immediately prior to writing responses back to the client (to ensure
/// that what is sent to the client is correct).
pub struct MiddlewareChain<Target>
where
    Target: Composer,
{
    processors: Arc<Vec<Box<dyn MiddlewareProcessor<Target> + Sync + Send>>>,
}

impl<Target> MiddlewareChain<Target>
where
    Target: Composer,
{
    pub fn new(
        processors: Vec<Box<dyn MiddlewareProcessor<Target> + Send + Sync>>,
    ) -> MiddlewareChain<Target>
    where
        Target: Composer,
    {
        Self {
            processors: Arc::new(processors),
        }
    }
}

impl<Target> MiddlewareChain<Target>
where
    Target: Composer,
{
    pub fn apply<T, E>(
        &self,
        request: ContextAwareMessage<Message<Target>>,
        target: StreamTarget<Target>,
        handle_msg_cb: T,
    ) -> Result<(ContextAwareMessage<Message<Target>>, CallResult<Target>), E>
    where
        T: Fn(
            &ContextAwareMessage<Message<Target>>,
            MessageBuilder<StreamTarget<Target>>,
        ) -> Result<CallResult<Target>, E>,
    {
        let response_builder = MessageBuilder::from_target(target).unwrap();
        self.walk(request, response_builder, handle_msg_cb, 0)
    }

    fn walk<T, E>(
        &self,
        request: ContextAwareMessage<Message<Target>>,
        response_builder: MessageBuilder<StreamTarget<Target>>,
        handle_msg_cb: T,
        processor_index: usize,
    ) -> Result<(ContextAwareMessage<Message<Target>>, CallResult<Target>), E>
    where
        T: Fn(
            &ContextAwareMessage<Message<Target>>,
            MessageBuilder<StreamTarget<Target>>,
        ) -> Result<CallResult<Target>, E>,
    {
        let next_processor = self.processors.get(processor_index);

        match next_processor {
            None => {
                eprintln!("Processor {processor_index}: no more processors, invoking callback...");
                // This is the end of the processor chain. Execute the callback
                // to pass the request to the service for processing.
                let call_result = handle_msg_cb(&request, response_builder)?;
                Ok((request, call_result))
            }

            Some(processor) => {
                eprintln!("Processor {processor_index}: pre-processing...");
                match processor.preprocess(request, response_builder) {
                    Err((request, additional)) => {
                        // Pre-processing resulted in a response to send back to the
                        // client. This request will not be processed further.
                        eprintln!("Processor {processor_index}: pre-processing rejected the request");
                        Ok((request, CallResult::new(additional)))
                    }

                    Ok((request, response_builder)) => {
                        eprintln!("Processor {processor_index}: pre-processing accepted the request, invoking next processor...");
                        // Pre-processing allowed the request to continue.
                        // Pass the request to the next processor.
                        let (request, mut call_result) = self.walk(
                            request,
                            response_builder,
                            handle_msg_cb,
                            processor_index + 1,
                        )?;

                        // Post-process it.
                        eprintln!("Processor {processor_index}: next processor finished, post-processing...");
                        processor
                            .postprocess(&request, &mut call_result.response);

                        // Go back down the processor tree and apply the next
                        // post-processor.
                        eprintln!("Processor {processor_index}: post-processing finished.");
                        Ok((request, call_result))
                    }
                }
            }
        }
    }
}

/// Manual implementation of Clone to avoid requiring trait bounds to also be Clone.
impl<Target> Clone for MiddlewareChain<Target>
where
    Target: Composer,
{
    fn clone(&self) -> Self {
        Self {
            processors: self.processors.clone(),
        }
    }
}
