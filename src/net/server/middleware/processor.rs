use crate::{
    base::{
        message_builder::AdditionalBuilder, wire::Composer, Message,
        StreamTarget,
    },
    net::server::traits::message::ContextAwareMessage,
};
use core::ops::ControlFlow;

/// A processing stage applied to incoming and outgoing messages.
///
/// See [`MiddlewareChain`] for more information.
pub trait MiddlewareProcessor<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    /// Apply middleware pre-processing rules to a request.
    fn preprocess(
        &self,
        request: &mut ContextAwareMessage<Message<RequestOctets>>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>>;

    /// Apply middleware post-processing rules to a response.
    fn postprocess(
        &self,
        request: &ContextAwareMessage<Message<RequestOctets>>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    );
}
