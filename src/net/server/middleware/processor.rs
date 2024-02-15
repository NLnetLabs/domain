//! Supporting types common to all processors.
use crate::{
    base::{
        message_builder::AdditionalBuilder, wire::Composer, Message,
        StreamTarget,
    },
    net::server::message::ContextAwareMessage,
};
use core::ops::ControlFlow;

/// A processing stage applied to incoming and outgoing messages.
///
/// See the documentation in the [`middleware`] module for more information.
///
/// [`middleware`]: crate::net::server::middleware
pub trait MiddlewareProcessor<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    /// Apply middleware pre-processing rules to a request.
    ///
    /// See [`MiddlewareChain::preprocess()`] for more information.
    ///
    /// [`MiddlewareChain::preprocess()`]: crate::net::server::middleware::chain::MiddlewareChain::preprocess()
    fn preprocess(
        &self,
        request: &mut ContextAwareMessage<Message<RequestOctets>>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>>;

    /// Apply middleware post-processing rules to a response.
    ///
    /// See [`MiddlewareChain::postprocess()`] for more information.
    ///
    /// [`MiddlewareChain::postprocess()`]: crate::net::server::middleware::chain::MiddlewareChain::postprocess()
    fn postprocess(
        &self,
        request: &ContextAwareMessage<Message<RequestOctets>>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    );
}
