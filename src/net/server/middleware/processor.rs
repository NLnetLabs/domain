//! Supporting types common to all processors.
use core::ops::ControlFlow;

use crate::base::message_builder::AdditionalBuilder;
use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};
use crate::net::server::message::Request;

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
        request: &mut Request<Message<RequestOctets>>,
    ) -> ControlFlow<AdditionalBuilder<StreamTarget<Target>>>;

    /// Apply middleware post-processing rules to a response.
    ///
    /// See [`MiddlewareChain::postprocess()`] for more information.
    ///
    /// [`MiddlewareChain::postprocess()`]: crate::net::server::middleware::chain::MiddlewareChain::postprocess()
    fn postprocess(
        &self,
        request: &Request<Message<RequestOctets>>,
        response: &mut AdditionalBuilder<StreamTarget<Target>>,
    );
}
