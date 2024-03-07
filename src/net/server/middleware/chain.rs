//! Chaining [`MiddlewareProcessor`]s together.
use std::future::Future;
use std::sync::Arc;
use std::vec::Vec;

use crate::base::wire::Composer;
use crate::base::{Message, StreamTarget};
use crate::net::server::message::ContextAwareMessage;
use crate::net::server::service::{
    CallResult, ServiceResultItem, Transaction,
};

use super::processor::MiddlewareProcessor;
use crate::base::message_builder::AdditionalBuilder;
use core::ops::{ControlFlow, RangeTo};

/// A chain of [`MiddlewareProcessor`]s.
///
/// Processors earlier in the chain process requests _before_ and responses
/// _after_ processors later in the chain.
///
/// The chain can be cloned in order to use it with more than one server at
/// once, assuming that you want to use exactly the same set of processors for
/// all servers using the same chain.
///
/// A [`MiddlewareChain`] is immutable. Requests should not be post-processed
/// by a different or modified chain than they were pre-processed by.
pub struct MiddlewareChain<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    processors: Arc<
        Vec<
            Arc<dyn MiddlewareProcessor<RequestOctets, Target> + Sync + Send>,
        >,
    >,
}

impl<RequestOctets, Target> MiddlewareChain<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    /// Create a new _empty_ chain of processors.
    ///
    /// <div class="warning">Warning:
    ///
    /// Most DNS server implementations will need to perform mandatory
    /// pre-processing of requests and post-processing of responses in order
    /// to comply with RFC defined standards.
    ///
    /// By using this function you are responsible for ensuring that you
    /// perform such processing yourself.
    ///
    /// Most users should **NOT** use this function but should instead use
    /// [`MiddlewareBuilder::default()`] which constructs a chain that starts
    /// with [`MandatoryMiddlewareProcessor`].
    /// </div>
    ///
    /// [`MiddlewareBuilder::default()`]:
    ///     super::builder::MiddlewareBuilder::default()
    /// [`MandatoryMiddlewareProcessor`]:
    ///     super::processors::mandatory::MandatoryMiddlewareProcessor
    #[must_use]
    pub fn new(
        processors: Vec<
            Arc<dyn MiddlewareProcessor<RequestOctets, Target> + Send + Sync>,
        >,
    ) -> MiddlewareChain<RequestOctets, Target> {
        Self {
            processors: Arc::new(processors),
        }
    }
}

impl<RequestOctets, Target> MiddlewareChain<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]> + Send + 'static,
    Target: Composer + Default + Send + 'static,
{
    /// Walks the chain forward invoking pre-processors one by one.
    ///
    /// Pre-processors either inspect the given request, or may also
    /// optionally modify it.
    ///
    /// Returns either [`ControlFlow::Continue`] indicating that processing of
    /// the request should continue, or [`ControlFlow::Break`] indicating that
    /// a pre-processor decided to terminate processing of the request.
    ///
    /// On [`ControlFlow::Break`] the caller should pass the given result to
    /// [`postprocess()`][Self::postprocess]. If processing terminated early
    /// the result includes the index of the pre-processor which terminated
    /// the processing.
    ///
    /// # Performance
    ///
    /// Pre-processing may take place in the same task that handles receipt
    /// and pre-processing of other requests. It is therefore important to
    /// finish pre-processing as quickly as possible. It is also important to
    /// put pre-processors which protect the server against doing too much
    /// work as early in the chain as possible.
    #[allow(clippy::type_complexity)]
    pub fn preprocess<Error, Single>(
        &self,
        request: &mut ContextAwareMessage<Message<RequestOctets>>,
    ) -> ControlFlow<(
        Transaction<ServiceResultItem<Target, Error>, Single>,
        usize,
    )>
    where
        Error: Send + 'static,
        Single: Future<Output = ServiceResultItem<Target, Error>> + Send,
    {
        for (i, p) in self.processors.iter().enumerate() {
            match p.preprocess(request) {
                ControlFlow::Continue(()) => {
                    // Pre-processing complete, move on to the next pre-processor.
                }

                ControlFlow::Break(response) => {
                    // Stop pre-processing, return the produced response
                    // (after first applying post-processors to it).
                    let item = Ok(CallResult::new(response));
                    return ControlFlow::Break((
                        Transaction::immediate(item),
                        i,
                    ));
                }
            }
        }

        ControlFlow::Continue(())
    }

    /// Walks the chain backward invoking post-processors one by one.
    ///
    /// Post-processors either inspect the given response, or may also
    /// optionally modify it.
    ///
    /// The request supplied should be the request to which the response was
    /// generated. This is used e.g. for copying the request DNS message ID
    /// into the response, or for checking the transport by which the reques
    /// was recieved.
    ///
    /// The optional `last_processor_idx` value should come from an earlier
    /// call to [`preprocess()`][Self::preprocess]. Post-processing will start
    /// with this processor and walk backward from there, post-processors
    /// further down the chain will not be invoked.
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
