//! Middleware builders.
use std::sync::Arc;
use std::vec::Vec;

use octseq::Octets;

use crate::base::wire::Composer;

use super::chain::MiddlewareChain;
use super::processor::MiddlewareProcessor;
use super::processors::edns::EdnsMiddlewareProcessor;
use super::processors::mandatory::MandatoryMiddlewareProcessor;

/// A [`MiddlewareChain`] builder.
///
/// A [`MiddlewareChain`] is immutable and so cannot be constructed one
/// [`MiddlewareProcessor`] at a time.
///
/// This builder allows you to add [`MiddlewareProcessor`]s sequentially using
/// [`push`] before finally calling [`build`] to turn the builder into an
/// immutable [`MiddlewareChain`].
///
/// [`push`]: Self::push()
/// [`build`]: Self::build()
pub struct MiddlewareBuilder<RequestOctets = Vec<u8>, Target = Vec<u8>> {
    /// The ordered set of processors which will pre-process requests and then
    /// in reverse order will post-process responses.
    processors: Vec<
        Arc<
            dyn MiddlewareProcessor<RequestOctets, Target>
                + Send
                + Sync
                + 'static,
        >,
    >,
}

impl<RequestOctets, Target> MiddlewareBuilder<RequestOctets, Target>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    /// Create a new empty builder.
    ///
    /// <div class="warning">Warning:
    ///
    /// When building a standards compliant DNS server you should probably use
    /// [`MiddlewareBuilder::minimal`] or [`MiddlewareBuilder::standard`]
    /// instead.
    /// </div>
    ///
    /// [`MiddlewareBuilder::minimal`]: Self::minimal()
    /// [`MiddlewareBuilder::standard`]: Self::standard()
    #[must_use]
    pub fn new() -> Self {
        Self { processors: vec![] }
    }

    /// Creates a new builder pre-populated with "minimal" middleware
    /// processors.
    ///
    /// The default configuration pre-populates the builder with a
    /// [`MandatoryMiddlewareProcessor`] in the chain.
    ///
    /// This is the minimum most normal DNS servers probably need to comply
    /// with applicable RFC standards for DNS servers, only special cases like
    /// testing and research may want a chain that doesn't start with the
    /// mandatory processor.
    #[must_use]
    pub fn minimal() -> Self {
        let mut builder = Self::new();
        builder.push(MandatoryMiddlewareProcessor::default().into());
        builder
    }

    /// Creates a new builder pre-populated with "standard" middleware
    /// processors.
    ///
    /// The constructed builder will be pre-populated with the following
    /// [`MiddlewareProcessor`]s in their [`Default`] configuration.
    ///
    /// - [`MandatoryMiddlewareProcessor`]
    /// - [`EdnsMiddlewareProcessor`]
    #[must_use]
    pub fn standard() -> Self {
        let mut builder = Self::new();

        builder.push(MandatoryMiddlewareProcessor::default().into());

        #[allow(clippy::default_constructed_unit_structs)]
        builder.push(EdnsMiddlewareProcessor::default().into());

        builder
    }

    /// Add a [`MiddlewareProcessor`] to the end of the chain.
    ///
    /// Processors later in the chain pre-process requests after, and
    /// post-process responses before, than processors earlier in the chain.
    pub fn push<T>(&mut self, processor: Arc<T>)
    where
        T: MiddlewareProcessor<RequestOctets, Target> + Send + Sync + 'static,
    {
        self.processors.push(processor);
    }

    /// Add a [`MiddlewareProcessor`] to the start of the chain.
    ///
    /// Processors later in the chain pre-process requests after, and
    /// post-process responses before, processors earlier in the chain.
    pub fn push_front<T>(&mut self, processor: Arc<T>)
    where
        T: MiddlewareProcessor<RequestOctets, Target> + Send + Sync + 'static,
    {
        self.processors.insert(0, processor);
    }

    /// Turn the builder into an immutable [`MiddlewareChain`].
    #[must_use]
    pub fn build(self) -> MiddlewareChain<RequestOctets, Target> {
        MiddlewareChain::new(self.processors)
    }
}

//--- Default

impl<RequestOctets, Target> Default
    for MiddlewareBuilder<RequestOctets, Target>
where
    RequestOctets: Octets,
    Target: Composer + Default,
{
    /// Create a middleware builder with default, aka "standard", processors.
    ///
    /// See [`Self::standard`].
    fn default() -> Self {
        Self::standard()
    }
}
