use std::{boxed::Box, vec::Vec};

use octseq::Octets;

use crate::base::wire::Composer;

use super::{
    chain::MiddlewareChain, processor::MiddlewareProcessor,
    processors::mandatory::MandatoryMiddlewareProcesor,
};

pub struct MiddlewareBuilder<RequestOctets = Vec<u8>, Target = Vec<u8>>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    processors: Vec<
        Box<dyn MiddlewareProcessor<RequestOctets, Target> + Sync + Send>,
    >,
}

impl<RequestOctets, Target> MiddlewareBuilder<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]>,
    Target: Composer + Default,
{
    #[must_use]
    pub fn new() -> Self {
        Self { processors: vec![] }
    }

    pub fn push<T>(&mut self, processor: T)
    where
        T: MiddlewareProcessor<RequestOctets, Target> + Sync + Send + 'static,
    {
        self.processors.push(Box::new(processor));
    }

    #[must_use]
    pub fn finish(self) -> MiddlewareChain<RequestOctets, Target> {
        MiddlewareChain::new(self.processors)
    }
}

impl<RequestOctets, Target> Default
    for MiddlewareBuilder<RequestOctets, Target>
where
    RequestOctets: AsRef<[u8]> + Octets,
    Target: Composer + Default,
{
    #[must_use]
    fn default() -> Self {
        let mut builder = Self::new();
        builder.push(MandatoryMiddlewareProcesor::new());
        builder
    }
}
