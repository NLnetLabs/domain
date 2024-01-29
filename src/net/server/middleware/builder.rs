use core::fmt::Debug;
use std::{boxed::Box, vec::Vec};

use octseq::{FreezeBuilder, Octets, OctetsBuilder};

use crate::base::wire::Composer;

use super::{
    chain::MiddlewareChain, processor::MiddlewareProcessor,
    processors::mandatory::MandatoryMiddlewareProcesor,
};

pub struct MiddlewareBuilder<Target>
where
    Target: Composer,
{
    processors: Vec<Box<dyn MiddlewareProcessor<Target> + Sync + Send>>,
}

impl<Target> MiddlewareBuilder<Target>
where
    Target: Composer,
{
    pub fn new() -> Self {
        Self { processors: vec![] }
    }

    pub fn push<T>(&mut self, processor: T)
    where
        T: MiddlewareProcessor<Target> + Sync + Send + 'static,
    {
        self.processors.push(Box::new(processor));
    }

    pub fn finish(self) -> MiddlewareChain<Target> {
        MiddlewareChain::new(self.processors)
    }
}

impl<Target> Default for MiddlewareBuilder<Target>
where
    Target: Composer + Octets + FreezeBuilder<Octets = Target>,
    <Target as OctetsBuilder>::AppendError: Debug,
{
    fn default() -> Self {
        let mut builder = Self::new();
        builder.push(MandatoryMiddlewareProcesor::new());
        builder
    }
}
