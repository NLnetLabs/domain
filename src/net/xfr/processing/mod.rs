//! Parsing of AXFR/IXFR response messages for higher level processing.
//!
//! This module provides [`XfrResponseProcessor`] which enables you to process
//! one or more AXFR/IXFR response messages in terms of the high level
//! [`XfrEvent`]s that they represent without having to deal with the
//! AXFR/IXFR protocol details.
mod iterator;
mod processor;
mod types;

#[cfg(test)]
mod tests;

pub use iterator::XfrEventIterator;
pub use processor::XfrResponseProcessor;
pub use types::{ProcessingError, XfrEvent, IterationError, XfrRecord};
