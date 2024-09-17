//! Parsing of AXFR/IXFR response messages for higher level processing.
//!
//! This module provides [`XfrResponseInterpreter`] which can be used to
//! process one or more AXFR/IXFR response messages in terms of the high level
//! [`ZoneUpdate`]s that they represent without having to deal with the
//! AXFR/IXFR protocol details.
//!
//! [`ZoneUpdate`]: crate::zonetree::types::ZoneUpdate
mod interpreter;
mod iterator;
mod types;

#[cfg(test)]
mod tests;

pub use interpreter::XfrResponseInterpreter;
pub use iterator::XfrZoneUpdateIterator;
pub use types::{IterationError, ProcessingError, XfrRecord};
