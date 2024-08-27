//! Parsing of AXFR/IXFR response messages for higher level processing.
//!
//! This module provides [`XfrResponseProcessor`] which enables you to process
//! one or more AXFR/IXFR response messages in terms of the high level
//! [`XfrEvent`]s that they represent without having to deal with the
//! AXFR/IXFR protocol details.
pub mod iterator;
pub mod processor;
pub mod types;

#[cfg(test)]
mod tests;