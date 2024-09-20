//! An in-memory backing store for [`Zone`]s.
//!
//! [`Zone`]: super::Zone
mod builder;
mod nodes;
mod read;
mod versioned;
mod write;

pub use builder::ZoneBuilder;
