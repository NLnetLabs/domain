//! A versioned in-memory backing store for [`Zone`]s.
//!
//! # Limitations
//!
//! * There is currently no support for removing old versions of zone data
//!   stored in the tree. The only optionis to [`walk()`] the [`Zone`] cloning
//!   the current version into a new [`Zone`] then dropping the old [`Zone`].
//!
//! [`Zone`]: crate::zonetree::Zone
//! [`walk()`]: crate::zoneree::ReadableZone::walk()
mod builder;
mod nodes;
mod read;
mod versioned;
mod write;

pub use builder::ZoneBuilder;
