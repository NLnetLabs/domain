//! Basic DNS.
//!
//! This module provides the essential types and functionality for working
//! with DNS.  Most importantly, it provides functionality for parsing and
//! building DNS messages on the wire.

mod message;
pub use message::{Header, HeaderFlags, Message, SectionCounts};

pub mod name;

pub mod parse;
