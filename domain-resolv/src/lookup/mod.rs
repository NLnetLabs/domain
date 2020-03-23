//! Lookup functions and related types.
//!
//! This module collects a number of more or less complex lookups that
//! implement applications of the DNS.

pub use self::addr::lookup_addr;
pub use self::host::{lookup_host, search_host};
pub use self::srv::lookup_srv;

pub mod addr;
pub mod host;
pub mod srv;

