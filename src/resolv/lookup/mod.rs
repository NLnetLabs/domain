//! Lookup functions and related types.
//!
//! This module collects a number of more or less complex lookups that
//! implement applications of the DNS.

pub use self::addr::lookup_addr;
pub use self::host::lookup_host;
pub use self::records::lookup_records;

pub mod addr;
pub mod host;
pub mod records;
pub mod search;
