//! Lookup functions and related types.
//!
//! This module collects a number of more or less complex lookups that
//! implement applications of the DNS.

pub use self::addr::{lookup_addr, LookupAddr, LookupAddrIter};
pub use self::host::{lookup_host, LookupHost, LookupHostIter,
                     LookupHostSocketIter};
pub use self::records::lookup_records;

mod addr;
mod host;
mod records;
mod search;
