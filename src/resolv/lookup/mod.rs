/// Lookup functions and related types.

pub use self::addr::{lookup_addr, LookupAddr, LookupAddrIter};
pub use self::host::{lookup_host, LookupHost};

mod addr;
mod host;
mod search;
