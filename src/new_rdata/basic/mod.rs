//! Core record data types.
//!
//! See [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035).

mod a;
pub use a::A;

mod ns;
pub use ns::Ns;

mod cname;
pub use cname::CName;

mod soa;
pub use soa::Soa;

mod wks;
pub use wks::Wks;

mod ptr;
pub use ptr::Ptr;

mod hinfo;
pub use hinfo::HInfo;

mod mx;
pub use mx::Mx;

mod txt;
pub use txt::Txt;
