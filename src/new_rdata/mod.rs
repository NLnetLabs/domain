//! Record data types.

mod basic;
pub use basic::{Cname, Hinfo, Mx, Ns, Ptr, Soa, Txt, Wks, A};

mod ipv6;
pub use ipv6::Aaaa;

mod edns;
pub use edns::Opt;
