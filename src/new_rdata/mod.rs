//! Record data types.

mod rfc1035;
pub use rfc1035::{Cname, Hinfo, Mx, Ns, Ptr, Soa, Txt, Wks, A};

mod rfc3596;
pub use rfc3596::Aaaa;
