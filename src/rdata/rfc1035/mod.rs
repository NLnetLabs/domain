//! Record data from [RFC 1035]: initial record types.
//!
//! This RFC defines the initial set of record types.
//!
//! [RFC 1035]: https://tools.ietf.org/html/rfc1035

pub use self::a::A;
pub use self::hinfo::Hinfo;
pub use self::minfo::Minfo;
pub use self::mx::Mx;
pub use self::name::{Cname, Mb, Md, Mf, Mg, Mr, Ns, Ptr};
pub use self::null::Null;
pub use self::soa::Soa;
pub use self::txt::{
    Txt, TxtAppendError, TxtBuilder, TxtCharStrIter, TxtError, TxtIter,
};

mod a;
mod hinfo;
mod minfo;
mod mx;
mod name;
mod null;
mod soa;
mod txt;
