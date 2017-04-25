//! Resource data implementations.
//!
//! This module will eventually contain implementations for the record data
//! for all defined resource record types.
//!
//! The types are named identically to the [`RRType`] variant they implement.
//! They are grouped into submodules for the RFCs they are defined in. All
//! types are also re-exported at the top level here. Ie., for the AAAA
//! record type, you can simple `use domain::rdata::Aaaa` instead of
//! `use domain::rdata::rfc3596::Aaaa` which nobody could possibly remember.
//! There are, however, some helper data types defined here and there which
//! are not re-exported to keep things somewhat tidy.
//!
//! See the [`RRType`] enum for the complete set of record types and,
//! consequently, those types that are still missing.
//!
//! [`RRType`]: ../iana/enum.RRType.html

pub mod rfc1035;
pub mod rfc2782;
pub mod rfc3596;
//pub mod rfc6891;

#[macro_use] mod macros;
mod generic;

use ::bits::{CharStrBuf, DNameBuf};

master_types!{
    rfc1035::{
        A => A,
        Cname => Cname<DNameBuf>,
        Hinfo => Hinfo<CharStrBuf>,
        Mb => Mb<DNameBuf>,
        Md => Md<DNameBuf>,
        Mf => Mf<DNameBuf>,
        Mg => Mg<DNameBuf>,
        Minfo => Minfo<DNameBuf>,
        Mr => Mr<DNameBuf>,
        Mx => Mx<DNameBuf>,
        Ns => Ns<DNameBuf>,
        Ptr => Ptr<DNameBuf>,
        Soa => Soa<DNameBuf>,
        Txt => Txt<Vec<u8>>,
        Wks => Wks<rfc1035::WksBitmapBuf>,
    }
    rfc2782::{
        Srv => Srv<DNameBuf>,
    }
    rfc3596::{
        Aaaa => Aaaa,
    }
}

pseudo_types!{
    rfc1035::{Null};
    //rfc6891::{Opt};
}

pub fn fmt_rdata(rtype: ::iana::Rtype, parser: &mut ::bits::Parser,
                 f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
    match try!(fmt_master_data(rtype, parser, f)) {
        Some(res) => Ok(res),
        None => {
            let mut parser = parser.clone();
            let len = parser.remaining();
            let data = parser.parse_bytes(len).unwrap();
            generic::fmt(data, f)
        }
    }
}

pub mod parsed {
    pub use super::rfc1035::parsed::*;
    pub use super::rfc3596::Aaaa;
    pub type Srv<'a> = super::rfc2782::Srv<::bits::ParsedDName<'a>>;
}

pub mod owned {
    pub use super::rfc1035::owned::*;
    pub use super::rfc3596::Aaaa;
    pub type Srv = super::rfc2782::Srv<::bits::DNameBuf>;
}
