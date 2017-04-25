//! Resource data implementations.
//!
//! This module will eventually contain implementations for the record data
//! for all defined resource record types.
//!
//! The types are named identically to the [`Rtype`] variant they implement.
//! They are grouped into submodules for the RFCs they are defined in. All
//! types are also re-exported at the top level here. Ie., for the AAAA
//! record type, you can simple `use domain::rdata::Aaaa` instead of
//! `use domain::rdata::rfc3596::Aaaa` which nobody could possibly remember.
//! There are, however, some helper data types defined here and there which
//! are not re-exported to keep things somewhat tidy.
//!
//! See the [`Rtype`] enum for the complete set of record types and,
//! consequently, those types that are still missing.
//!
//! [`Rtype`]: ../iana/enum.Rtype.html

pub mod rfc1035;
pub mod rfc2782;
pub mod rfc3596;
//pub mod rfc6891;

#[macro_use] mod macros;
mod generic;

use ::bits::{CharStrBuf, DNameBuf};

// The master_types! macro (defined in self::macros) creates the
// MasterRecordData enum produced when parsing master files (aka zone files).
// 
// Include all record types that can occur in master files. Place the name of
// the variant (identical to the type name) on the left side of the double
// arrow and the name of the type on the right. If the type is generic, use
// the owned version.
//
// The macro creates the re-export of the record data type.
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

// The pseudo_types! macro (defined in self::macros) creates the re-exports
// for all the types not part of master_types! above.
pseudo_types!{
    rfc1035::{Null};
    //rfc6891::{Opt};
}

/// Formats record data from a message parser in master file format. 
///
/// This helper function formats the record data at the start of `parser`
/// using the formatter `f`. It assumes that the record data is for a
/// record of record type `rtype`.
///
/// If the record type is known, the function tries to use the type’s
/// proper master data format. Otherwise the generic format is used.
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

/// Parsed versions of all record data types.
///
/// This module defines or re-exports type aliases for all record data
/// types that use parsed domain names and references to bytes slices where
/// applicable. For convenience, it also includes re-exports for those types
/// that are not in fact generic.
///
/// Use the types from this module when working with wire format DNS messages.
pub mod parsed {
    pub use super::rfc1035::parsed::*;
    pub use super::rfc3596::Aaaa;
    pub type Srv<'a> = super::rfc2782::Srv<::bits::ParsedDName<'a>>;
}

/// Owned versions of all record data types.
///
/// This module defines or re-exports type aliases for all record data
/// types using owned data only. For convenience, it also includes re-exports
/// for those types that are not generic.
///
/// Use the types from this module if you are working with master file data
/// or if you are constructing your own values.
pub mod owned {
    pub use super::rfc1035::owned::*;
    pub use super::rfc3596::Aaaa;
    pub type Srv = super::rfc2782::Srv<::bits::DNameBuf>;
}
