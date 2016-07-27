//! Resource data implementations.
//!
//! This module will eventually contain implementations for the record data
//! for all defined resource record types.
//!
//! The types are named identically to the [RRType] variant they implement.
//! They are grouped into submodules for the RFCs they are defined in. All
//! types are also re-exported at the top level here. Ie., for the AAAA
//! record type, you can simple `use domain::rdata::Aaaa` instead of
//! `use domain::rdata::rfc3596::Aaaa` which nobody could possibly remember.
//! There are, however, some helper data types defined here and there which
//! are not re-exported to keep things somewhat tidy.
//!
//! See the [RRType] enum for the complete set of record types and,
//! consequently, those types that are still missing.
//!
//! [RRType]: ../iana/enum.RRType.html

pub mod rfc1035;
pub mod rfc3596;
pub mod rfc6891;

#[macro_use] mod macros;
mod generic;


master_types!{
    rfc1035::{A, Cname, Hinfo, Mb, Md, Mf, Mg, Minfo, Mr, Mx, Ns, Ptr,
              Soa, Txt, Wks};
    rfc3596::{Aaaa};
}

pseudo_types!{
    rfc1035::{Null};
    rfc6891::{Opt};
}
