//! Record Data of Well-defined Record Types
//!
//! This module will eventually contain implementations for the record data
//! of all defined resource record types.
//!
//! The types are named identically to the
//! [`domain::base::iana::Rtype`][crate::base::iana::Rtype] variant they
//! implement. They are grouped into submodules for the RFCs they are defined
//! in. All types are also re-exported at the top level here. Ie., for the
//! AAAA record type, you can simple `use domain::rdata::Aaaa` instead of
//! `use domain::rdata::rfc3596::Aaaa` which nobody could possibly
//! remember. There are, however, some helper data types defined here and
//! there which are not re-exported to keep things somewhat tidy.
//!
//! See the [`domain::base::iana::Rtype`][crate::base::iana::Rtype] enum for
//! the complete set of record types and, consequently, those types that are
//! still missing.
//!
//! In addition, the module provides two enums combining the known types.
//! [`AllRecordData`] indeed contains all record data types known plus
//! [`UnknownRecordData`][crate::base::rdata::UnknownRecordData] for the
//! rest, while [`MasterRecordData`] only
//! contains those types that can appear in master files plus, again,
//! [`UnknownRecordData`][crate::base::rdata::UnknownRecordData] for
//! everything else.

#[macro_use]
mod macros;

pub mod rfc1035;
pub mod rfc2782;
pub mod rfc2845;
pub mod rfc3596;
pub mod rfc4034;
pub mod rfc5155;
pub mod rfc6672;
pub mod rfc7344;

// The rdata_types! macro (defined in self::macros) reexports the record data
// types here and creates the MasterRecordData and AllRecordData enums
// containing all record types that can appear in master files or all record
// types that exist.
//
// All record data types listed here MUST have the same name as the
// `Rtype` variant they implement – some of the code implemented by the macro
// relies on that.
//
// Add any new module here and then add all record types in that module that
// can appear in master files under "master" and all others under "pseudo".
// Your type can be generic over an octet type "O" and a domain name type "N".
// Add these as needed.
//
// Each type entry has to be followed by a comma, even the last one. The macro
// is messy enough as it is ...
rdata_types! {
    rfc1035::{
        master {
            A,
            Cname<N>,
            Hinfo<O>,
            Mb<N>,
            Md<N>,
            Mf<N>,
            Minfo<N>,
            Mr<N>,
            Mx<N>,
            Ns<N>,
            Ptr<N>,
            Soa<N>,
            Txt<O>,
        }
        pseudo {
            Null<O>,
        }
    }
    rfc2782::{
        master {
            Srv<N>,
        }
    }
    rfc2845::{
        pseudo {
            Tsig<O, N>,
        }
    }
    rfc3596::{
        master {
            Aaaa,
        }
    }
    rfc4034::{
        master {
            Dnskey<O>,
            Rrsig<O, N>,
            Nsec<O, N>,
            Ds<O>,
        }
    }
    rfc6672::{
        master {
            Dname<N>,
        }
    }
    rfc5155::{
        master {
            Nsec3<O>,
            Nsec3param<O>,
        }
    }
    rfc7344::{
        master {
            Cdnskey<O>,
            Cds<O>,
        }
    }
}
