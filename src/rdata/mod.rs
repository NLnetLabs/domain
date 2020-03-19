//! Resource data implementations.
//!
//!
//! # Record Data of Well-defined Record Types
//!
//! This module will eventually contain implementations for the record data
//! for all defined resource record types.
//!
//! The types are named identically to the [`iana::Rtype`] variant they
//! implement. They are grouped into submodules for the RFCs they are defined
//! in. All types are also re-exported at the top level here. Ie., for the
//! AAAA record type, you can simple `use domain_core::rdata::Aaaa` instead of
//! `use domain_core::rdata::rfc3596::Aaaa` which nobody could possibly
//! remember. There are, however, some helper data types defined here and
//! there which are not re-exported to keep things somewhat tidy.
//!
//! See the [`iana::Rtype`] enum for the complete set of record types and,
//! consequently, those types that are still missing.
//!
//!
//! [`iana::Rtype`]: ../iana/enum.Rtype.html

pub mod rfc1035;
pub mod rfc2782;
pub mod rfc2845;
pub mod rfc3596;
pub mod rfc4034;
pub mod rfc5155;
pub mod rfc7344;

#[macro_use]
mod macros;

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
            Wks<O>,
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

